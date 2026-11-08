//go:build saturation

// Saturation tests drive the node API at concurrency and check that the
// security invariants hold under load, that unauthenticated floods leave no
// state, and that overload fails closed. ATTEST_SATURATION_SCALE multiplies
// the work; 1 is the CI smoke run. See `make saturation`.
package api

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	attestv1 "github.com/0xciph3r/attest/api/gen/attest/v1"
	"github.com/0xciph3r/attest/internal/audit"
	"github.com/0xciph3r/attest/internal/store/storetest"
	"github.com/0xciph3r/attest/internal/verifier/verifiertest"
)

func scale(t *testing.T) int {
	t.Helper()
	s := os.Getenv("ATTEST_SATURATION_SCALE")
	if s == "" {
		return 1
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		t.Fatalf("ATTEST_SATURATION_SCALE=%q", s)
	}
	return n
}

// outcomes tallies call results and latencies across workers.
type outcomes struct {
	mu      sync.Mutex
	lat     []time.Duration
	codes   map[codes.Code]int
	reasons map[string]int
}

func newOutcomes() *outcomes {
	return &outcomes{codes: map[codes.Code]int{}, reasons: map[string]int{}}
}

func (o *outcomes) record(start time.Time, err error) {
	d := time.Since(start)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lat = append(o.lat, d)
	o.codes[status.Code(err)]++
	if r := DenialReason(err); r != "" {
		o.reasons[r]++
	}
}

func (o *outcomes) report(t *testing.T, name string, elapsed time.Duration) {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	slices.Sort(o.lat)
	q := func(p float64) time.Duration {
		if len(o.lat) == 0 {
			return 0
		}
		return o.lat[min(len(o.lat)-1, int(p*float64(len(o.lat))))]
	}
	t.Logf("%s: %d calls in %v (%.0f/s) p50=%v p95=%v p99=%v max=%v codes=%v reasons=%v",
		name, len(o.lat), elapsed.Round(time.Millisecond), float64(len(o.lat))/elapsed.Seconds(),
		q(0.50), q(0.95), q(0.99), q(1), o.codes, o.reasons)
}

// run starts workers goroutines running fn(worker) and waits for them.
func run(workers int, fn func(w int)) time.Duration {
	start := time.Now()
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() { fn(w) })
	}
	wg.Wait()
	return time.Since(start)
}

// answer fetches a challenge for node and returns an honest Attest request.
func (e *env) answer(c attestv1.NodeServiceClient, node string, ak *verifiertest.AK) (*attestv1.AttestRequest, error) {
	ch, err := c.GetChallenge(bg, &attestv1.GetChallengeRequest{NodeId: node})
	if err != nil {
		return nil, err
	}
	pcrs := e.boot.PCRs(ch.GetPcrs()...)
	a, s := ak.Quote(e.t, ch.GetNonce(), pcrs)
	return &attestv1.AttestRequest{NodeId: node, ChallengeId: ch.GetChallengeId(), Nonce: ch.GetNonce(),
		Evidence: &attestv1.Evidence{Attest: a, Signature: s, Pcrs: pcrs, EventLog: e.boot.Bytes()}}, nil
}

func (e *env) rawDB() *sql.DB {
	e.t.Helper()
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: e.dbPath}).EscapedPath()+"?_pragma=busy_timeout(10000)")
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = db.Close() })
	return db
}

func (e *env) count(query string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.rawDB().QueryRow(query, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *env) verifyAudit() audit.Head {
	e.t.Helper()
	rep, err := audit.Verify(e.st.AuditEntries(bg), audit.VerifyOptions{AllowUnanchored: true})
	if err != nil {
		e.t.Fatalf("audit chain: %v", err)
	}
	return rep.Head
}

// serveTCP serves NodeService on a loopback TCP port with lim, as attestd
// does, and returns its address.
func (e *env) serveTCP(lim RateLimits) string {
	e.t.Helper()
	ns, err := NewNodeServer(NodeConfig{Enrollment: e.enr, Verifier: e.ver, Identity: e.ident, Log: e.log})
	if err != nil {
		e.t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		e.t.Fatal(err)
	}
	srv := NewNodeGRPCServer(ns, e.cert, NewRateLimiter(lim, e.log))
	go func() { _ = srv.Serve(LimitNodeListener(l)) }()
	e.t.Cleanup(srv.Stop)
	return l.Addr().String()
}

func (e *env) tcpClient(addr string, cfg *tls.Config) attestv1.NodeServiceClient {
	e.t.Helper()
	conn, err := grpc.NewClient("passthrough:///"+addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = conn.Close() })
	return attestv1.NewNodeServiceClient(conn)
}

// settle waits for the goroutine count to fall to at most limit.
func settle(t *testing.T, limit int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for runtime.NumGoroutine() > limit {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			t.Fatalf("%d goroutines, want <= %d:\n%s", runtime.NumGoroutine(), limit, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Concurrent honest attestation: every call succeeds, each success is
// recorded exactly once with its audit entry, and the chain verifies.
func TestSaturationAttest(t *testing.T) {
	e := newEnv(t)
	const nodes, workers = 4, 16
	per := 25 * scale(t)
	aks := make([]*verifiertest.AK, nodes)
	for i := range aks {
		aks[i] = e.node(fmt.Sprintf("n%d", i+1))
	}
	clients := make([]attestv1.NodeServiceClient, workers)
	for i := range clients {
		clients[i] = e.client(nil)
	}
	o := newOutcomes()
	var ok atomic.Int64
	elapsed := run(workers, func(w int) {
		node := fmt.Sprintf("n%d", w%nodes+1)
		for range per {
			start := time.Now()
			req, err := e.answer(clients[w], node, aks[w%nodes])
			if err == nil {
				_, err = clients[w].Attest(bg, req)
			}
			o.record(start, err)
			if err == nil {
				ok.Add(1)
			} else {
				t.Errorf("attest %s: %v", node, err)
			}
		}
	})
	o.report(t, "challenge+attest", elapsed)
	want := int(ok.Load())
	if want != workers*per {
		t.Fatalf("%d of %d attestations succeeded", want, workers*per)
	}
	if n := e.count(`SELECT count(*) FROM attestations WHERE result = 'pass'`); n != want {
		t.Errorf("%d passed attestations recorded, %d reported", n, want)
	}
	if n := e.count(`SELECT count(*) FROM attest_challenges WHERE consumed_at IS NOT NULL`); n != want {
		t.Errorf("%d challenges consumed, %d reported", n, want)
	}
	if n := e.count(`SELECT count(*) FROM audit_entries WHERE action = 'node.attest'`); n != want {
		t.Errorf("%d audit entries, %d reported", n, want)
	}
	e.verifyAudit()
}

// The same answer submitted concurrently is accepted exactly once.
func TestSaturationReplayRace(t *testing.T) {
	e := newEnv(t)
	ak := e.node("n1")
	const racers = 16
	rounds := 20 * scale(t)
	clients := make([]attestv1.NodeServiceClient, racers)
	for i := range clients {
		clients[i] = e.client(nil)
	}
	o := newOutcomes()
	start := time.Now()
	for r := range rounds {
		req, err := e.answer(clients[0], "n1", ak)
		if err != nil {
			t.Fatal(err)
		}
		var ok atomic.Int64
		run(racers, func(w int) {
			s := time.Now()
			_, err := clients[w].Attest(bg, req)
			o.record(s, err)
			switch {
			case err == nil:
				ok.Add(1)
			case DenialReason(err) != "challenge_consumed":
				t.Errorf("round %d: %v", r, err)
			}
		})
		if ok.Load() != 1 {
			t.Fatalf("round %d: %d submissions accepted", r, ok.Load())
		}
	}
	o.report(t, "replay race", time.Since(start))
	if n := e.count(`SELECT count(*) FROM attestations`); n != rounds {
		t.Fatalf("%d attestations recorded for %d challenges", n, rounds)
	}
	e.verifyAudit()
}

// Concurrent workload issuance: every certificate has a distinct serial and
// a matching identity record.
func TestSaturationIssueWorkload(t *testing.T) {
	e := newEnv(t)
	_, cert := e.nodeIdentity()
	const workers = 16
	per := 25 * scale(t)
	clients := make([]attestv1.NodeServiceClient, workers)
	for i := range clients {
		clients[i] = e.client(e.tls(cert))
	}
	o := newOutcomes()
	var mu sync.Mutex
	serials := map[string]bool{}
	elapsed := run(workers, func(w int) {
		req := csr(t, p256(t))
		for range per {
			start := time.Now()
			resp, err := clients[w].IssueWorkloadIdentity(bg, &attestv1.IssueWorkloadIdentityRequest{
				SystemdUnit: "api.service", Uid: 1000, Csr: req})
			o.record(start, err)
			if err != nil {
				t.Errorf("issue: %v", err)
				continue
			}
			leaf, err := x509.ParseCertificate(resp.GetIdentity().GetCertificate())
			if err != nil {
				t.Error(err)
				continue
			}
			mu.Lock()
			if serials[leaf.SerialNumber.String()] {
				t.Errorf("serial %s issued twice", leaf.SerialNumber)
			}
			serials[leaf.SerialNumber.String()] = true
			mu.Unlock()
		}
	})
	o.report(t, "issue workload identity", elapsed)
	if len(serials) != workers*per {
		t.Fatalf("%d distinct serials for %d issuances", len(serials), workers*per)
	}
	if n := e.count(`SELECT count(*) FROM identity_records WHERE kind = 'workload'`); n != len(serials) {
		t.Fatalf("%d workload identity records for %d certificates", n, len(serials))
	}
	e.verifyAudit()
}

// A flood of unauthenticated calls of every kind leaves the database and
// ledger byte-for-byte unchanged, does not cut off the node, and does not
// leak goroutines or memory.
func TestSaturationUnauthenticatedFloodLeavesNoState(t *testing.T) {
	e := newEnv(t)
	ak := e.node("n1")
	other := verifiertest.NewAK(t)
	ekKey := p256(t)
	if _, err := e.enr.Register(bg, "operator:alice", "r1", e.ekCA.IssueEKCert(t, &ekKey.PublicKey)); err != nil {
		t.Fatal(err)
	}
	c := e.client(nil)
	// An accepted answer, for replay.
	consumed, err := e.answer(c, "n1", ak)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Attest(bg, consumed); err != nil {
		t.Fatal(err)
	}
	node, _ := e.nodeIdentity2(ak)

	const workers = 16
	per := 200 * scale(t)
	clients := make([]attestv1.NodeServiceClient, workers)
	for i := range clients {
		clients[i] = e.client(nil)
		// Connect now, so the baseline includes connection goroutines.
		if _, err := clients[i].GetChallenge(bg, &attestv1.GetChallengeRequest{NodeId: "n1"}); err != nil {
			t.Fatal(err)
		}
	}
	before := storetest.Dump(t, e.dbPath)
	head := e.verifyAudit()
	runtime.GC()
	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)
	g0 := runtime.NumGoroutine()

	junk := &attestv1.Evidence{Attest: bytes.Repeat([]byte{0xff}, 512), Signature: []byte("junk"),
		Pcrs: e.boot.PCRs(0), EventLog: e.boot.Bytes()}
	forgedID := "att_" + strings.Repeat("0", 48)
	o := newOutcomes()
	elapsed := run(workers, func(w int) {
		c := clients[w]
		for i := range per {
			start := time.Now()
			var err error
			switch (w + i) % 9 {
			case 0:
				_, err = c.GetChallenge(bg, &attestv1.GetChallengeRequest{NodeId: "n1"})
				err = flipOK(err)
			case 1:
				_, err = c.GetChallenge(bg, &attestv1.GetChallengeRequest{NodeId: "ghost"})
			case 2:
				var req *attestv1.AttestRequest
				if req, err = e.answer(c, "n1", ak); err == nil {
					req.Evidence = junk
					_, err = c.Attest(bg, req)
				}
			case 3:
				_, err = c.Attest(bg, &attestv1.AttestRequest{NodeId: "n1", ChallengeId: forgedID,
					Nonce: make([]byte, 32), Evidence: junk})
			case 4:
				var req *attestv1.AttestRequest
				if req, err = e.answer(c, "n1", other); err == nil {
					_, err = c.Attest(bg, req)
				}
			case 5:
				_, err = c.Attest(bg, consumed)
			case 6:
				_, err = c.BeginEnrollment(bg, &attestv1.BeginEnrollmentRequest{NodeId: "r1", AkPublic: other.PublicBytes()})
				err = flipOK(err)
			case 7:
				// A live challenge answered without the EK: the secret is wrong.
				var b *attestv1.BeginEnrollmentResponse
				if b, err = c.BeginEnrollment(bg, &attestv1.BeginEnrollmentRequest{NodeId: "r1", AkPublic: other.PublicBytes()}); err == nil {
					_, err = c.CompleteEnrollment(bg, &attestv1.CompleteEnrollmentRequest{NodeId: "r1",
						ChallengeId: b.GetChallengeId(), AkPublic: other.PublicBytes(), Secret: make([]byte, 32)})
				}
			case 8:
				_, err = c.IssueWorkloadIdentity(bg, &attestv1.IssueWorkloadIdentityRequest{
					SystemdUnit: "api.service", Uid: 1000, Csr: []byte("junk")})
			}
			o.record(start, err)
			switch status.Code(err) {
			case codes.PermissionDenied, codes.InvalidArgument, codes.Unauthenticated:
			default:
				t.Errorf("op %d: %v", (w+i)%9, err)
			}
		}
	})
	o.report(t, "unauthenticated flood", elapsed)

	if after := storetest.Dump(t, e.dbPath); after != before {
		t.Fatal("unauthenticated flood changed the database")
	}
	if h := e.verifyAudit(); h != head {
		t.Fatalf("audit head moved: %v -> %v", head, h)
	}
	if _, err := node.IssueWorkloadIdentity(bg, &attestv1.IssueWorkloadIdentityRequest{
		SystemdUnit: "api.service", Uid: 1000, Csr: csr(t, p256(t))}); err != nil {
		t.Fatalf("node cut off by the flood: %v", err)
	}
	settle(t, g0+8, 5*time.Second)
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	if grew := int64(m1.HeapAlloc) - int64(m0.HeapAlloc); grew > 64<<20 {
		t.Fatalf("heap grew %d MiB during the flood", grew>>20)
	}
}

// flipOK turns success into a sentinel denial so stateless successes count
// as expected outcomes.
func flipOK(err error) error {
	if err == nil {
		return status.Error(codes.PermissionDenied, "ok")
	}
	return err
}

// nodeIdentity2 attests the already enrolled n1 with a fresh bound key.
func (e *env) nodeIdentity2(ak *verifiertest.AK) (attestv1.NodeServiceClient, *tls.Certificate) {
	e.t.Helper()
	key := verifiertest.NewNodeKey(e.t)
	resp, err := e.attest(e.client(nil), "n1", ak, key)
	if err != nil {
		e.t.Fatal(err)
	}
	cert := &tls.Certificate{Certificate: [][]byte{resp.GetIdentity().GetCertificate()}, PrivateKey: key.Key}
	return e.client(e.tls(cert)), cert
}

// Under a flood from one address over real TCP, admitted calls stay within
// the bucket, the rest are refused cleanly, and the peer recovers.
func TestSaturationRateLimit(t *testing.T) {
	e := newEnv(t)
	e.node("n1")
	lim := RateLimits{PerPeer: 50, PerPeerBurst: 100, Global: 1e9, GlobalBurst: 1e9, MaxPeers: 16}
	addr := e.serveTCP(lim)
	const workers = 16
	clients := make([]attestv1.NodeServiceClient, workers)
	for i := range clients {
		clients[i] = e.tcpClient(addr, e.tls(nil))
	}
	window := time.Duration(scale(t)) * 2 * time.Second
	o := newOutcomes()
	var admitted atomic.Int64
	start := time.Now()
	elapsed := run(workers, func(w int) {
		for time.Since(start) < window {
			s := time.Now()
			_, err := clients[w].GetChallenge(bg, &attestv1.GetChallengeRequest{NodeId: "n1"})
			o.record(s, err)
			switch status.Code(err) {
			case codes.OK:
				admitted.Add(1)
			case codes.ResourceExhausted:
			default:
				t.Errorf("flood: %v", err)
			}
		}
	})
	o.report(t, "rate-limited flood", elapsed)
	bound := float64(lim.PerPeerBurst) + lim.PerPeer*elapsed.Seconds() + 1
	if got := admitted.Load(); float64(got) > bound {
		t.Fatalf("admitted %d calls, bound %.0f", got, bound)
	}
	if o.codes[codes.ResourceExhausted] == 0 {
		t.Fatal("flood was never limited")
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := clients[0].GetChallenge(bg, &attestv1.GetChallengeRequest{NodeId: "n1"}); err != nil {
		t.Fatalf("peer did not recover: %v", err)
	}
}

// Connections that never complete a TLS handshake do not block service and
// are closed after the handshake timeout.
func TestSaturationStalledConnections(t *testing.T) {
	e := newEnv(t)
	e.node("n1")
	addr := e.serveTCP(unlimited)
	g0 := runtime.NumGoroutine()
	stalled := min(100*scale(t), MaxNodeConnections/2)
	conns := make([]net.Conn, 0, stalled)
	for range stalled {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	c := e.tcpClient(addr, e.tls(nil))
	start := time.Now()
	if _, err := c.GetChallenge(bg, &attestv1.GetChallengeRequest{NodeId: "n1"}); err != nil {
		t.Fatalf("with %d stalled connections: %v", stalled, err)
	}
	t.Logf("%d stalled connections: call took %v", stalled, time.Since(start).Round(time.Millisecond))
	// The server closes each after connectionTimeout.
	for i, conn := range conns {
		_ = conn.SetReadDeadline(time.Now().Add(connectionTimeout + 5*time.Second))
		if _, err := conn.Read(make([]byte, 1)); err == nil || isTimeout(err) {
			t.Fatalf("stalled connection %d not closed by the server: %v", i, err)
		}
	}
	settle(t, g0+16, 5*time.Second)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// When the audit ledger cannot be written mid-load, attestation fails
// closed: no success is reported that was not recorded with its audit
// entry, internal details do not reach callers, and service resumes when
// the fault clears.
func TestSaturationAuditFailureFailsClosed(t *testing.T) {
	e := newEnv(t)
	const nodes, workers = 4, 8
	aks := make([]*verifiertest.AK, nodes)
	for i := range aks {
		aks[i] = e.node(fmt.Sprintf("n%d", i+1))
	}
	clients := make([]attestv1.NodeServiceClient, workers)
	for i := range clients {
		clients[i] = e.client(nil)
	}
	db := e.rawDB()
	phase := time.Duration(scale(t)) * 300 * time.Millisecond
	var stop atomic.Bool
	var ok, failed atomic.Int64
	ids := make(chan int64, 1<<16)
	o := newOutcomes()
	done := make(chan time.Duration)
	go func() {
		done <- run(workers, func(w int) {
			node := fmt.Sprintf("n%d", w%nodes+1)
			for !stop.Load() {
				start := time.Now()
				req, err := e.answer(clients[w], node, aks[w%nodes])
				if err == nil {
					var resp *attestv1.AttestResponse
					if resp, err = clients[w].Attest(bg, req); err == nil {
						ok.Add(1)
						ids <- resp.GetAttestationId()
					}
				}
				o.record(start, err)
				if err != nil {
					failed.Add(1)
					if status.Code(err) != codes.Internal || strings.Contains(err.Error(), "injected") {
						t.Errorf("under audit failure: %v", err)
					}
				}
			}
		})
	}()
	time.Sleep(phase)
	if _, err := db.Exec(`CREATE TRIGGER saturation_fault BEFORE INSERT ON audit_entries
		BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	okAtFault := ok.Load()
	time.Sleep(phase)
	if _, err := db.Exec(`DROP TRIGGER saturation_fault`); err != nil {
		t.Fatal(err)
	}
	time.Sleep(phase)
	stop.Store(true)
	elapsed := <-done
	close(ids)
	o.report(t, "attest through audit fault", elapsed)

	if failed.Load() == 0 {
		t.Fatal("injected fault caused no failures")
	}
	if ok.Load() <= okAtFault {
		t.Fatal("service did not resume after the fault cleared")
	}
	n := 0
	for id := range ids {
		n++
		var result string
		var seq int64
		if err := db.QueryRow(`SELECT result, audit_seq FROM attestations WHERE id = ?`, id).Scan(&result, &seq); err != nil {
			t.Fatalf("reported attestation %d not recorded: %v", id, err)
		}
		if result != "pass" || e.count(`SELECT count(*) FROM audit_entries WHERE seq = ? AND action = 'node.attest'`, seq) != 1 {
			t.Fatalf("attestation %d lacks its audit entry", id)
		}
	}
	if total := e.count(`SELECT count(*) FROM attestations`); total != n {
		t.Fatalf("%d attestations recorded, %d reported", total, n)
	}
	e.verifyAudit()
}
