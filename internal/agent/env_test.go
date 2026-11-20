package agent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/test/bufconn"

	attestv1 "github.com/0xciph3r/attest/api/gen/attest/v1"
	"github.com/0xciph3r/attest/internal/api"
	"github.com/0xciph3r/attest/internal/enrollment"
	"github.com/0xciph3r/attest/internal/eventlog"
	"github.com/0xciph3r/attest/internal/identity"
	"github.com/0xciph3r/attest/internal/store"
	"github.com/0xciph3r/attest/internal/tpm/swtpm/swtpmtest"
	"github.com/0xciph3r/attest/internal/verifier"
	"github.com/0xciph3r/attest/internal/verifier/verifiertest"
)

var bg = context.Background()

const td = "attest.local"

const workloadPolicy = `{"schema":"attest.dev/workload-policy/v1","workloads":[
	{"name":"api","nodes":["n1"],"systemd_unit":"api.service","uid":1000}]}`

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }

func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

// syncBuffer is a log sink safe for concurrent writers.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// fakeTPM answers with software keys of the exact TPM templates.
type fakeTPM struct {
	t    testing.TB
	ak   *verifiertest.AK
	key  *verifiertest.NodeKey
	mu   sync.Mutex
	boot *eventlog.Builder
	err  error
	// activate answers ActivateCredential; nil fails it.
	activate func(blob, secret []byte) ([]byte, error)
	quotes   []time.Time
}

func (f *fakeTPM) AKPublic() []byte { return f.ak.PublicBytes() }

func (f *fakeTPM) ActivateCredential(blob, secret []byte) ([]byte, error) {
	if f.activate == nil {
		return nil, errors.New("fake: no EK")
	}
	return f.activate(blob, secret)
}

func (f *fakeTPM) Evidence(nonce []byte, pcrs []uint32) (*attestv1.Evidence, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.quotes = append(f.quotes, time.Now())
	if f.err != nil {
		return nil, f.err
	}
	pv := f.boot.PCRs(pcrs...)
	b := f.ak.BoundEvidence(f.t, nonce, f.key, pv)
	return &attestv1.Evidence{Attest: b.Attest, Signature: b.Signature, Pcrs: pv, EventLog: f.boot.Bytes(),
		NodeKey: &attestv1.NodeKeyEvidence{Public: b.Public, Certify: b.Certify, CertifySignature: b.CertifySignature}}, nil
}

func (f *fakeTPM) NodeKey() crypto.Signer { return f.key.Key }

func (f *fakeTPM) set(boot *eventlog.Builder, err error) {
	f.mu.Lock()
	f.boot, f.err = boot, err
	f.mu.Unlock()
}

func (f *fakeTPM) quoteCount() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.quotes) }

func (f *fakeTPM) quoteTimes() []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Time(nil), f.quotes...)
}

// env is an in-process attestd with node n1 enrolled.
type env struct {
	t     *testing.T
	clk   *clock
	st    *store.Store
	ca    *identity.CA
	ident *identity.Service
	enr   *enrollment.Service
	ekCA  *swtpmtest.CA
	lis   *bufconn.Listener
	tpm   *fakeTPM
	logs  *syncBuffer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	clk := &clock{now: time.Now().UTC().Truncate(time.Second)}
	st, err := store.Open(bg, filepath.Join(t.TempDir(), "attest.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ca, err := identity.Init(t.TempDir(), identity.Options{TrustDomain: td, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	boot := eventlog.SimulatedBoot("v1")
	e := &env{t: t, clk: clk, st: st, ca: ca, logs: &syncBuffer{}, ekCA: swtpmtest.NewCA(t, "Production EK CA")}
	log := slog.New(slog.NewTextHandler(e.logs, nil))
	roots := x509.NewCertPool()
	roots.AddCert(e.ekCA.Cert)
	if e.enr, err = enrollment.New(enrollment.Config{Store: st, Roots: verifier.EKRoots{Production: roots}, Now: clk.Now}); err != nil {
		t.Fatal(err)
	}
	ver, err := verifier.NewService(verifier.ServiceConfig{Store: st, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ver.ApplyPolicy(bg, "operator:alice", verifiertest.PolicyJSON(t, false, boot)); err != nil {
		t.Fatal(err)
	}
	if e.ident, err = identity.NewService(identity.ServiceConfig{Store: st, CA: ca, Now: clk.Now}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ident.ApplyWorkloadPolicy(bg, "operator:alice", []byte(workloadPolicy)); err != nil {
		t.Fatal(err)
	}
	ns, err := api.NewNodeServer(api.NodeConfig{Enrollment: e.enr, Verifier: ver, Identity: e.ident, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := api.NewServerCert(bg, api.ServerCertConfig{CA: ca, Store: st, Now: clk.Now, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	e.lis = bufconn.Listen(1 << 20)
	lim := api.RateLimits{PerPeer: 1e9, PerPeerBurst: 1e9, Global: 1e9, GlobalBurst: 1e9, MaxPeers: 1}
	srv := api.NewNodeGRPCServer(ns, cert, api.NewRateLimiter(lim, log))
	go func() { _ = srv.Serve(e.lis) }()
	t.Cleanup(srv.Stop)

	e.tpm = &fakeTPM{t: t, ak: verifiertest.NewAK(t), key: verifiertest.NewNodeKey(t), boot: boot}
	err = st.Update(bg, func(tx *store.Tx) error {
		ek := []byte("ek-n1")
		if err := tx.InsertNode(&store.Node{ID: "n1", EKType: "eccp256", EKCert: ek, EKPublic: ek,
			EKDigest: bytes.Repeat([]byte{1}, 32), RegisteredBy: "operator:alice", RegisteredAt: clk.Now()}); err != nil {
			return err
		}
		return tx.EnrollNode("n1", e.tpm.ak.PublicBytes(), e.tpm.ak.Name, clk.Now())
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) config() Config {
	return Config{
		NodeID: "n1", TrustDomain: td, Bundle: e.ca.Bundle(), Addr: "attestd:8443",
		Dial: func(ctx context.Context, _ string) (net.Conn, error) { return e.lis.DialContext(ctx) },
		TPM:  e.tpm, Log: slog.New(slog.NewTextHandler(e.logs, nil)), Now: e.clk.Now,
	}
}

func (e *env) agent(mods ...func(*Config)) *Agent {
	e.t.Helper()
	cfg := e.config()
	for _, m := range mods {
		m(&cfg)
	}
	a, err := New(cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(a.Close)
	return a
}

func (e *env) attested(mods ...func(*Config)) *Agent {
	e.t.Helper()
	a := e.agent(mods...)
	if err := a.Attest(bg); err != nil {
		e.t.Fatal(err)
	}
	return a
}

// shortDir returns a temporary directory short enough for Unix socket
// paths, which t.TempDir can exceed on macOS.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "agent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func p256(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
