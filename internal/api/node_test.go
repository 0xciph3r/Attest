package api

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	attestv1 "github.com/0xciph3r/attest/api/gen/attest/v1"
	"github.com/0xciph3r/attest/internal/enrollment"
	"github.com/0xciph3r/attest/internal/eventlog"
	"github.com/0xciph3r/attest/internal/identity"
	"github.com/0xciph3r/attest/internal/store"
	"github.com/0xciph3r/attest/internal/tpm/swtpm/swtpmtest"
	"github.com/0xciph3r/attest/internal/verifier"
	"github.com/0xciph3r/attest/internal/verifier/verifiertest"
)

var bg = context.Background()

const workloadPolicy = `{"schema":"attest.dev/workload-policy/v1","workloads":[
	{"name":"api","nodes":["n1"],"systemd_unit":"api.service","uid":1000}]}`

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }

func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

type env struct {
	t     *testing.T
	clk   *clock
	st    *store.Store
	ca    *identity.CA
	boot  *eventlog.Builder
	cert  *ServerCert
	lis   *bufconn.Listener
	logs  *bytes.Buffer
	ident *identity.Service
	enr   *enrollment.Service
	ver   *verifier.Service
	ekCA  *swtpmtest.CA
	log   *slog.Logger
}

func newEnv(t *testing.T) *env {
	t.Helper()
	clk := &clock{now: time.Now().UTC().Truncate(time.Second)}
	st, err := store.Open(bg, filepath.Join(t.TempDir(), "attest.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ca, err := identity.Init(t.TempDir(), identity.Options{TrustDomain: "attest.local", Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, clk: clk, st: st, ca: ca, boot: eventlog.SimulatedBoot("v1"), logs: &bytes.Buffer{}}
	log := slog.New(slog.NewTextHandler(e.logs, nil))
	e.log = log
	e.ekCA = swtpmtest.NewCA(t, "Production EK CA")
	roots := x509.NewCertPool()
	roots.AddCert(e.ekCA.Cert)

	enr, err := enrollment.New(enrollment.Config{Store: st, Roots: verifier.EKRoots{Production: roots}, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	ver, err := verifier.NewService(verifier.ServiceConfig{Store: st, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ver.ApplyPolicy(bg, "operator:alice", verifiertest.PolicyJSON(t, false, e.boot)); err != nil {
		t.Fatal(err)
	}
	if e.ident, err = identity.NewService(identity.ServiceConfig{Store: st, CA: ca, Now: clk.Now}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ident.ApplyWorkloadPolicy(bg, "operator:alice", []byte(workloadPolicy)); err != nil {
		t.Fatal(err)
	}
	e.enr, e.ver = enr, ver
	ns, err := NewNodeServer(NodeConfig{Enrollment: enr, Verifier: ver, Identity: e.ident, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	if e.cert, err = NewServerCert(bg, ServerCertConfig{CA: ca, Store: st, Now: clk.Now, Log: log}); err != nil {
		t.Fatal(err)
	}
	e.lis = bufconn.Listen(1 << 20)
	srv := NewNodeGRPCServer(ns, e.cert)
	go func() { _ = srv.Serve(e.lis) }()
	t.Cleanup(srv.Stop)
	return e
}

// client connects with cfg, or as an unauthenticated node if cfg is nil.
func (e *env) client(cfg *tls.Config) attestv1.NodeServiceClient {
	e.t.Helper()
	if cfg == nil {
		cfg = e.tls(nil)
	}
	conn, err := grpc.NewClient("passthrough:///attestd",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return e.lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = conn.Close() })
	return attestv1.NewNodeServiceClient(conn)
}

func (e *env) tls(cert *tls.Certificate) *tls.Config {
	e.t.Helper()
	cfg, err := ClientTLS(e.ca.Bundle(), "attest.local", cert, e.clk.Now)
	if err != nil {
		e.t.Fatal(err)
	}
	return cfg
}

// node inserts an enrolled node; enrollment is tested in its own package.
func (e *env) node(id string) *verifiertest.AK {
	e.t.Helper()
	ak := verifiertest.NewAK(e.t)
	err := e.st.Update(bg, func(tx *store.Tx) error {
		ek := []byte("ek-" + id)
		if err := tx.InsertNode(&store.Node{ID: id, EKType: "eccp256", EKCert: ek, EKPublic: ek,
			EKDigest: bytes.Repeat([]byte(id[len(id)-1:]), 32), RegisteredBy: "operator:alice", RegisteredAt: e.clk.Now()}); err != nil {
			return err
		}
		return tx.EnrollNode(id, ak.PublicBytes(), ak.Name, e.clk.Now())
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return ak
}

// attest runs the challenge-quote exchange, binding key if non-nil.
func (e *env) attest(c attestv1.NodeServiceClient, node string, ak *verifiertest.AK, key *verifiertest.NodeKey) (*attestv1.AttestResponse, error) {
	e.t.Helper()
	ch, err := c.GetChallenge(bg, &attestv1.GetChallengeRequest{NodeId: node})
	if err != nil {
		e.t.Fatal(err)
	}
	pcrs := e.boot.PCRs(ch.GetPcrs()...)
	ev := &attestv1.Evidence{Pcrs: pcrs, EventLog: e.boot.Bytes()}
	if key != nil {
		b := ak.BoundEvidence(e.t, ch.GetNonce(), key, pcrs)
		ev.Attest, ev.Signature = b.Attest, b.Signature
		ev.NodeKey = &attestv1.NodeKeyEvidence{Public: b.Public, Certify: b.Certify, CertifySignature: b.CertifySignature}
	} else {
		ev.Attest, ev.Signature = ak.Quote(e.t, ch.GetNonce(), pcrs)
	}
	return c.Attest(bg, &attestv1.AttestRequest{NodeId: node, ChallengeId: ch.GetChallengeId(), Nonce: ch.GetNonce(), Evidence: ev})
}

// nodeIdentity attests n1 with a bound key and returns a client
// authenticated with the resulting node identity.
func (e *env) nodeIdentity() (attestv1.NodeServiceClient, *tls.Certificate) {
	e.t.Helper()
	ak := e.node("n1")
	key := verifiertest.NewNodeKey(e.t)
	resp, err := e.attest(e.client(nil), "n1", ak, key)
	if err != nil {
		e.t.Fatal(err)
	}
	cert := &tls.Certificate{Certificate: [][]byte{resp.GetIdentity().GetCertificate()}, PrivateKey: key.Key}
	return e.client(e.tls(cert)), cert
}

func csr(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func p256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func expectCode(t *testing.T, name string, err error, code codes.Code, reason string) {
	t.Helper()
	if status.Code(err) != code || DenialReason(err) != reason {
		t.Errorf("%s: got %v (reason %q), want %s %q", name, err, DenialReason(err), code, reason)
	}
}

func TestNodeIdentityEndToEnd(t *testing.T) {
	e := newEnv(t)
	ak := e.node("n1")
	key := verifiertest.NewNodeKey(t)
	resp, err := e.attest(e.client(nil), "n1", ak, key)
	if err != nil {
		t.Fatal(err)
	}
	ident := resp.GetIdentity()
	if resp.GetAttestationId() == 0 || ident.GetSpiffeId() != "spiffe://attest.local/node/n1" || len(ident.GetBundle()) != 1 {
		t.Fatalf("response %v", resp)
	}
	leaf, err := x509.ParseCertificate(ident.GetCertificate())
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(&key.Key.PublicKey) || !leaf.NotAfter.Equal(ident.GetNotAfter().AsTime()) {
		t.Fatalf("leaf key or validity differs: %s", leaf.NotAfter)
	}

	// The node identity authenticates the agent for workload issuance.
	cert := &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key.Key}
	wk := p256(t)
	wr, err := e.client(e.tls(cert)).IssueWorkloadIdentity(bg, &attestv1.IssueWorkloadIdentityRequest{
		SystemdUnit: "api.service", Uid: 1000, Csr: csr(t, wk)})
	if err != nil {
		t.Fatal(err)
	}
	wl, err := x509.ParseCertificate(wr.GetIdentity().GetCertificate())
	if err != nil {
		t.Fatal(err)
	}
	if wr.GetIdentity().GetSpiffeId() != "spiffe://attest.local/workload/api" || !wl.PublicKey.(*ecdsa.PublicKey).Equal(wk.Public()) {
		t.Fatalf("workload identity %v", wr.GetIdentity().GetSpiffeId())
	}
}

func TestAttestWithoutKeyIssuesNoIdentity(t *testing.T) {
	e := newEnv(t)
	resp, err := e.attest(e.client(nil), "n1", e.node("n1"), nil)
	if err != nil || resp.GetIdentity() != nil || resp.GetAttestationId() == 0 {
		t.Fatalf("%v, %v", resp, err)
	}
}

func TestAttestRejects(t *testing.T) {
	e := newEnv(t)
	ak := e.node("n1")
	c := e.client(nil)

	_, err := c.Attest(bg, &attestv1.AttestRequest{NodeId: "n1", ChallengeId: "att_" + strings.Repeat("0", 48)})
	expectCode(t, "no evidence", err, codes.InvalidArgument, "")

	ch, err := c.GetChallenge(bg, &attestv1.GetChallengeRequest{NodeId: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	pcrs := e.boot.PCRs(ch.GetPcrs()...)
	wrong := bytes.Repeat([]byte{1}, len(ch.GetNonce()))
	attest, sig := ak.Quote(t, wrong, pcrs)
	req := &attestv1.AttestRequest{NodeId: "n1", ChallengeId: ch.GetChallengeId(), Nonce: ch.GetNonce(),
		Evidence: &attestv1.Evidence{Attest: attest, Signature: sig, Pcrs: pcrs, EventLog: e.boot.Bytes()}}
	_, err = c.Attest(bg, req)
	expectCode(t, "quote over another nonce", err, codes.PermissionDenied, "nonce_mismatch")
	// That attempt was not the node's, so the challenge is still live.
	req.Evidence.Attest, req.Evidence.Signature = ak.Quote(t, ch.GetNonce(), pcrs)
	if _, err := c.Attest(bg, req); err != nil {
		t.Fatalf("honest answer after a forged one: %v", err)
	}
	_, err = c.Attest(bg, req)
	expectCode(t, "replayed challenge", err, codes.PermissionDenied, "challenge_consumed")

	_, err = c.GetChallenge(bg, &attestv1.GetChallengeRequest{NodeId: "N1/.."})
	expectCode(t, "malformed node", err, codes.InvalidArgument, "")
	_, err = c.GetChallenge(bg, &attestv1.GetChallengeRequest{NodeId: "ghost"})
	if status.Code(err) == codes.OK || status.Code(err) == codes.Internal {
		t.Errorf("challenge for unknown node: %v", err)
	}

	// The node key is checked, so a passing quote with a substituted key
	// yields no identity.
	key, other := verifiertest.NewNodeKey(t), verifiertest.NewNodeKey(t)
	ch, err = c.GetChallenge(bg, &attestv1.GetChallengeRequest{NodeId: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	pcrs = e.boot.PCRs(ch.GetPcrs()...)
	b := ak.BoundEvidence(t, ch.GetNonce(), key, pcrs)
	_, err = c.Attest(bg, &attestv1.AttestRequest{NodeId: "n1", ChallengeId: ch.GetChallengeId(), Nonce: ch.GetNonce(),
		Evidence: &attestv1.Evidence{Attest: b.Attest, Signature: b.Signature, Pcrs: pcrs, EventLog: e.boot.Bytes(),
			NodeKey: &attestv1.NodeKeyEvidence{Public: other.PublicBytes(), Certify: b.Certify, CertifySignature: b.CertifySignature}}})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("substituted key: %v", err)
	}
}

func TestEnrollmentRejects(t *testing.T) {
	e := newEnv(t)
	c := e.client(nil)
	ak := verifiertest.NewAK(t)
	_, err := c.BeginEnrollment(bg, &attestv1.BeginEnrollmentRequest{NodeId: "ghost", AkPublic: ak.PublicBytes()})
	expectCode(t, "unregistered node", err, codes.PermissionDenied, "node_unknown")
	_, err = c.BeginEnrollment(bg, &attestv1.BeginEnrollmentRequest{NodeId: "", AkPublic: ak.PublicBytes()})
	expectCode(t, "empty node ID", err, codes.InvalidArgument, "")
	_, err = c.CompleteEnrollment(bg, &attestv1.CompleteEnrollmentRequest{NodeId: "n1", ChallengeId: "x"})
	expectCode(t, "malformed challenge", err, codes.InvalidArgument, "")
	_, err = c.CompleteEnrollment(bg, &attestv1.CompleteEnrollmentRequest{NodeId: "n1", ChallengeId: "enr_" + strings.Repeat("a", 32)})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("unknown challenge: %v", err)
	}
}

func TestIssueWorkloadRejects(t *testing.T) {
	e := newEnv(t)
	c, nodeCert := e.nodeIdentity()
	wk := p256(t)
	good := csr(t, wk)

	issue := func(c attestv1.NodeServiceClient, unit string, uid uint32, csr []byte) error {
		_, err := c.IssueWorkloadIdentity(bg, &attestv1.IssueWorkloadIdentityRequest{SystemdUnit: unit, Uid: uid, Csr: csr})
		return err
	}
	expectCode(t, "no client certificate", issue(e.client(nil), "api.service", 1000, good), codes.Unauthenticated, "")
	expectCode(t, "not in policy", issue(c, "api.service", 0, good), codes.PermissionDenied, "workload_not_allowed")
	expectCode(t, "other unit", issue(c, "db.service", 1000, good), codes.PermissionDenied, "workload_not_allowed")

	// A well-formed, correctly signed CSR that is merely too large.
	names := make([]string, 80)
	for i := range names {
		names[i] = strings.Repeat("a", 60) + ".example"
	}
	big, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, wk)
	if err != nil || len(big) <= MaxCSRSize {
		t.Fatal(len(big), err)
	}
	tampered := bytes.Clone(good)
	tampered[len(tampered)-5] ^= 0xff
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"empty CSR":          nil,
		"garbage CSR":        []byte("not a csr"),
		"oversized CSR":      big,
		"bad CSR signature":  tampered,
		"RSA CSR":            csr(t, r),
		"P-384 CSR":          csr(t, p384),
		"CSR with trailing":  append(bytes.Clone(good), 0),
		"certificate as CSR": nodeCert.Certificate[0],
	} {
		expectCode(t, name, issue(c, "api.service", 1000, b), codes.InvalidArgument, "")
	}

	// Certificates the identity service does not accept as node identities.
	other, err := identity.Init(t.TempDir(), identity.Options{TrustDomain: "attest.local", Now: e.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	n1, _ := identity.NodeID("attest.local", "n1")
	k := p256(t)
	foreign, err := other.Issue(identity.IssueRequest{ID: n1, PublicKey: k.Public(), TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	wr, err := c.IssueWorkloadIdentity(bg, &attestv1.IssueWorkloadIdentityRequest{SystemdUnit: "api.service", Uid: 1000, Csr: good})
	if err != nil {
		t.Fatal(err)
	}
	for name, cert := range map[string]*tls.Certificate{
		"node identity from another CA": {Certificate: [][]byte{foreign.Cert.Raw}, PrivateKey: k},
		"workload identity as node":     {Certificate: [][]byte{wr.GetIdentity().GetCertificate()}, PrivateKey: wk},
	} {
		expectCode(t, name, issue(e.client(e.tls(cert)), "api.service", 1000, good), codes.Unauthenticated, "")
	}

	// Presenting the node certificate without its key fails the
	// handshake: the client cannot produce CertificateVerify.
	stolen := &tls.Certificate{Certificate: nodeCert.Certificate, PrivateKey: p256(t)}
	if err := issue(e.client(e.tls(stolen)), "api.service", 1000, good); status.Code(err) != codes.Unavailable {
		t.Errorf("stolen certificate: %v", err)
	}

	e.clk.Add(2 * time.Hour)
	expectCode(t, "expired node identity", issue(c, "api.service", 1000, good), codes.Unauthenticated, "")
}

func TestServerAuthentication(t *testing.T) {
	e := newEnv(t)
	e.node("n1")
	other, err := identity.Init(t.TempDir(), identity.Options{TrustDomain: "attest.local", Now: e.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	wrongBundle, err := ClientTLS(other.Bundle(), "attest.local", nil, e.clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	wrongDomain, err := ClientTLS(e.ca.Bundle(), "other.local", nil, e.clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]*tls.Config{"untrusted CA": wrongBundle, "other trust domain": wrongDomain} {
		if _, err := e.client(cfg).GetChallenge(bg, &attestv1.GetChallengeRequest{NodeId: "n1"}); status.Code(err) != codes.Unavailable {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ClientTLS(nil, "attest.local", nil, nil); err == nil {
		t.Error("empty bundle accepted")
	}

	// A workload identity is a valid serverAuth certificate under the
	// bundle, but it is not attestd.
	wl, _ := identity.WorkloadID("attest.local", "api")
	k := p256(t)
	iss, err := e.ca.Issue(identity.IssueRequest{ID: wl, PublicKey: k.Public(), TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	cfg := e.tls(nil)
	err = cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{iss.Cert}})
	if err == nil || !strings.Contains(err.Error(), "want spiffe://attest.local/server/attestd") {
		t.Errorf("impersonating workload: %v", err)
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{}); err == nil {
		t.Error("no server certificate accepted")
	}
}

func TestServerCertRenewal(t *testing.T) {
	e := newEnv(t)
	first, err := e.cert.Get()
	if err != nil {
		t.Fatal(err)
	}
	if id, err := identity.Verify(e.ca.Bundle(), "attest.local", first.Leaf, e.clk.Now(), x509.ExtKeyUsageServerAuth); err != nil || id != e.cert.ID() {
		t.Fatalf("server identity %v, %v", id, err)
	}
	again, _ := e.cert.Get()
	if again != first {
		t.Fatal("renewed before half-life")
	}
	e.clk.Add(DefaultServerCertTTL / 2)
	renewed, err := e.cert.Get()
	if err != nil || renewed == first || renewed.PrivateKey.(*ecdsa.PrivateKey).Equal(first.PrivateKey) {
		t.Fatalf("not renewed with a fresh key: %v", err)
	}
	var issued int
	for en, err := range e.st.AuditEntries(bg) {
		if err != nil {
			t.Fatal(err)
		}
		if en.Action == identity.ActionIssue && bytes.Contains(en.Metadata, []byte(`"server"`)) {
			issued++
		}
	}
	if issued != 2 {
		t.Fatalf("%d server issuances audited", issued)
	}

	// With the audit store unavailable no new key is used: the current
	// certificate is served until it expires, then handshakes fail.
	if err := e.st.Close(); err != nil {
		t.Fatal(err)
	}
	e.clk.Add(DefaultServerCertTTL / 2)
	if got, err := e.cert.Get(); err != nil || got != renewed {
		t.Fatalf("before expiry: %v, %v", got == renewed, err)
	}
	if !strings.Contains(e.logs.String(), "renewal failed") {
		t.Error("renewal failure not logged")
	}
	e.clk.Add(DefaultServerCertTTL)
	if got, err := e.cert.Get(); err == nil {
		t.Fatalf("expired certificate served: %v", got.Leaf.NotAfter)
	}
}

func TestNewServerCertFailsClosed(t *testing.T) {
	e := newEnv(t)
	for name, cfg := range map[string]ServerCertConfig{
		"no CA":     {Store: e.st},
		"no store":  {CA: e.ca},
		"TTL > max": {CA: e.ca, Store: e.st, TTL: identity.MaxTTL + 1},
		"TTL < 0":   {CA: e.ca, Store: e.st, TTL: -1},
	} {
		if _, err := NewServerCert(bg, cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := e.st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewServerCert(bg, ServerCertConfig{CA: e.ca, Store: e.st}); err == nil {
		t.Error("issued a server certificate without auditing it")
	}
}

func TestInternalErrorsAreOpaque(t *testing.T) {
	e := newEnv(t)
	e.node("n1")
	c := e.client(nil)
	if err := e.st.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := c.GetChallenge(bg, &attestv1.GetChallengeRequest{NodeId: "n1"})
	if status.Code(err) != codes.Internal || status.Convert(err).Message() != "internal error" {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(e.logs.String(), "NodeService/GetChallenge") {
		t.Fatalf("not logged: %s", e.logs.String())
	}
}

func TestOversizedRequest(t *testing.T) {
	e := newEnv(t)
	_, err := e.client(nil).Attest(bg, &attestv1.AttestRequest{NodeId: "n1",
		Evidence: &attestv1.Evidence{EventLog: make([]byte, MaxMessageSize)}})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("got %v", err)
	}
}

func TestNewNodeServerRequiresServices(t *testing.T) {
	if _, err := NewNodeServer(NodeConfig{}); err == nil {
		t.Fatal("accepted")
	}
}

// GetChallenge and Attest are unauthenticated and node IDs are public, so
// anyone can answer a challenge for a node. Junk answers must not record a
// failure that supersedes the node's attestation, which would cut off its
// workload identities.
func TestForeignAttemptsCannotSupersedeNode(t *testing.T) {
	e := newEnv(t)
	node, _ := e.nodeIdentity()
	issue := func() error {
		_, err := node.IssueWorkloadIdentity(bg, &attestv1.IssueWorkloadIdentityRequest{
			SystemdUnit: "api.service", Uid: 1000, Csr: csr(t, p256(t))})
		return err
	}
	if err := issue(); err != nil {
		t.Fatal(err)
	}
	attacker := e.client(nil)
	impostor := verifiertest.NewAK(t)
	for range 3 {
		ch, err := attacker.GetChallenge(bg, &attestv1.GetChallengeRequest{NodeId: "n1"})
		if err != nil {
			t.Fatal(err)
		}
		pcrs := e.boot.PCRs(ch.GetPcrs()...)
		for _, ev := range []*attestv1.Evidence{
			{Attest: []byte("junk"), Signature: []byte("junk")},
			func() *attestv1.Evidence {
				a, s := impostor.Quote(t, ch.GetNonce(), pcrs)
				return &attestv1.Evidence{Attest: a, Signature: s, Pcrs: pcrs, EventLog: e.boot.Bytes()}
			}(),
		} {
			_, err := attacker.Attest(bg, &attestv1.AttestRequest{NodeId: "n1", ChallengeId: ch.GetChallengeId(),
				Nonce: ch.GetNonce(), Evidence: ev})
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("junk attestation: %v", err)
			}
		}
	}
	if err := issue(); err != nil {
		t.Fatalf("node cut off by foreign attempts: %v", err)
	}
}
