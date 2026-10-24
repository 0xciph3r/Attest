package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"

	"github.com/0xciph3r/attest/internal/audit"
	"github.com/0xciph3r/attest/internal/eventlog"
	"github.com/0xciph3r/attest/internal/policy"
	"github.com/0xciph3r/attest/internal/store"
	"github.com/0xciph3r/attest/internal/tpm/swtpm/swtpmtest"
	"github.com/0xciph3r/attest/internal/verifier"
	"github.com/0xciph3r/attest/internal/verifier/verifiertest"
)

var ctx = context.Background()

// recorder is a random source that remembers what it produced, so tests can
// learn the credential secret without a TPM to activate it. The secret is the
// first SecretSize bytes Begin reads.
type recorder struct {
	mu  sync.Mutex
	buf []byte
}

func (r *recorder) Read(p []byte) (int, error) {
	n, err := rand.Read(p)
	r.mu.Lock()
	r.buf = append(r.buf, p[:n]...)
	r.mu.Unlock()
	return n, err
}

func (r *recorder) reset() { r.mu.Lock(); r.buf = nil; r.mu.Unlock() }

func (r *recorder) secret() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Clone(r.buf[:SecretSize])
}

type env struct {
	t    *testing.T
	dir  string
	st   *store.Store
	svc  *Service
	rng  *recorder
	now  time.Time
	prod *swtpmtest.CA
	dev  *swtpmtest.CA
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "attest.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e := &env{t: t, st: st, dir: dir, rng: &recorder{}, now: time.Now(),
		prod: swtpmtest.NewCA(t, "Production EK CA"), dev: swtpmtest.NewCA(t, "swtpm-localca")}
	prod, dev := x509.NewCertPool(), x509.NewCertPool()
	prod.AddCert(e.prod.Cert)
	dev.AddCert(e.dev.Cert)
	e.svc, err = New(Config{
		Store: st, Roots: verifier.EKRoots{Production: prod, Development: dev},
		Now: func() time.Time { return e.now }, Rand: e.rng,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) applyPolicy(allowDev bool) {
	e.t.Helper()
	doc := verifiertest.PolicyJSON(e.t, allowDev, eventlog.SimulatedBoot("v1"))
	m, err := policy.ParseMeasurement(doc)
	if err != nil {
		e.t.Fatal(err)
	}
	err = e.st.Update(ctx, func(tx *store.Tx) error {
		_, err := tx.InsertPolicy(&store.Policy{Kind: store.PolicyMeasurement, Document: doc, Digest: m.Digest(),
			CreatedAt: e.now, CreatedBy: "operator:alice"})
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func ekCert(t *testing.T, ca *swtpmtest.CA) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ca.IssueEKCert(t, &key.PublicKey)
}

// begin starts enrollment and returns the challenge and its secret.
func (e *env) begin(nodeID string, ak *verifiertest.AK) (*Challenge, []byte) {
	e.t.Helper()
	e.rng.reset()
	ch, err := e.svc.Begin(ctx, nodeID, ak.PublicBytes())
	if err != nil {
		e.t.Fatalf("Begin: %v", err)
	}
	return ch, e.rng.secret()
}

func (e *env) enroll(nodeID string, ca *swtpmtest.CA) *verifiertest.AK {
	e.t.Helper()
	if _, err := e.svc.Register(ctx, "operator:alice", nodeID, ekCert(e.t, ca)); err != nil {
		e.t.Fatalf("Register: %v", err)
	}
	ak := verifiertest.NewAK(e.t)
	ch, secret := e.begin(nodeID, ak)
	if err := e.svc.Complete(ctx, nodeID, ch.ID, secret); err != nil {
		e.t.Fatalf("Complete: %v", err)
	}
	return ak
}

func (e *env) auditActions() []string {
	e.t.Helper()
	var out []string
	for ent, err := range e.st.AuditEntries(ctx) {
		if err != nil {
			e.t.Fatal(err)
		}
		out = append(out, ent.Action)
	}
	if _, err := audit.Verify(e.st.AuditEntries(ctx), audit.VerifyOptions{AllowUnanchored: true}); err != nil {
		e.t.Fatalf("audit chain: %v", err)
	}
	return out
}

func wantReason(t *testing.T, err error, want verifier.Reason) {
	t.Helper()
	if got := verifier.ReasonOf(err); got != want {
		t.Fatalf("got reason %q (%v), want %q", got, err, want)
	}
}

func TestEnroll(t *testing.T) {
	e := newEnv(t)
	ak := e.enroll("node-1", e.prod)

	n, err := e.st.Node(ctx, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	if n.State != store.NodeEnrolled || !bytes.Equal(n.AKName, ak.Name) || n.EKDevelopment {
		t.Fatalf("got %+v", n)
	}
	want := []string{ActionRegister, ActionEnrollBegin, ActionEnroll}
	if got := e.auditActions(); !slices.Equal(got, want) {
		t.Fatalf("audit %v, want %v", got, want)
	}
}

func TestEnrollDevelopmentRoot(t *testing.T) {
	e := newEnv(t)
	cert := ekCert(t, e.dev)
	_, err := e.svc.Register(ctx, "operator:alice", "dev-1", cert)
	wantReason(t, err, verifier.ReasonPolicyMissing)

	e.applyPolicy(false)
	_, err = e.svc.Register(ctx, "operator:alice", "dev-1", cert)
	wantReason(t, err, verifier.ReasonDevelopmentRoot)

	e.applyPolicy(true)
	if _, err := e.svc.Register(ctx, "operator:alice", "dev-1", cert); err != nil {
		t.Fatal(err)
	}
	// Withdrawing permission between registration and completion blocks
	// enrollment and burns the challenge.
	ak := verifiertest.NewAK(t)
	ch, secret := e.begin("dev-1", ak)
	e.applyPolicy(false)
	wantReason(t, e.svc.Complete(ctx, "dev-1", ch.ID, secret), verifier.ReasonDevelopmentRoot)
	e.applyPolicy(true)
	wantReason(t, e.svc.Complete(ctx, "dev-1", ch.ID, secret), verifier.ReasonChallengeConsumed)

	ch, secret = e.begin("dev-1", ak)
	if err := e.svc.Complete(ctx, "dev-1", ch.ID, secret); err != nil {
		t.Fatal(err)
	}
	if n, _ := e.st.Node(ctx, "dev-1"); !n.EKDevelopment {
		t.Fatal("development root not recorded")
	}
}

func TestRegisterRejects(t *testing.T) {
	e := newEnv(t)
	untrusted := swtpmtest.NewCA(t, "Unknown CA")
	cert := ekCert(t, e.prod)

	if _, err := e.svc.Register(ctx, "operator:alice", "Node_1", cert); !errors.Is(err, ErrInvalidNodeID) {
		t.Fatalf("invalid node ID: %v", err)
	}
	_, err := e.svc.Register(ctx, "operator:alice", "node-1", ekCert(t, untrusted))
	wantReason(t, err, verifier.ReasonEKUntrusted)
	_, err = e.svc.Register(ctx, "operator:alice", "node-1", make([]byte, MaxEKCertSize+1))
	wantReason(t, err, verifier.ReasonEKCertInvalid)

	if _, err := e.svc.Register(ctx, "operator:alice", "node-1", cert); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Register(ctx, "operator:alice", "node-2", cert); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("same EK registered twice: %v", err)
	}
	if got := e.auditActions(); !slices.Equal(got, []string{ActionRegister}) {
		t.Fatalf("rejected registrations were recorded: %v", got)
	}
}

func TestBeginRejects(t *testing.T) {
	e := newEnv(t)
	ak := verifiertest.NewAK(t)

	_, err := e.svc.Begin(ctx, "ghost", ak.PublicBytes())
	wantReason(t, err, verifier.ReasonNodeUnknown)

	if _, err := e.svc.Register(ctx, "operator:alice", "node-1", ekCert(t, e.prod)); err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.Begin(ctx, "node-1", append(ak.PublicBytes(), 0))
	wantReason(t, err, verifier.ReasonAKInvalid)
	weak := ak.Public
	weak.ObjectAttributes.Restricted = false
	_, err = e.svc.Begin(ctx, "node-1", tpm2.Marshal(weak))
	wantReason(t, err, verifier.ReasonAKInvalid)

	e.enroll("node-2", e.prod)
	_, err = e.svc.Begin(ctx, "node-2", ak.PublicBytes())
	wantReason(t, err, verifier.ReasonNodeState)

	got := e.auditActions()
	denied := 0
	for _, a := range got {
		if a == ActionEnrollDenied {
			denied++
		}
	}
	if denied != 4 {
		t.Fatalf("denials not audited: %v", got)
	}
}

func TestCompleteRejects(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.Register(ctx, "operator:alice", "node-1", ekCert(t, e.prod)); err != nil {
		t.Fatal(err)
	}
	ak := verifiertest.NewAK(t)

	t.Run("wrong secret burns the challenge", func(t *testing.T) {
		ch, secret := e.begin("node-1", ak)
		wrong := bytes.Clone(secret)
		wrong[0] ^= 1
		wantReason(t, e.svc.Complete(ctx, "node-1", ch.ID, wrong), verifier.ReasonActivationFailed)
		wantReason(t, e.svc.Complete(ctx, "node-1", ch.ID, secret), verifier.ReasonChallengeConsumed)
	})
	t.Run("short secret", func(t *testing.T) {
		ch, secret := e.begin("node-1", ak)
		wantReason(t, e.svc.Complete(ctx, "node-1", ch.ID, secret[:16]), verifier.ReasonActivationFailed)
	})
	t.Run("expired", func(t *testing.T) {
		ch, secret := e.begin("node-1", ak)
		e.now = e.now.Add(DefaultChallengeTTL)
		defer func() { e.now = e.now.Add(-DefaultChallengeTTL) }()
		wantReason(t, e.svc.Complete(ctx, "node-1", ch.ID, secret), verifier.ReasonChallengeExpired)
	})
	t.Run("wrong node", func(t *testing.T) {
		if _, err := e.svc.Register(ctx, "operator:alice", "node-x", ekCert(t, e.prod)); err != nil {
			t.Fatal(err)
		}
		ch, secret := e.begin("node-1", ak)
		wantReason(t, e.svc.Complete(ctx, "node-x", ch.ID, secret), verifier.ReasonChallengeWrongNode)
		wantReason(t, e.svc.Complete(ctx, "node-1", ch.ID, secret), verifier.ReasonChallengeConsumed)
	})
	t.Run("unknown challenge", func(t *testing.T) {
		wantReason(t, e.svc.Complete(ctx, "node-1", "enr_00000000000000000000000000000000", make([]byte, 32)),
			verifier.ReasonChallengeUnknown)
		if err := e.svc.Complete(ctx, "node-1", "../etc", nil); !errors.Is(err, ErrInvalidChallengeID) {
			t.Fatal(err)
		}
	})
	t.Run("revoked before completion", func(t *testing.T) {
		if _, err := e.svc.Register(ctx, "operator:alice", "node-r", ekCert(t, e.prod)); err != nil {
			t.Fatal(err)
		}
		ch, secret := e.begin("node-r", verifiertest.NewAK(t))
		if err := e.svc.Revoke(ctx, "operator:alice", "node-r"); err != nil {
			t.Fatal(err)
		}
		wantReason(t, e.svc.Complete(ctx, "node-r", ch.ID, secret), verifier.ReasonNodeState)
	})
	t.Run("EK certificate expired since registration", func(t *testing.T) {
		if _, err := e.svc.Register(ctx, "operator:alice", "node-e", ekCert(t, e.prod)); err != nil {
			t.Fatal(err)
		}
		saved := e.now
		e.svc.ttl = 100 * 365 * 24 * time.Hour
		defer func() { e.now, e.svc.ttl = saved, DefaultChallengeTTL }()
		ch, secret := e.begin("node-e", verifiertest.NewAK(t))
		e.now = e.now.AddDate(30, 0, 0)
		wantReason(t, e.svc.Complete(ctx, "node-e", ch.ID, secret), verifier.ReasonEKUntrusted)
	})
	t.Run("AK already enrolled for another node", func(t *testing.T) {
		shared := e.enroll("node-a", e.prod)
		if _, err := e.svc.Register(ctx, "operator:alice", "node-b", ekCert(t, e.prod)); err != nil {
			t.Fatal(err)
		}
		ch, secret := e.begin("node-b", shared)
		wantReason(t, e.svc.Complete(ctx, "node-b", ch.ID, secret), verifier.ReasonAKInUse)
		if n, _ := e.st.Node(ctx, "node-b"); n.State != store.NodeRegistered {
			t.Fatalf("node-b is %s", n.State)
		}
	})

	if n, _ := e.st.Node(ctx, "node-1"); n.State != store.NodeRegistered {
		t.Fatalf("failed attempts changed node state to %s", n.State)
	}
	e.auditActions()
}

// The credential secret is never persisted; only its hash is.
func TestSecretNotStored(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.Register(ctx, "operator:alice", "node-1", ekCert(t, e.prod)); err != nil {
		t.Fatal(err)
	}
	ch, secret := e.begin("node-1", verifiertest.NewAK(t))
	if err := e.svc.Complete(ctx, "node-1", ch.ID, secret); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(secret)
	files, _ := filepath.Glob(filepath.Join(e.dir, "*"))
	var all []byte
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, b...)
	}
	if bytes.Contains(all, secret) {
		t.Fatal("plaintext credential secret found in the database files")
	}
	if !bytes.Contains(all, h[:]) {
		t.Fatal("secret hash not found; the scan is not seeing the data")
	}
}
