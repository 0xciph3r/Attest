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
	"strings"
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

type env struct {
	t   *testing.T
	dir string
	st  *store.Store
	svc *Service
	// aks remembers the AK each challenge was begun for.
	aks  map[string]*verifiertest.AK
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
	e := &env{t: t, st: st, dir: dir, aks: map[string]*verifiertest.AK{}, now: time.Now(),
		prod: swtpmtest.NewCA(t, "Production EK CA"), dev: swtpmtest.NewCA(t, "swtpm-localca")}
	prod, dev := x509.NewCertPool(), x509.NewCertPool()
	prod.AddCert(e.prod.Cert)
	dev.AddCert(e.dev.Cert)
	e.svc, err = New(Config{
		Store: st, Roots: verifier.EKRoots{Production: prod, Development: dev},
		Now: func() time.Time { return e.now },
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

// begin starts enrollment and returns the challenge and the secret its TPM
// would recover.
func (e *env) begin(nodeID string, ak *verifiertest.AK) (*Challenge, []byte) {
	e.t.Helper()
	ch, err := e.svc.Begin(ctx, nodeID, ak.PublicBytes())
	if err != nil {
		e.t.Fatalf("Begin: %v", err)
	}
	e.aks[ch.ID] = ak
	return ch, e.svc.secret(nodeID, ch.ID, ak.Name)
}

// complete answers challenge id with the AK it was begun for.
func (e *env) complete(nodeID, id string, secret []byte) error {
	var akPublic []byte
	if ak := e.aks[id]; ak != nil {
		akPublic = ak.PublicBytes()
	} else {
		akPublic = verifiertest.NewAK(e.t).PublicBytes()
	}
	return e.svc.Complete(ctx, nodeID, id, akPublic, secret)
}

func (e *env) enroll(nodeID string, ca *swtpmtest.CA) *verifiertest.AK {
	e.t.Helper()
	if _, err := e.svc.Register(ctx, "operator:alice", nodeID, ekCert(e.t, ca)); err != nil {
		e.t.Fatalf("Register: %v", err)
	}
	ak := verifiertest.NewAK(e.t)
	ch, secret := e.begin(nodeID, ak)
	if err := e.complete(nodeID, ch.ID, secret); err != nil {
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
	want := []string{ActionRegister, ActionEnroll}
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
	wantReason(t, e.complete("dev-1", ch.ID, secret), verifier.ReasonDevelopmentRoot)
	e.applyPolicy(true)
	wantReason(t, e.complete("dev-1", ch.ID, secret), verifier.ReasonChallengeConsumed)

	ch, secret = e.begin("dev-1", ak)
	if err := e.complete("dev-1", ch.ID, secret); err != nil {
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

// Begin is unauthenticated, so its refusals are not recorded.
func TestBeginRejects(t *testing.T) {
	e := newEnv(t)
	ak := verifiertest.NewAK(t)

	e.unchanged("unknown node", func() error {
		_, err := e.svc.Begin(ctx, "ghost", ak.PublicBytes())
		wantReason(t, err, verifier.ReasonNodeUnknown)
		return err
	})
	if _, err := e.svc.Register(ctx, "operator:alice", "node-1", ekCert(t, e.prod)); err != nil {
		t.Fatal(err)
	}
	e.unchanged("trailing byte", func() error {
		_, err := e.svc.Begin(ctx, "node-1", append(ak.PublicBytes(), 0))
		wantReason(t, err, verifier.ReasonAKInvalid)
		return err
	})
	weak := ak.Public
	weak.ObjectAttributes.Restricted = false
	e.unchanged("unrestricted AK", func() error {
		_, err := e.svc.Begin(ctx, "node-1", tpm2.Marshal(weak))
		wantReason(t, err, verifier.ReasonAKInvalid)
		return err
	})
	e.unchanged("oversized AK", func() error {
		_, err := e.svc.Begin(ctx, "node-1", make([]byte, MaxAKSize+1))
		wantReason(t, err, verifier.ReasonAKInvalid)
		return err
	})
	e.enroll("node-2", e.prod)
	e.unchanged("enrolled node", func() error {
		_, err := e.svc.Begin(ctx, "node-2", ak.PublicBytes())
		wantReason(t, err, verifier.ReasonNodeState)
		return err
	})
	e.unchanged("successful begin", func() error {
		e.begin("node-1", ak)
		return errors.New("ok")
	})
	want := []string{ActionRegister, ActionRegister, ActionEnroll}
	if got := e.auditActions(); !slices.Equal(got, want) {
		t.Fatalf("audit %v, want %v", got, want)
	}
}

func TestCompleteRejects(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.Register(ctx, "operator:alice", "node-1", ekCert(t, e.prod)); err != nil {
		t.Fatal(err)
	}
	ak := verifiertest.NewAK(t)

	// Until the secret matches, the caller could be anyone: refusals leave
	// the challenge usable and record nothing.
	t.Run("wrong secret", func(t *testing.T) {
		if _, err := e.svc.Register(ctx, "operator:alice", "node-w", ekCert(t, e.prod)); err != nil {
			t.Fatal(err)
		}
		ch, secret := e.begin("node-w", ak)
		wrong := bytes.Clone(secret)
		wrong[0] ^= 1
		e.unchanged("wrong secret", func() error {
			err := e.complete("node-w", ch.ID, wrong)
			wantReason(t, err, verifier.ReasonActivationFailed)
			return err
		})
		if err := e.complete("node-w", ch.ID, secret); err != nil {
			t.Fatalf("challenge burned by a wrong guess: %v", err)
		}
	})
	t.Run("short secret", func(t *testing.T) {
		ch, secret := e.begin("node-1", ak)
		e.unchanged("short secret", func() error {
			err := e.complete("node-1", ch.ID, secret[:16])
			wantReason(t, err, verifier.ReasonActivationFailed)
			return err
		})
	})
	t.Run("expired", func(t *testing.T) {
		ch, secret := e.begin("node-1", ak)
		e.now = e.now.Add(DefaultChallengeTTL)
		defer func() { e.now = e.now.Add(-DefaultChallengeTTL) }()
		e.unchanged("expired", func() error {
			err := e.complete("node-1", ch.ID, secret)
			wantReason(t, err, verifier.ReasonChallengeExpired)
			return err
		})
	})
	t.Run("wrong node", func(t *testing.T) {
		if _, err := e.svc.Register(ctx, "operator:alice", "node-x", ekCert(t, e.prod)); err != nil {
			t.Fatal(err)
		}
		ch, secret := e.begin("node-1", ak)
		e.unchanged("wrong node", func() error {
			err := e.complete("node-x", ch.ID, secret)
			wantReason(t, err, verifier.ReasonActivationFailed)
			return err
		})
	})
	t.Run("AK substituted", func(t *testing.T) {
		ch, secret := e.begin("node-1", ak)
		e.unchanged("AK substituted", func() error {
			err := e.svc.Complete(ctx, "node-1", ch.ID, verifiertest.NewAK(t).PublicBytes(), secret)
			wantReason(t, err, verifier.ReasonActivationFailed)
			return err
		})
		for name, pub := range map[string][]byte{
			"missing":   nil,
			"oversized": make([]byte, MaxAKSize+1),
			"trailing":  append(ak.PublicBytes(), 0),
		} {
			e.unchanged("AK "+name, func() error {
				err := e.svc.Complete(ctx, "node-1", ch.ID, pub, secret)
				wantReason(t, err, verifier.ReasonAKInvalid)
				return err
			})
		}
	})
	t.Run("forged challenge", func(t *testing.T) {
		ch, secret := e.begin("node-1", ak)
		// Pushing the expiry out changes the ID and so the secret.
		later := ch.ID[:len(ch.ID)-16] + "7fffffffffffffff"
		e.aks[later] = ak
		for _, id := range []string{"enr_" + strings.Repeat("0", 48), later} {
			e.unchanged("forged "+id, func() error {
				err := e.complete("node-1", id, secret)
				wantReason(t, err, verifier.ReasonActivationFailed)
				return err
			})
		}
		if err := e.complete("node-1", "../etc", nil); !errors.Is(err, ErrInvalidChallengeID) {
			t.Fatal(err)
		}
	})
	t.Run("challenge from before a restart", func(t *testing.T) {
		ch, secret := e.begin("node-1", ak)
		restarted, err := New(Config{Store: e.st, Roots: e.svc.roots, Now: e.svc.now})
		if err != nil {
			t.Fatal(err)
		}
		e.unchanged("after restart", func() error {
			err := restarted.Complete(ctx, "node-1", ch.ID, ak.PublicBytes(), secret)
			wantReason(t, err, verifier.ReasonActivationFailed)
			return err
		})
	})
	// Failures after the secret matches are the node's own and recorded.
	t.Run("revoked before completion", func(t *testing.T) {
		if _, err := e.svc.Register(ctx, "operator:alice", "node-r", ekCert(t, e.prod)); err != nil {
			t.Fatal(err)
		}
		ch, secret := e.begin("node-r", verifiertest.NewAK(t))
		if err := e.svc.Revoke(ctx, "operator:alice", "node-r"); err != nil {
			t.Fatal(err)
		}
		wantReason(t, e.complete("node-r", ch.ID, secret), verifier.ReasonNodeState)
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
		wantReason(t, e.complete("node-e", ch.ID, secret), verifier.ReasonEKUntrusted)
	})
	t.Run("AK already enrolled for another node", func(t *testing.T) {
		shared := e.enroll("node-a", e.prod)
		if _, err := e.svc.Register(ctx, "operator:alice", "node-b", ekCert(t, e.prod)); err != nil {
			t.Fatal(err)
		}
		ch, secret := e.begin("node-b", shared)
		wantReason(t, e.complete("node-b", ch.ID, secret), verifier.ReasonAKInUse)
		if n, _ := e.st.Node(ctx, "node-b"); n.State != store.NodeRegistered {
			t.Fatalf("node-b is %s", n.State)
		}
		e.unchanged("replay", func() error {
			err := e.complete("node-b", ch.ID, secret)
			wantReason(t, err, verifier.ReasonChallengeConsumed)
			return err
		})
	})

	if n, _ := e.st.Node(ctx, "node-1"); n.State != store.NodeRegistered {
		t.Fatalf("failed attempts changed node state to %s", n.State)
	}
	denied := 0
	for _, a := range e.auditActions() {
		if a == ActionEnrollDenied {
			denied++
		}
	}
	// revoked, EK expired and AK in use.
	if denied != 3 {
		t.Fatalf("%d denials audited, want 3", denied)
	}
}

// The credential secret is never persisted; only its hash is.
func TestSecretNotStored(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.Register(ctx, "operator:alice", "node-1", ekCert(t, e.prod)); err != nil {
		t.Fatal(err)
	}
	ch, secret := e.begin("node-1", verifiertest.NewAK(t))
	if err := e.complete("node-1", ch.ID, secret); err != nil {
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
