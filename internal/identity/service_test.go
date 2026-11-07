package identity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/0xciph3r/attest/internal/audit"
	"github.com/0xciph3r/attest/internal/store"
)

var bg = context.Background()

const apiPolicy = `{"schema":"attest.dev/workload-policy/v1","workloads":[
	{"name":"api","nodes":["n1"],"systemd_unit":"api.service","uid":1000,"ttl":"15m"},
	{"name":"db","nodes":["n2"],"systemd_unit":"db.service","uid":1001}]}`

type svcEnv struct {
	t   *testing.T
	st  *store.Store
	ca  *CA
	dir string
	clk *clock
	svc *Service
	n   int
}

func newEnv(t *testing.T) *svcEnv {
	t.Helper()
	ca, dir, clk := newCAInDir(t)
	st, err := store.Open(bg, filepath.Join(t.TempDir(), "attest.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc, err := NewService(ServiceConfig{Store: st, CA: ca, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	e := &svcEnv{t: t, st: st, ca: ca, dir: dir, clk: clk, svc: svc}
	e.update(func(tx *store.Tx) error {
		_, err := tx.InsertPolicy(&store.Policy{Kind: store.PolicyMeasurement, Document: []byte("{}"),
			Digest: make([]byte, 32), CreatedAt: t0, CreatedBy: "op"})
		return err
	})
	e.node("n1")
	e.node("n2")
	return e
}

func (e *svcEnv) update(fn func(*store.Tx) error) {
	e.t.Helper()
	if err := e.st.Update(bg, fn); err != nil {
		e.t.Fatal(err)
	}
}

func (e *svcEnv) seq(tx *store.Tx) uint64 {
	en, err := tx.AppendAudit(audit.Record{Time: e.clk.now, Actor: "test", Action: "test", Object: "x", Metadata: []byte("{}")})
	if err != nil {
		e.t.Fatal(err)
	}
	return en.Sequence
}

func (e *svcEnv) node(id string) {
	e.update(func(tx *store.Tx) error {
		ek := sha256.Sum256([]byte(id))
		if err := tx.InsertNode(&store.Node{ID: id, EKType: "eccp256", EKCert: []byte{1}, EKPublic: ek[:], EKDigest: ek[:],
			RegisteredBy: "op", RegisteredAt: t0}); err != nil {
			return err
		}
		return tx.EnrollNode(id, []byte{1}, ek[:], t0)
	})
}

// attest records an attestation of node at the current time under the
// current measurement policy. A nil key records one that bound no key.
func (e *svcEnv) attest(node string, passed bool, key crypto.PublicKey) int64 {
	e.t.Helper()
	var id int64
	e.update(func(tx *store.Tx) error {
		e.n++
		ch := fmt.Sprintf("att_%032x", e.n)
		if err := tx.InsertAttestChallenge(&store.AttestChallenge{ID: ch, NodeID: node, NonceHash: make([]byte, 32),
			IssuedAt: e.clk.now, ExpiresAt: e.clk.now.Add(time.Minute)}); err != nil {
			return err
		}
		m, err := tx.CurrentPolicy(store.PolicyMeasurement)
		if err != nil {
			return err
		}
		a := &store.Attestation{NodeID: node, ChallengeID: ch, VerifiedAt: e.clk.now, Passed: passed,
			PolicyVersion: m.Version, EvidenceHash: make([]byte, 32), AuditSeq: e.seq(tx)}
		if passed {
			a.Reference, a.PCRDigest = "fw", make([]byte, 32)
		} else {
			a.Reason = "pcr_digest_mismatch"
		}
		if key != nil {
			a.KeyBinding = mustHash(e.t, key)
		}
		id, err = tx.InsertAttestation(a)
		return err
	})
	return id
}

func mustHash(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	h, err := spkiHash(pub)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// audit returns the number of audit entries and the newest one's action and
// metadata, after checking the chain.
func (e *svcEnv) audit() (n int, action string, meta map[string]any) {
	e.t.Helper()
	if _, err := audit.Verify(e.st.AuditEntries(bg), audit.VerifyOptions{AllowUnanchored: true}); err != nil {
		e.t.Fatal(err)
	}
	var last audit.Entry
	for en, err := range e.st.AuditEntries(bg) {
		if err != nil {
			e.t.Fatal(err)
		}
		n, last = n+1, en
	}
	if n == 0 {
		return 0, "", nil
	}
	if err := json.Unmarshal(last.Metadata, &meta); err != nil {
		e.t.Fatal(err)
	}
	return n, last.Action, meta
}

// expectDenied runs op and checks it was refused for reason, audited as a
// denial, and issued nothing.
func (e *svcEnv) expectDenied(name string, reason Reason, op func() (*Identity, error)) map[string]any {
	e.t.Helper()
	before, _, _ := e.audit()
	id, err := op()
	if ReasonOf(err) != reason || id != nil {
		e.t.Errorf("%s: got %v, %v; want %s", name, id, err, reason)
		return nil
	}
	n, action, meta := e.audit()
	if n != before+1 || action != ActionIssueDenied || meta["reason"] != string(reason) {
		e.t.Errorf("%s: audit %d->%d %s %v", name, before, n, action, meta)
	}
	return meta
}

// expectRefused runs op and checks it failed with target without touching
// the audit log.
func (e *svcEnv) expectRefused(name string, target error, op func() (*Identity, error)) {
	e.t.Helper()
	before, _, _ := e.audit()
	id, err := op()
	if !errors.Is(err, target) || id != nil || ReasonOf(err) != "" {
		e.t.Errorf("%s: got %v, %v; want %v", name, id, err, target)
	}
	if n, _, _ := e.audit(); n != before {
		e.t.Errorf("%s: audit grew %d->%d", name, before, n)
	}
}

func TestNewServiceRejects(t *testing.T) {
	e := newEnv(t)
	for name, cfg := range map[string]ServiceConfig{
		"no store":         {CA: e.ca},
		"no CA":            {Store: e.st},
		"negative TTL":     {Store: e.st, CA: e.ca, NodeTTL: -time.Hour},
		"TTL over maximum": {Store: e.st, CA: e.ca, NodeTTL: MaxTTL + 1},
		"negative max age": {Store: e.st, CA: e.ca, AttestationMaxAge: -time.Second},
	} {
		if s, err := NewService(cfg); err == nil {
			t.Errorf("%s: accepted %+v", name, s)
		}
	}
}

func TestIssueNode(t *testing.T) {
	e := newEnv(t)
	k := p256(t)
	attID := e.attest("n1", true, k.Public())
	e.clk.now = e.clk.now.Add(DefaultAttestationMaxAge) // exactly at the bound

	id, err := e.svc.IssueNode(bg, "n1", attID, k.Public())
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(id.Bundle, "attest.local", id.Cert, e.clk.now, x509.ExtKeyUsageClientAuth)
	if err != nil || got != must(NodeID("attest.local", "n1")) || got != id.ID {
		t.Fatalf("verify: %v, %v", got, err)
	}
	if !id.Cert.PublicKey.(*ecdsa.PublicKey).Equal(k.Public()) || !id.Cert.NotAfter.Equal(e.clk.now.Add(DefaultNodeTTL)) {
		t.Fatalf("certificate %v until %s", id.Cert.PublicKey, id.Cert.NotAfter)
	}
	if _, err := Verify(id.Bundle, "attest.local", id.Cert, e.clk.now, x509.ExtKeyUsageServerAuth); err == nil {
		t.Fatal("node identity usable as a server")
	}
	rec, err := e.st.Identity(bg, id.Serial)
	if err != nil || rec.Kind != store.IdentityNode || rec.AttestationID != attID || rec.NodeID != "n1" ||
		!bytes.Equal(rec.PublicKeyHash, mustHash(t, k.Public())) || rec.AuditSeq != id.AuditSeq ||
		!rec.NotAfter.Equal(id.Cert.NotAfter) || rec.SPIFFEID != id.ID.String() {
		t.Fatalf("record %+v, %v", rec, err)
	}
	if _, action, meta := e.audit(); action != ActionIssue || meta["spiffe_id"] != id.ID.String() || meta["kind"] != "node" {
		t.Fatalf("audit %s %v", action, meta)
	}
}

func TestIssueNodeDenied(t *testing.T) {
	key := func(t *testing.T) *ecdsa.PrivateKey { return p256(t) }
	for _, tc := range []struct {
		name   string
		reason Reason
		// setup returns the attestation and key to request with.
		setup func(e *svcEnv) (int64, crypto.PublicKey)
	}{
		{"unknown attestation", ReasonAttestationUnknown, func(e *svcEnv) (int64, crypto.PublicKey) {
			k := key(e.t)
			return e.attest("n1", true, k.Public()) + 1, k.Public()
		}},
		{"another node's attestation", ReasonAttestationWrongNode, func(e *svcEnv) (int64, crypto.PublicKey) {
			k := key(e.t)
			return e.attest("n2", true, k.Public()), k.Public()
		}},
		{"failed attestation", ReasonAttestationFailed, func(e *svcEnv) (int64, crypto.PublicKey) {
			k := key(e.t)
			return e.attest("n1", false, k.Public()), k.Public()
		}},
		{"superseded by a later pass", ReasonAttestationSuperseded, func(e *svcEnv) (int64, crypto.PublicKey) {
			k := key(e.t)
			id := e.attest("n1", true, k.Public())
			e.attest("n1", true, k.Public())
			return id, k.Public()
		}},
		{"superseded by a later failure", ReasonAttestationSuperseded, func(e *svcEnv) (int64, crypto.PublicKey) {
			k := key(e.t)
			id := e.attest("n1", true, k.Public())
			e.attest("n1", false, k.Public())
			return id, k.Public()
		}},
		{"stale attestation", ReasonAttestationStale, func(e *svcEnv) (int64, crypto.PublicKey) {
			k := key(e.t)
			id := e.attest("n1", true, k.Public())
			e.clk.now = e.clk.now.Add(DefaultAttestationMaxAge + time.Second)
			return id, k.Public()
		}},
		{"attestation from the future", ReasonAttestationStale, func(e *svcEnv) (int64, crypto.PublicKey) {
			k := key(e.t)
			id := e.attest("n1", true, k.Public())
			e.clk.now = e.clk.now.Add(-clockSkew - time.Second)
			return id, k.Public()
		}},
		{"measurement policy changed", ReasonMeasurementPolicy, func(e *svcEnv) (int64, crypto.PublicKey) {
			k := key(e.t)
			id := e.attest("n1", true, k.Public())
			e.update(func(tx *store.Tx) error {
				_, err := tx.InsertPolicy(&store.Policy{Kind: store.PolicyMeasurement, Document: []byte("{}"),
					Digest: make([]byte, 32), CreatedAt: t0, CreatedBy: "op"})
				return err
			})
			return id, k.Public()
		}},
		{"attestation bound no key", ReasonKeyNotAttested, func(e *svcEnv) (int64, crypto.PublicKey) {
			return e.attest("n1", true, nil), key(e.t).Public()
		}},
		{"key other than the bound one", ReasonKeyBinding, func(e *svcEnv) (int64, crypto.PublicKey) {
			return e.attest("n1", true, key(e.t).Public()), key(e.t).Public()
		}},
		{"node revoked", ReasonNodeNotEnrolled, func(e *svcEnv) (int64, crypto.PublicKey) {
			k := key(e.t)
			id := e.attest("n1", true, k.Public())
			e.update(func(tx *store.Tx) error { return tx.RevokeNode("n1", e.clk.now) })
			return id, k.Public()
		}},
		{"second issuance", ReasonAlreadyIssued, func(e *svcEnv) (int64, crypto.PublicKey) {
			k := key(e.t)
			id := e.attest("n1", true, k.Public())
			if _, err := e.svc.IssueNode(bg, "n1", id, k.Public()); err != nil {
				e.t.Fatal(err)
			}
			return id, k.Public()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			attID, pub := tc.setup(e)
			meta := e.expectDenied(tc.name, tc.reason, func() (*Identity, error) { return e.svc.IssueNode(bg, "n1", attID, pub) })
			if meta != nil && (meta["attestation"] != float64(attID) || meta["kind"] != "node") {
				t.Errorf("denial metadata %v", meta)
			}
			if tc.reason != ReasonAlreadyIssued && attID > 0 {
				err := e.st.Update(bg, func(tx *store.Tx) error {
					_, err := tx.NodeIdentityForAttestation(attID)
					return err
				})
				if !errors.Is(err, store.ErrNotFound) {
					t.Errorf("identity recorded: %v", err)
				}
			}
		})
	}
}

func TestIssueNodeRefusesInvalidRequests(t *testing.T) {
	e := newEnv(t)
	k := p256(t)
	attID := e.attest("n1", true, k.Public())
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	offCurve := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}
	for name, req := range map[string]struct {
		node string
		att  int64
		pub  crypto.PublicKey
	}{
		"malformed node ID":    {"N1/../x", attID, k.Public()},
		"empty node ID":        {"", attID, k.Public()},
		"zero attestation":     {"n1", 0, k.Public()},
		"negative attestation": {"n1", -1, k.Public()},
		"nil key":              {"n1", attID, nil},
		"typed nil key":        {"n1", attID, (*ecdsa.PublicKey)(nil)},
		"P-384 key":            {"n1", attID, p384.Public()},
		"RSA key":              {"n1", attID, r.Public()},
		"off-curve key":        {"n1", attID, offCurve},
	} {
		e.expectRefused(name, ErrInvalidRequest, func() (*Identity, error) { return e.svc.IssueNode(bg, req.node, req.att, req.pub) })
	}
	// The valid request still succeeds: nothing above consumed it.
	if _, err := e.svc.IssueNode(bg, "n1", attID, k.Public()); err != nil {
		t.Fatal(err)
	}
}

func TestIssueNodeFailsClosed(t *testing.T) {
	t.Run("expired CA", func(t *testing.T) {
		e := newEnv(t)
		e.clk.now = e.ca.Cert().NotAfter.Add(time.Second)
		k := p256(t)
		attID := e.attest("n1", true, k.Public())
		e.expectRefused("expired CA", ErrCAExpired, func() (*Identity, error) { return e.svc.IssueNode(bg, "n1", attID, k.Public()) })
	})
	t.Run("cancelled context", func(t *testing.T) {
		e := newEnv(t)
		k := p256(t)
		attID := e.attest("n1", true, k.Public())
		ctx, cancel := context.WithCancel(bg)
		cancel()
		e.expectRefused("cancelled", context.Canceled, func() (*Identity, error) { return e.svc.IssueNode(ctx, "n1", attID, k.Public()) })
		// Nothing was consumed.
		if _, err := e.svc.IssueNode(bg, "n1", attID, k.Public()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("serial entropy failure", func(t *testing.T) {
		e := newEnv(t)
		o := opts(e.clk)
		o.Rand = errReader{}
		ca, err := Load(e.dir, o)
		if err != nil {
			t.Fatal(err)
		}
		e.svc.ca = ca
		k := p256(t)
		attID := e.attest("n1", true, k.Public())
		before, _, _ := e.audit()
		if id, err := e.svc.IssueNode(bg, "n1", attID, k.Public()); err == nil || ReasonOf(err) != "" {
			t.Fatalf("got %v, %v", id, err)
		}
		if n, _, _ := e.audit(); n != before {
			t.Fatalf("audit grew %d->%d", before, n)
		}
	})
}

func TestIssueNodeConcurrently(t *testing.T) {
	e := newEnv(t)
	k := p256(t)
	attID := e.attest("n1", true, k.Public())
	const n = 8
	var (
		wg   sync.WaitGroup
		errs = make([]error, n)
	)
	for i := range n {
		wg.Go(func() { _, errs[i] = e.svc.IssueNode(bg, "n1", attID, k.Public()) })
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case ReasonOf(err) != ReasonAlreadyIssued:
			t.Errorf("unexpected error %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d issuances from one attestation", ok)
	}
}

func (e *svcEnv) applyPolicy(doc string) int64 {
	e.t.Helper()
	v, err := e.svc.ApplyWorkloadPolicy(bg, "operator:alice", []byte(doc))
	if err != nil {
		e.t.Fatal(err)
	}
	return v
}

func TestApplyWorkloadPolicy(t *testing.T) {
	e := newEnv(t)
	before, _, _ := e.audit()
	for name, doc := range map[string]string{
		"empty":           ``,
		"not JSON":        `{`,
		"wrong schema":    `{"schema":"attest.dev/measurement-policy/v1","workloads":[]}`,
		"unknown field":   `{"schema":"attest.dev/workload-policy/v1","workloads":[],"allow_all":true}`,
		"root workload":   `{"schema":"attest.dev/workload-policy/v1","workloads":[{"name":"x","nodes":["n1"],"systemd_unit":"x.service","uid":0}]}`,
		"overlong ttl":    `{"schema":"attest.dev/workload-policy/v1","workloads":[{"name":"x","nodes":["n1"],"systemd_unit":"x.service","uid":1,"ttl":"2h"}]}`,
		"trailing object": apiPolicy + `{}`,
	} {
		if v, err := e.svc.ApplyWorkloadPolicy(bg, "operator:alice", []byte(doc)); err == nil {
			t.Errorf("%s: applied as v%d", name, v)
		}
	}
	if v, err := e.svc.ApplyWorkloadPolicy(bg, "", []byte(apiPolicy)); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("anonymous apply: v%d, %v", v, err)
	}
	if n, _, _ := e.audit(); n != before {
		t.Fatalf("rejected policies were audited: %d->%d", before, n)
	}
	if _, err := e.st.CurrentPolicy(bg, store.PolicyWorkload); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rejected policy stored: %v", err)
	}

	v := e.applyPolicy(apiPolicy)
	p, err := e.st.CurrentPolicy(bg, store.PolicyWorkload)
	if err != nil || p.Version != v || p.CreatedBy != "operator:alice" || string(p.Document) != apiPolicy {
		t.Fatalf("stored %+v, %v", p, err)
	}
	if _, action, meta := e.audit(); action != ActionPolicyApply || meta["kind"] != "workload" || meta["workloads"] != float64(2) {
		t.Fatalf("audit %s %v", action, meta)
	}
}
