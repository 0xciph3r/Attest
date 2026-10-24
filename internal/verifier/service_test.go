package verifier

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xciph3r/attest/internal/audit"
	"github.com/0xciph3r/attest/internal/eventlog"
	"github.com/0xciph3r/attest/internal/store"
	"github.com/0xciph3r/attest/internal/verifier/verifiertest"
)

var bg = context.Background()

type svcEnv struct {
	t    *testing.T
	st   *store.Store
	svc  *Service
	now  time.Time
	boot *eventlog.Builder
}

func newSvcEnv(t *testing.T) *svcEnv {
	t.Helper()
	st, err := store.Open(bg, filepath.Join(t.TempDir(), "attest.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e := &svcEnv{t: t, st: st, now: time.Now(), boot: eventlog.SimulatedBoot("v1")}
	if e.svc, err = NewService(ServiceConfig{Store: st, Now: func() time.Time { return e.now }}); err != nil {
		t.Fatal(err)
	}
	e.apply(false, e.boot)
	return e
}

func (e *svcEnv) apply(allowDev bool, boots ...*eventlog.Builder) {
	e.t.Helper()
	if _, err := e.svc.ApplyPolicy(bg, "operator:alice", verifiertest.PolicyJSON(e.t, allowDev, boots...)); err != nil {
		e.t.Fatal(err)
	}
}

// node inserts an enrolled node directly; enrollment has its own tests.
func (e *svcEnv) node(id string, development bool) *verifiertest.AK {
	e.t.Helper()
	ak := verifiertest.NewAK(e.t)
	err := e.st.Update(bg, func(tx *store.Tx) error {
		ek := []byte("ek-" + id)
		if err := tx.InsertNode(&store.Node{ID: id, EKType: "eccp256", EKCert: ek, EKPublic: ek,
			EKDigest: bytes.Repeat([]byte(id[len(id)-1:]), 32), EKDevelopment: development,
			RegisteredBy: "operator:alice", RegisteredAt: e.now}); err != nil {
			return err
		}
		return tx.EnrollNode(id, ak.PublicBytes(), ak.Name, e.now)
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return ak
}

func (e *svcEnv) challenge(nodeID string) *Challenge {
	e.t.Helper()
	c, err := e.svc.Challenge(bg, nodeID)
	if err != nil {
		e.t.Fatalf("Challenge: %v", err)
	}
	return c
}

// evidence is what an honest node booted with boot would submit.
func evidence(t *testing.T, ak *verifiertest.AK, c *Challenge, boot *eventlog.Builder) *Evidence {
	t.Helper()
	pcrs := boot.PCRs(c.PCRs...)
	attest, sig := ak.Quote(t, c.Nonce, pcrs)
	return &Evidence{Attest: attest, Signature: sig, PCRs: pcrs, EventLog: boot.Bytes()}
}

func (e *svcEnv) verifyAudit() {
	e.t.Helper()
	if _, err := audit.Verify(e.st.AuditEntries(bg), audit.VerifyOptions{AllowUnanchored: true}); err != nil {
		e.t.Fatalf("audit chain: %v", err)
	}
}

func TestServiceAttest(t *testing.T) {
	e := newSvcEnv(t)
	ak := e.node("node-1", false)
	c := e.challenge("node-1")
	if len(c.Nonce) != NonceSize || len(c.PCRs) != 8 {
		t.Fatalf("challenge %+v", c)
	}
	ev := evidence(t, ak, c, e.boot)
	v, err := e.svc.Verify(bg, "node-1", c.ID, c.Nonce, ev)
	if err != nil {
		t.Fatal(err)
	}
	if v.NodeID != "node-1" || v.PolicyVersion != 1 || v.Reference != "boot0" || v.Development {
		t.Fatalf("verdict %+v", v)
	}
	a, err := e.st.LatestAttestation(bg, "node-1")
	if err != nil || !a.Passed || a.ID != v.AttestationID || a.AuditSeq != v.AuditSeq || a.ResetCount != 2 {
		t.Fatalf("recorded %+v, %v", a, err)
	}

	// Replaying the same evidence is refused, audited, and does not add a
	// second verdict for the challenge.
	_, err = e.svc.Verify(bg, "node-1", c.ID, c.Nonce, ev)
	wantServiceReason(t, err, ReasonChallengeConsumed)
	if a2, _ := e.st.LatestAttestation(bg, "node-1"); a2.ID != a.ID {
		t.Fatal("replay recorded a verdict")
	}
	head, _ := e.st.AuditHead(bg)
	if head.Sequence != 3 { // policy.apply, node.attest, node.attest.denied
		t.Fatalf("audit head %d", head.Sequence)
	}
	e.verifyAudit()
}

func wantServiceReason(t *testing.T, err error, want Reason) {
	t.Helper()
	if got := ReasonOf(err); got != want {
		t.Fatalf("got reason %q (%v), want %q", got, err, want)
	}
}

// Every failed attempt against a live challenge consumes it and records a
// failed verdict with the specific reason.
func TestServiceRejects(t *testing.T) {
	e := newSvcEnv(t)
	ak := e.node("node-1", false)
	e.node("node-2", false)
	other := verifiertest.NewAK(t)

	cases := []struct {
		name   string
		node   string
		before func()
		mutate func(c *Challenge, ev *Evidence) (nonce []byte)
		want   Reason
	}{
		{name: "wrong nonce echoed", want: ReasonNonceMismatch,
			mutate: func(c *Challenge, ev *Evidence) []byte { return bytes.Repeat([]byte{1}, NonceSize) }},
		{name: "quote over another nonce", want: ReasonNonceMismatch,
			mutate: func(c *Challenge, ev *Evidence) []byte {
				ev.Attest, ev.Signature = ak.Quote(t, bytes.Repeat([]byte{1}, NonceSize), ev.PCRs)
				return c.Nonce
			}},
		{name: "signed by an unenrolled key", want: ReasonBadSignature,
			mutate: func(c *Challenge, ev *Evidence) []byte {
				ev.Signature = other.Sign(t, ev.Attest)
				return c.Nonce
			}},
		{name: "claimed PCR differs from quote", want: ReasonPCRDigest,
			mutate: func(c *Challenge, ev *Evidence) []byte {
				ev.PCRs[7] = bytes.Repeat([]byte{7}, 32)
				return c.Nonce
			}},
		{name: "event log does not replay", want: ReasonEventLogReplay,
			mutate: func(c *Challenge, ev *Evidence) []byte {
				ev.EventLog = eventlog.SimulatedBoot("v2").Bytes()
				return c.Nonce
			}},
		{name: "event log missing", want: ReasonEventLogInvalid,
			mutate: func(c *Challenge, ev *Evidence) []byte { ev.EventLog = nil; return c.Nonce }},
		{name: "measurements not in policy", want: ReasonMeasurement,
			mutate: func(c *Challenge, ev *Evidence) []byte {
				*ev = *evidence(t, ak, c, eventlog.SimulatedBoot("v2"))
				return c.Nonce
			}},
		{name: "expired", want: ReasonChallengeExpired,
			before: func() { e.now = e.now.Add(DefaultChallengeTTL) }},
		{name: "answered by another node", node: "node-2", want: ReasonChallengeWrongNode},
		{name: "policy changed after challenge", want: ReasonMeasurement,
			before: func() { e.apply(false, eventlog.SimulatedBoot("v2")) }},
		{name: "node revoked after challenge", want: ReasonNodeNotEnrolled,
			before: func() {
				if err := e.st.Update(bg, func(tx *store.Tx) error { return tx.RevokeNode("node-1", e.now) }); err != nil {
					t.Fatal(err)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			saved := e.now
			defer func() { e.now = saved }()
			c := e.challenge("node-1")
			ev := evidence(t, ak, c, e.boot)
			nonce := c.Nonce
			if tc.mutate != nil {
				nonce = tc.mutate(c, ev)
			}
			if tc.before != nil {
				tc.before()
			}
			node := "node-1"
			if tc.node != "" {
				node = tc.node
			}
			_, err := e.svc.Verify(bg, node, c.ID, nonce, ev)
			wantServiceReason(t, err, tc.want)

			a, err := e.st.LatestAttestation(bg, "node-1")
			if err != nil || a.Passed || a.ChallengeID != c.ID || a.Reason != string(tc.want) {
				t.Fatalf("recorded %+v, %v", a, err)
			}
			// The honest answer can no longer be used.
			_, err = e.svc.Verify(bg, "node-1", c.ID, c.Nonce, evidence(t, ak, c, e.boot))
			wantServiceReason(t, err, ReasonChallengeConsumed)
		})
	}
	e.verifyAudit()
}

func TestServiceDevelopmentRoot(t *testing.T) {
	e := newSvcEnv(t)
	ak := e.node("dev-1", true)
	c := e.challenge("dev-1")
	_, err := e.svc.Verify(bg, "dev-1", c.ID, c.Nonce, evidence(t, ak, c, e.boot))
	wantServiceReason(t, err, ReasonDevelopmentRoot)

	e.apply(true, e.boot)
	c = e.challenge("dev-1")
	v, err := e.svc.Verify(bg, "dev-1", c.ID, c.Nonce, evidence(t, ak, c, e.boot))
	if err != nil || !v.Development || v.PolicyVersion != 2 {
		t.Fatalf("verdict %+v, %v", v, err)
	}
}

func TestServiceChallengeRejects(t *testing.T) {
	e := newSvcEnv(t)
	_, err := e.svc.Challenge(bg, "ghost")
	wantServiceReason(t, err, ReasonNodeUnknown)
	if _, err := e.svc.Challenge(bg, "../x"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal(err)
	}
	if err := e.st.Update(bg, func(tx *store.Tx) error {
		return tx.InsertNode(&store.Node{ID: "pending", EKType: "eccp256", EKCert: []byte{1}, EKPublic: []byte{1},
			EKDigest: bytes.Repeat([]byte{1}, 32), RegisteredBy: "op", RegisteredAt: e.now})
	}); err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.Challenge(bg, "pending")
	wantServiceReason(t, err, ReasonNodeNotEnrolled)

	// Without a policy nothing can attest.
	st, err := store.Open(bg, filepath.Join(t.TempDir(), "empty.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	svc, _ := NewService(ServiceConfig{Store: st})
	if err := st.Update(bg, func(tx *store.Tx) error {
		if err := tx.InsertNode(&store.Node{ID: "n1", EKType: "eccp256", EKCert: []byte{1}, EKPublic: []byte{1},
			EKDigest: bytes.Repeat([]byte{1}, 32), RegisteredBy: "op", RegisteredAt: e.now}); err != nil {
			return err
		}
		return tx.EnrollNode("n1", verifiertest.NewAK(t).PublicBytes(), bytes.Repeat([]byte{2}, 34), e.now)
	}); err != nil {
		t.Fatal(err)
	}
	_, err = svc.Challenge(bg, "n1")
	wantServiceReason(t, err, ReasonPolicyMissing)
}

func TestServiceUnknownChallengeAuditedOnly(t *testing.T) {
	e := newSvcEnv(t)
	ak := e.node("node-1", false)
	c := e.challenge("node-1")
	ev := evidence(t, ak, c, e.boot)
	_, err := e.svc.Verify(bg, "node-1", "att_00000000000000000000000000000000", c.Nonce, ev)
	wantServiceReason(t, err, ReasonChallengeUnknown)
	if _, err := e.st.LatestAttestation(bg, "node-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("verdict recorded for unknown challenge: %v", err)
	}
	if h, _ := e.st.AuditHead(bg); h.Sequence != 2 {
		t.Fatalf("denial not audited: head %d", h.Sequence)
	}
	// The real challenge is untouched.
	if _, err := e.svc.Verify(bg, "node-1", c.ID, c.Nonce, ev); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Verify(bg, "node-1", "bogus", c.Nonce, ev); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal(err)
	}
}

func TestApplyPolicy(t *testing.T) {
	e := newSvcEnv(t)
	if _, err := e.svc.ApplyPolicy(bg, "operator:alice", []byte(`{"schema":"nope"}`)); err == nil {
		t.Fatal("invalid policy applied")
	}
	e.apply(false, e.boot, eventlog.SimulatedBoot("v2"))
	p, err := e.st.CurrentPolicy(bg, store.PolicyMeasurement)
	if err != nil || p.Version != 2 || p.CreatedBy != "operator:alice" {
		t.Fatalf("got %+v, %v", p, err)
	}
	if h, _ := e.st.AuditHead(bg); h.Sequence != 2 {
		t.Fatalf("policy changes not audited: head %d", h.Sequence)
	}
}
