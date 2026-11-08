package verifier

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"sync"
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
	path string
	st   *store.Store
	svc  *Service
	now  time.Time
	boot *eventlog.Builder
}

func newSvcEnv(t *testing.T) *svcEnv {
	t.Helper()
	path := filepath.Join(t.TempDir(), "attest.db")
	st, err := store.Open(bg, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e := &svcEnv{t: t, path: path, st: st, now: time.Now(), boot: eventlog.SimulatedBoot("v1")}
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

	// Replaying the same evidence is refused and records nothing: anyone
	// who saw it could replay it indefinitely.
	e.unchanged("replay", func() error {
		_, err := e.svc.Verify(bg, "node-1", c.ID, c.Nonce, ev)
		wantServiceReason(t, err, ReasonChallengeConsumed)
		return err
	})
	e.verifyAudit()
}

func wantServiceReason(t *testing.T, err error, want Reason) {
	t.Helper()
	if got := ReasonOf(err); got != want {
		t.Fatalf("got reason %q (%v), want %q", got, err, want)
	}
}

// Evidence the node's AK signed over the challenge nonce consumes the
// challenge and records a failed verdict with the specific reason. Anything
// else could have come from anyone, so it is refused without writing
// anything and leaves the challenge usable.
func TestServiceRejects(t *testing.T) {
	e := newSvcEnv(t)
	ak := e.node("node-1", false)
	e.node("node-2", false)
	other := verifiertest.NewAK(t)

	cases := []struct {
		name     string
		node     string
		before   func()
		mutate   func(c *Challenge, ev *Evidence) (nonce []byte)
		want     Reason
		recorded bool
		// honest is the outcome of then answering the challenge honestly.
		honest Reason
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
		{name: "junk evidence", want: ReasonMalformed,
			mutate: func(c *Challenge, ev *Evidence) []byte { *ev = Evidence{}; return c.Nonce }},
		{name: "answered by another node", node: "node-2", want: ReasonNonceMismatch},
		{name: "claimed PCR differs from quote", want: ReasonPCRDigest, recorded: true,
			mutate: func(c *Challenge, ev *Evidence) []byte {
				ev.PCRs[7] = bytes.Repeat([]byte{7}, 32)
				return c.Nonce
			}},
		{name: "event log does not replay", want: ReasonEventLogReplay, recorded: true,
			mutate: func(c *Challenge, ev *Evidence) []byte {
				ev.EventLog = eventlog.SimulatedBoot("v2").Bytes()
				return c.Nonce
			}},
		{name: "event log missing", want: ReasonEventLogInvalid, recorded: true,
			mutate: func(c *Challenge, ev *Evidence) []byte { ev.EventLog = nil; return c.Nonce }},
		{name: "measurements not in policy", want: ReasonMeasurement, recorded: true,
			mutate: func(c *Challenge, ev *Evidence) []byte {
				*ev = *evidence(t, ak, c, eventlog.SimulatedBoot("v2"))
				return c.Nonce
			}},
		{name: "policy changed after challenge", want: ReasonMeasurement, recorded: true,
			before: func() { e.apply(false, eventlog.SimulatedBoot("v2")) }},
		{name: "expired", want: ReasonChallengeExpired, honest: ReasonChallengeExpired,
			before: func() { e.now = e.now.Add(DefaultChallengeTTL) }},
		{name: "node revoked after challenge", want: ReasonNodeNotEnrolled, honest: ReasonNodeNotEnrolled,
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
			before := e.dump()
			_, err := e.svc.Verify(bg, node, c.ID, nonce, ev)
			wantServiceReason(t, err, tc.want)

			if tc.recorded {
				a, err := e.st.LatestAttestation(bg, "node-1")
				if err != nil || a.Passed || a.ChallengeID != c.ID || a.Reason != string(tc.want) {
					t.Fatalf("recorded %+v, %v", a, err)
				}
				tc.honest = ReasonChallengeConsumed
			} else if after := e.dump(); after != before {
				t.Fatalf("unauthenticated failure changed the database:\n%s\n---\n%s", before, after)
			}
			_, err = e.svc.Verify(bg, "node-1", c.ID, c.Nonce, evidence(t, ak, c, e.boot))
			wantServiceReason(t, err, tc.honest)
			// Restore the baseline policy for the next case.
			e.apply(false, e.boot)
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

// Challenges are MACs under a per-process key: one cannot be forged,
// extended, moved to another node, or redeemed after a restart, and none of
// those attempts writes anything.
func TestServiceForgedChallengesLeaveNoState(t *testing.T) {
	e := newSvcEnv(t)
	ak := e.node("node-1", false)
	e.node("node-2", false)
	c := e.challenge("node-1")
	ev := evidence(t, ak, c, e.boot)

	var later [8]byte
	binary.BigEndian.PutUint64(later[:], uint64(c.ExpiresAt.Add(time.Hour).UnixNano())) //nolint:gosec // after 1970
	extended := c.ID[:36] + hex.EncodeToString(later[:])
	if !challengeIDRe.MatchString(extended) {
		t.Fatalf("bad test ID %s", extended)
	}
	restarted, err := NewService(ServiceConfig{Store: e.st, Now: func() time.Time { return e.now }})
	if err != nil {
		t.Fatal(err)
	}
	other := e.challenge("node-2")
	for name, verify := range map[string]func() error{
		"invented ID": func() error {
			_, err := e.svc.Verify(bg, "node-1", "att_"+strings.Repeat("0", 32)+c.ID[36:], c.Nonce, ev)
			return err
		},
		"expiry extended": func() error {
			_, err := e.svc.Verify(bg, "node-1", extended, c.Nonce, ev)
			return err
		},
		"another node's challenge": func() error {
			_, err := e.svc.Verify(bg, "node-1", other.ID, other.Nonce, evidence(t, ak, other, e.boot))
			return err
		},
		"after restart": func() error {
			_, err := restarted.Verify(bg, "node-1", c.ID, c.Nonce, ev)
			return err
		},
	} {
		e.unchanged(name, func() error {
			err := verify()
			if ReasonOf(err) != ReasonNonceMismatch {
				t.Errorf("%s: got %v, want %s", name, err, ReasonNonceMismatch)
			}
			return err
		})
	}
	if _, err := e.svc.Verify(bg, "node-1", c.ID, c.Nonce, ev); err != nil {
		t.Fatal(err)
	}
}

// Issuing a challenge writes nothing, however many are asked for.
func TestServiceChallengeWritesNothing(t *testing.T) {
	e := newSvcEnv(t)
	e.node("node-1", false)
	before := e.dump()
	seen := map[string]bool{}
	for range 100 {
		c := e.challenge("node-1")
		if seen[c.ID] || seen[string(c.Nonce)] {
			t.Fatal("challenge repeated")
		}
		seen[c.ID], seen[string(c.Nonce)] = true, true
	}
	if after := e.dump(); after != before {
		t.Fatalf("challenges changed the database:\n%s\n---\n%s", before, after)
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

// Concurrent submissions of the same answer yield exactly one verdict.
func TestServiceConcurrentReplay(t *testing.T) {
	e := newSvcEnv(t)
	ak := e.node("node-1", false)
	c := e.challenge("node-1")
	ev := evidence(t, ak, c, e.boot)

	const n = 8
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			_, err := e.svc.Verify(bg, "node-1", c.ID, c.Nonce, ev)
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	ok := 0
	for err := range errs {
		switch {
		case err == nil:
			ok++
		case ReasonOf(err) != ReasonChallengeConsumed:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d submissions accepted", ok)
	}
	e.verifyAudit()
}
