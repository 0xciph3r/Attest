package verifier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/0xciph3r/attest/internal/policy"
	"github.com/0xciph3r/attest/internal/store"
	"github.com/0xciph3r/attest/internal/store/storetest"
	"github.com/0xciph3r/attest/internal/verifier/verifiertest"
)

// failAfter yields n bytes and then fails.
type failAfter struct{ n int }

func (r *failAfter) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, errors.New("entropy source failed")
	}
	k := min(len(p), r.n)
	clear(p[:k])
	r.n -= k
	return k, nil
}

func (e *svcEnv) dump() string { e.t.Helper(); return storetest.Dump(e.t, e.path) }

// unchanged runs fn and fails if it succeeded or changed any table.
func (e *svcEnv) unchanged(name string, fn func() error) {
	e.t.Helper()
	before := e.dump()
	if err := fn(); err == nil {
		e.t.Errorf("%s: succeeded", name)
	}
	if after := e.dump(); after != before {
		e.t.Errorf("%s: database changed:\n%s\n---\n%s", name, before, after)
	}
}

func TestServiceFailuresLeaveNoState(t *testing.T) {
	e := newSvcEnv(t)
	ak := e.node("node-1", false)
	c := e.challenge("node-1")
	ev := evidence(t, ak, c, e.boot)

	for _, n := range []int{0, NonceSize, NonceSize + 8} {
		svc, _ := NewService(ServiceConfig{Store: e.st, Now: func() time.Time { return e.now }, Rand: &failAfter{n}})
		e.unchanged("challenge with failing RNG", func() error { _, err := svc.Challenge(bg, "node-1"); return err })
	}
	canceled, cancel := context.WithCancel(bg)
	cancel()
	e.unchanged("challenge with canceled context", func() error { _, err := e.svc.Challenge(canceled, "node-1"); return err })
	e.unchanged("verify with canceled context", func() error { _, err := e.svc.Verify(canceled, "node-1", c.ID, c.Nonce, ev); return err })
	e.unchanged("policy with canceled context", func() error {
		_, err := e.svc.ApplyPolicy(canceled, "operator:alice", verifiertest.PolicyJSON(t, false, e.boot))
		return err
	})
	e.unchanged("policy without actor", func() error {
		_, err := e.svc.ApplyPolicy(bg, "", verifiertest.PolicyJSON(t, false, e.boot))
		return err
	})
	e.unchanged("invalid policy", func() error { _, err := e.svc.ApplyPolicy(bg, "operator:alice", []byte(`{}`)); return err })
	e.unchanged("nil evidence", func() error { _, err := e.svc.Verify(bg, "node-1", c.ID, c.Nonce, nil); return err })
	for _, id := range []string{"", "att_", "att_" + string(bytes.Repeat([]byte("A"), 32)), c.ID + "0", " " + c.ID} {
		e.unchanged("challenge ID "+id, func() error { _, err := e.svc.Verify(bg, "node-1", id, c.Nonce, ev); return err })
	}
	for _, id := range []string{"", "Node-1", "node/1", "node-1\n", string(bytes.Repeat([]byte("a"), 65))} {
		e.unchanged("node ID "+id, func() error { _, err := e.svc.Challenge(bg, id); return err })
		e.unchanged("verify node ID "+id, func() error { _, err := e.svc.Verify(bg, id, c.ID, c.Nonce, ev); return err })
	}

	// The challenge survived every refused attempt.
	if _, err := e.svc.Verify(bg, "node-1", c.ID, c.Nonce, ev); err != nil {
		t.Fatal(err)
	}
	e.verifyAudit()
}

func TestServiceRejectsMore(t *testing.T) {
	e := newSvcEnv(t)
	ak := e.node("node-1", false)
	for name, tc := range map[string]struct {
		nonce  func(c *Challenge) []byte
		before func()
		want   Reason
	}{
		"short nonce": {nonce: func(c *Challenge) []byte { return c.Nonce[:NonceSize-1] }, want: ReasonNonceMismatch},
		"long nonce":  {nonce: func(c *Challenge) []byte { return append(bytes.Clone(c.Nonce), 0) }, want: ReasonNonceMismatch},
		"nil nonce":   {nonce: func(*Challenge) []byte { return nil }, want: ReasonNonceMismatch},
		"nonce hash":  {nonce: func(c *Challenge) []byte { h := sha256.Sum256(c.Nonce); return h[:] }, want: ReasonNonceMismatch},
		"selection changed after challenge": {before: func() {
			e.applyPCRs(t, []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8})
		}, want: ReasonPCRSelection},
	} {
		t.Run(name, func(t *testing.T) {
			c := e.challenge("node-1")
			nonce := c.Nonce
			if tc.nonce != nil {
				nonce = tc.nonce(c)
			}
			if tc.before != nil {
				tc.before()
			}
			_, err := e.svc.Verify(bg, "node-1", c.ID, nonce, evidence(t, ak, c, e.boot))
			if got := ReasonOf(err); got != tc.want {
				t.Fatalf("got %q (%v), want %q", got, err, tc.want)
			}
			// Restore the baseline policy for the next case.
			e.apply(false, e.boot)
		})
	}
	e.verifyAudit()
}

func TestServiceChallengeTTLBoundary(t *testing.T) {
	e := newSvcEnv(t)
	ak := e.node("node-1", false)
	c := e.challenge("node-1")
	start := e.now
	e.now = c.ExpiresAt.Add(-time.Nanosecond)
	if _, err := e.svc.Verify(bg, "node-1", c.ID, c.Nonce, evidence(t, ak, c, e.boot)); err != nil {
		t.Fatalf("answer just before expiry: %v", err)
	}
	e.now = start
	c = e.challenge("node-1")
	e.now = c.ExpiresAt
	_, err := e.svc.Verify(bg, "node-1", c.ID, c.Nonce, evidence(t, ak, c, e.boot))
	wantServiceReason(t, err, ReasonChallengeExpired)
}

func TestServiceRevokedNodeCannotChallenge(t *testing.T) {
	e := newSvcEnv(t)
	e.node("node-1", false)
	if err := e.st.Update(bg, func(tx *store.Tx) error { return tx.RevokeNode("node-1", e.now) }); err != nil {
		t.Fatal(err)
	}
	e.unchanged("challenge for revoked node", func() error { _, err := e.svc.Challenge(bg, "node-1"); return err })
}

// applyPCRs applies a policy admitting e.boot over a different selection.
func (e *svcEnv) applyPCRs(t *testing.T, pcrs []uint32) {
	t.Helper()
	ref := policy.Reference{Name: "boot", PCRs: map[string]string{}}
	for p, v := range e.boot.PCRs(pcrs...) {
		ref.PCRs[strconv.Itoa(int(p))] = hex.EncodeToString(v)
	}
	doc, err := json.Marshal(policy.Measurement{Schema: policy.SchemaMeasurementV1, PCRs: pcrs, References: []policy.Reference{ref}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ApplyPolicy(bg, "operator:alice", doc); err != nil {
		t.Fatal(err)
	}
}
