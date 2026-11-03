package enrollment

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/0xciph3r/attest/internal/store"
	"github.com/0xciph3r/attest/internal/store/storetest"
	"github.com/0xciph3r/attest/internal/verifier"
	"github.com/0xciph3r/attest/internal/verifier/verifiertest"
)

type failingRand struct{ n int }

func (r *failingRand) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, errors.New("entropy source failed")
	}
	k := min(len(p), r.n)
	clear(p[:k])
	r.n -= k
	return k, nil
}

func (e *env) dump() string {
	e.t.Helper()
	return storetest.Dump(e.t, filepath.Join(e.dir, "attest.db"))
}

// unchanged runs fn and fails if it succeeded or changed any table.
func (e *env) unchanged(name string, fn func() error) {
	e.t.Helper()
	before := e.dump()
	if err := fn(); err == nil {
		e.t.Errorf("%s: succeeded", name)
	}
	if after := e.dump(); after != before {
		e.t.Errorf("%s: database changed:\n%s\n---\n%s", name, before, after)
	}
}

func TestRefusedCallsLeaveNoState(t *testing.T) {
	e := newEnv(t)
	cert := ekCert(t, e.prod)
	if _, err := e.svc.Register(ctx, "operator:alice", "node-1", cert); err != nil {
		t.Fatal(err)
	}
	ak := verifiertest.NewAK(t)

	e.unchanged("register without actor", func() error {
		_, err := e.svc.Register(ctx, "", "node-2", ekCert(t, e.prod))
		return err
	})
	e.unchanged("register existing node ID", func() error {
		_, err := e.svc.Register(ctx, "operator:alice", "node-1", ekCert(t, e.prod))
		return err
	})
	e.unchanged("register live EK under another ID", func() error {
		_, err := e.svc.Register(ctx, "operator:alice", "node-2", cert)
		return err
	})
	e.unchanged("register empty certificate", func() error {
		_, err := e.svc.Register(ctx, "operator:alice", "node-2", nil)
		return err
	})
	e.unchanged("register development EK without policy", func() error {
		_, err := e.svc.Register(ctx, "operator:alice", "node-2", ekCert(t, e.dev))
		return err
	})
	for _, n := range []int{0, 1, SecretSize - 1, SecretSize, SecretSize + 15} {
		svc, _ := New(Config{Store: e.st, Roots: e.svc.roots, Now: e.svc.now, Rand: &failingRand{n}})
		e.unchanged("begin with failing RNG", func() error { _, err := svc.Begin(ctx, "node-1", ak.PublicBytes()); return err })
	}
	for _, id := range []string{"", "Node-1", "node-1 ", "../node-1", string(bytes.Repeat([]byte("a"), 65))} {
		e.unchanged("register node ID "+id, func() error {
			_, err := e.svc.Register(ctx, "operator:alice", id, ekCert(t, e.prod))
			return err
		})
		e.unchanged("begin node ID "+id, func() error { _, err := e.svc.Begin(ctx, id, ak.PublicBytes()); return err })
		e.unchanged("complete node ID "+id, func() error {
			return e.svc.Complete(ctx, id, "enr_00000000000000000000000000000000", make([]byte, SecretSize))
		})
		e.unchanged("revoke node ID "+id, func() error { return e.svc.Revoke(ctx, "operator:alice", id) })
	}
	for _, id := range []string{"", "enr_", "enr_" + string(bytes.Repeat([]byte("A"), 32)), "att_00000000000000000000000000000000"} {
		e.unchanged("complete challenge ID "+id, func() error {
			return e.svc.Complete(ctx, "node-1", id, make([]byte, SecretSize))
		})
	}
	e.unchanged("revoke unknown node", func() error { return e.svc.Revoke(ctx, "operator:alice", "ghost") })
	e.unchanged("revoke without actor", func() error { return e.svc.Revoke(ctx, "", "node-1") })

	// node-1 is still registered and can enroll.
	ch, secret := e.begin("node-1", ak)
	if err := e.svc.Complete(ctx, "node-1", ch.ID, secret); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Revoke(ctx, "operator:alice", "node-1"); err != nil {
		t.Fatal(err)
	}
	e.unchanged("revoke twice", func() error { return e.svc.Revoke(ctx, "operator:alice", "node-1") })
}

func TestCompleteRejectsMore(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.Register(ctx, "operator:alice", "node-1", ekCert(t, e.prod)); err != nil {
		t.Fatal(err)
	}
	ak := verifiertest.NewAK(t)
	for name, tc := range map[string]struct {
		secret func(own, other []byte) []byte
		want   verifier.Reason
	}{
		"secret of another challenge": {func(_, other []byte) []byte { return other }, verifier.ReasonActivationFailed},
		"secret with extra byte":      {func(own, _ []byte) []byte { return append(bytes.Clone(own), 0) }, verifier.ReasonActivationFailed},
		"secret prefix":               {func(own, _ []byte) []byte { return own[:SecretSize-1] }, verifier.ReasonActivationFailed},
		"secret hash":                 {func(own, _ []byte) []byte { return sum(own) }, verifier.ReasonActivationFailed},
		"empty secret":                {func(_, _ []byte) []byte { return nil }, verifier.ReasonActivationFailed},
		"all-zero secret":             {func(_, _ []byte) []byte { return make([]byte, SecretSize) }, verifier.ReasonActivationFailed},
	} {
		t.Run(name, func(t *testing.T) {
			ch, own := e.begin("node-1", ak)
			_, other := e.begin("node-1", ak)
			wantReason(t, e.svc.Complete(ctx, "node-1", ch.ID, tc.secret(own, other)), tc.want)
			// The challenge is burned even for the right secret.
			wantReason(t, e.svc.Complete(ctx, "node-1", ch.ID, own), verifier.ReasonChallengeConsumed)
			if n, _ := e.st.Node(ctx, "node-1"); n.State != store.NodeRegistered {
				t.Fatalf("node %s after failed completion", n.State)
			}
		})
	}
}

// Of two outstanding challenges, only the first completion enrolls; the
// other then fails without changing the enrolled AK.
func TestSecondChallengeCannotReplaceAK(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.Register(ctx, "operator:alice", "node-1", ekCert(t, e.prod)); err != nil {
		t.Fatal(err)
	}
	ak1, ak2 := verifiertest.NewAK(t), verifiertest.NewAK(t)
	ch1, s1 := e.begin("node-1", ak1)
	ch2, s2 := e.begin("node-1", ak2)
	if err := e.svc.Complete(ctx, "node-1", ch1.ID, s1); err != nil {
		t.Fatal(err)
	}
	wantReason(t, e.svc.Complete(ctx, "node-1", ch2.ID, s2), verifier.ReasonNodeState)
	n, _ := e.st.Node(ctx, "node-1")
	if !bytes.Equal(n.AKName, ak1.Name) {
		t.Fatal("second challenge replaced the enrolled AK")
	}
}

func TestConcurrentCompletion(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.Register(ctx, "operator:alice", "node-1", ekCert(t, e.prod)); err != nil {
		t.Fatal(err)
	}
	ch, secret := e.begin("node-1", verifiertest.NewAK(t))
	const n = 8
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() { errs <- e.svc.Complete(ctx, "node-1", ch.ID, secret) })
	}
	wg.Wait()
	close(errs)
	ok := 0
	for err := range errs {
		switch {
		case err == nil:
			ok++
		case verifier.ReasonOf(err) != verifier.ReasonChallengeConsumed:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d completions succeeded", ok)
	}
}

// A revoked machine may be registered again under a new ID, but only through
// a fresh operator registration and enrollment; its old ID stays revoked.
func TestReRegisterAfterRevoke(t *testing.T) {
	e := newEnv(t)
	cert := ekCert(t, e.prod)
	if _, err := e.svc.Register(ctx, "operator:alice", "node-1", cert); err != nil {
		t.Fatal(err)
	}
	ak := verifiertest.NewAK(t)
	ch, s := e.begin("node-1", ak)
	if err := e.svc.Complete(ctx, "node-1", ch.ID, s); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Revoke(ctx, "operator:alice", "node-1"); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.Begin(ctx, "node-1", ak.PublicBytes())
	wantReason(t, err, verifier.ReasonNodeState)
	if _, err := e.svc.Register(ctx, "operator:alice", "node-1", cert); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("revoked ID reused: %v", err)
	}
	if _, err := e.svc.Register(ctx, "operator:alice", "node-1b", cert); err != nil {
		t.Fatalf("re-register revoked EK: %v", err)
	}
	// The revoked AK may be enrolled again for the new record, since the
	// old record can no longer attest.
	ch, s = e.begin("node-1b", ak)
	if err := e.svc.Complete(ctx, "node-1b", ch.ID, s); err != nil {
		t.Fatal(err)
	}
}

// A challenge answered exactly at its expiry is refused.
func TestCompleteTTLBoundary(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.Register(ctx, "operator:alice", "node-1", ekCert(t, e.prod)); err != nil {
		t.Fatal(err)
	}
	ak := verifiertest.NewAK(t)
	start := e.now
	ch, s := e.begin("node-1", ak)
	e.now = ch.ExpiresAt
	wantReason(t, e.svc.Complete(ctx, "node-1", ch.ID, s), verifier.ReasonChallengeExpired)
	e.now = start
	ch, s = e.begin("node-1", ak)
	e.now = ch.ExpiresAt.Add(-time.Nanosecond)
	if err := e.svc.Complete(ctx, "node-1", ch.ID, s); err != nil {
		t.Fatalf("just before expiry: %v", err)
	}
}

func sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

func TestRevokeValidatesNodeID(t *testing.T) {
	e := newEnv(t)
	for _, id := range []string{"", "Node-1", "../node-1", "node-1\x00"} {
		if err := e.svc.Revoke(ctx, "operator:alice", id); !errors.Is(err, ErrInvalidNodeID) {
			t.Errorf("Revoke(%q) = %v, want ErrInvalidNodeID", id, err)
		}
	}
}
