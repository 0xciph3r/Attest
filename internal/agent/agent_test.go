package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	attestv1 "github.com/0xciph3r/attest/api/gen/attest/v1"
	"github.com/0xciph3r/attest/internal/eventlog"
	"github.com/0xciph3r/attest/internal/identity"
	"github.com/0xciph3r/attest/internal/verifier/verifiertest"
)

func TestNewRejectsConfig(t *testing.T) {
	e := newEnv(t)
	for name, mod := range map[string]func(*Config){
		"node id":      func(c *Config) { c.NodeID = "" },
		"bad node id":  func(c *Config) { c.NodeID = "../n1" },
		"trust domain": func(c *Config) { c.TrustDomain = "Attest Local" },
		"no bundle":    func(c *Config) { c.Bundle = nil },
		"no addr":      func(c *Config) { c.Addr = "" },
		"no tpm":       func(c *Config) { c.TPM = nil },
	} {
		cfg := e.config()
		mod(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New accepted invalid config", name)
		}
	}
}

func TestAttestObtainsNodeIdentity(t *testing.T) {
	e := newEnv(t)
	a := e.attested()
	nc := a.acquire()
	if nc == nil {
		t.Fatal("no node identity after attestation")
	}
	defer a.release(nc)
	id, err := identity.Verify(e.ca.Bundle(), td, nc.cert, e.clk.Now(), x509.ExtKeyUsageClientAuth)
	if err != nil || id.String() != "spiffe://attest.local/node/n1" {
		t.Fatalf("node identity %v, %v", id, err)
	}
	if !samePublicKey(nc.cert.PublicKey, e.tpm.key.Key.Public()) {
		t.Fatal("node identity does not certify the TPM node key")
	}
}

func TestAttestFailureKeepsIdentity(t *testing.T) {
	e := newEnv(t)
	a := e.attested()
	before := a.current()

	e.tpm.set(eventlog.SimulatedBoot("tampered"), nil)
	if err := a.Attest(bg); err == nil {
		t.Fatal("attestation with unexpected measurements succeeded")
	}
	e.tpm.set(e.tpm.boot, errors.New("tpm unplugged"))
	if err := a.Attest(bg); err == nil || !strings.Contains(err.Error(), "tpm unplugged") {
		t.Fatalf("Attest with failing TPM = %v", err)
	}
	if a.current() != before || before.retired {
		t.Fatal("failed attestation replaced or retired the node identity")
	}
}

func TestAttestRefusals(t *testing.T) {
	e := newEnv(t)
	other, err := identity.Init(t.TempDir(), identity.Options{TrustDomain: td, Now: e.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*Config){
		// A control plane the bootstrap bundle does not vouch for.
		"untrusted server": func(c *Config) { c.Bundle = other.Bundle() },
		"wrong domain":     func(c *Config) { c.TrustDomain = "other.local" },
		"unenrolled node":  func(c *Config) { c.NodeID = "n2" },
		// Evidence signed by an AK that was never enrolled.
		"unknown ak": func(c *Config) {
			c.TPM = &fakeTPM{t: t, ak: verifiertest.NewAK(t), key: e.tpm.key, boot: e.tpm.boot}
		},
	} {
		a := e.agent(mod)
		if err := a.Attest(bg); err == nil {
			t.Errorf("%s: attestation succeeded", name)
		}
		if a.current() != nil {
			t.Errorf("%s: agent holds a node identity", name)
		}
	}
}

// issue signs a certificate for id and key with ca.
func issue(t testing.TB, ca *identity.CA, id identity.ID, key any) []byte {
	t.Helper()
	iss, err := ca.Issue(identity.IssueRequest{ID: id, PublicKey: key, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return iss.Cert.Raw
}

func raw(certs []*x509.Certificate) [][]byte {
	var out [][]byte
	for _, c := range certs {
		out = append(out, c.Raw)
	}
	return out
}

func TestCheckNodeIdentityRejects(t *testing.T) {
	e := newEnv(t)
	a := e.agent()
	other, err := identity.Init(t.TempDir(), identity.Options{TrustDomain: td, Now: e.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	n1, _ := identity.NodeID(td, "n1")
	n2, _ := identity.NodeID(td, "n2")
	wl, _ := identity.WorkloadID(td, "api")
	tpmKey := e.tpm.key.Key.Public()
	good := issue(t, e.ca, n1, tpmKey)
	bundle := raw(e.ca.Bundle())
	if _, _, err := a.checkNodeIdentity(&attestv1.X509Identity{Certificate: good, Bundle: bundle}); err != nil {
		t.Fatalf("valid node identity refused: %v", err)
	}
	for name, id := range map[string]*attestv1.X509Identity{
		"missing":       nil,
		"empty":         {},
		"garbage cert":  {Certificate: []byte("cert"), Bundle: bundle},
		"no bundle":     {Certificate: good},
		"garbage ca":    {Certificate: good, Bundle: [][]byte{[]byte("ca")}},
		"other node":    {Certificate: issue(t, e.ca, n2, tpmKey), Bundle: bundle},
		"workload cert": {Certificate: issue(t, e.ca, wl, tpmKey), Bundle: bundle},
		"other key":     {Certificate: issue(t, e.ca, n1, p256(t).Public()), Bundle: bundle},
		"other ca":      {Certificate: issue(t, other, n1, tpmKey), Bundle: bundle},
		"wrong bundle":  {Certificate: good, Bundle: raw(other.Bundle())},
		"foreign root":  {Certificate: issue(t, other, n1, tpmKey), Bundle: raw(other.Bundle())},
	} {
		if _, _, err := a.checkNodeIdentity(id); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A rotated CA arrives in a bundle that still holds the current one.
	rotated := append(raw(other.Bundle()), bundle...)
	if _, _, err := a.checkNodeIdentity(&attestv1.X509Identity{Certificate: issue(t, other, n1, tpmKey), Bundle: rotated}); err != nil {
		t.Errorf("identity from a rotated CA refused: %v", err)
	}
	e.clk.Add(2 * time.Hour)
	if _, _, err := a.checkNodeIdentity(&attestv1.X509Identity{Certificate: good, Bundle: bundle}); err == nil {
		t.Error("expired node identity accepted")
	}
}

func TestReattestRetiresOldConnection(t *testing.T) {
	e := newEnv(t)
	a := e.attested()
	old := a.acquire()
	if err := a.Attest(bg); err != nil {
		t.Fatal(err)
	}
	if a.current() == old || !old.retired {
		t.Fatal("re-attestation did not replace the node identity")
	}
	// In use: the old connection stays open until released.
	if _, err := old.client.GetChallenge(bg, &attestv1.GetChallengeRequest{NodeId: "n1"}); err != nil {
		t.Fatalf("retired connection closed while in use: %v", err)
	}
	a.release(old)
	if _, err := old.client.GetChallenge(bg, &attestv1.GetChallengeRequest{NodeId: "n1"}); status.Code(err) != codes.Canceled {
		t.Fatalf("retired connection still usable after release: %v", err)
	}
}

func TestExpiredNodeIdentityDropped(t *testing.T) {
	e := newEnv(t)
	a := e.attested()
	old := a.current()
	e.clk.Add(time.Hour)
	if a.acquire() != nil {
		t.Fatal("expired node identity used")
	}
	if a.current() != nil || !old.retired {
		t.Fatal("expired node identity kept")
	}
}

func TestEnroll(t *testing.T) {
	e := newEnv(t)
	if _, err := e.enr.Register(bg, "operator:alice", "n2", e.ekCA.IssueEKCert(t, p256(t).Public())); err != nil {
		t.Fatal(err)
	}
	ak := verifiertest.NewAK(t)
	enrolled := func() bool {
		n, err := e.st.Node(bg, "n2")
		if err != nil {
			t.Fatal(err)
		}
		return len(n.AKPublic) != 0
	}

	// Without the EK the secret cannot be recovered; nothing is sent.
	var got []byte
	tpm := &fakeTPM{t: t, ak: ak, key: e.tpm.key, boot: e.tpm.boot}
	a := e.agent(func(c *Config) { c.NodeID, c.TPM = "n2", tpm })
	if err := a.Enroll(bg); err == nil || !strings.Contains(err.Error(), "activate") {
		t.Fatalf("Enroll with failing TPM = %v", err)
	}
	// A wrong secret is refused.
	tpm.activate = func(blob, secret []byte) ([]byte, error) {
		got = blob
		return make([]byte, 32), nil
	}
	if err := a.Enroll(bg); err == nil || !strings.Contains(err.Error(), "complete") {
		t.Fatalf("Enroll with wrong secret = %v", err)
	}
	if len(got) == 0 || enrolled() {
		t.Fatal("wrong secret enrolled the node, or no credential was issued")
	}
	// Unregistered nodes are refused before the TPM is involved.
	tpm.activate = func([]byte, []byte) ([]byte, error) { t.Fatal("TPM used for unregistered node"); return nil, nil }
	b := e.agent(func(c *Config) { c.NodeID, c.TPM = "n3", tpm })
	if err := b.Enroll(bg); err == nil || !strings.Contains(err.Error(), "begin") {
		t.Fatalf("Enroll of unregistered node = %v", err)
	}
}

func TestBackoff(t *testing.T) {
	for n := 1; n < 100; n++ {
		want := time.Minute
		if n <= 6 {
			want = time.Second << (n - 1)
		}
		for range 50 {
			if d := backoff(n, time.Second, time.Minute); d < want/2 || d > want {
				t.Fatalf("backoff(%d) = %v, want in [%v, %v]", n, d, want/2, want)
			}
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRunRetriesAndStops(t *testing.T) {
	e := newEnv(t)
	e.tpm.set(e.tpm.boot, errors.New("tpm busy"))
	a := e.agent()
	a.backoffMin, a.kickMin = 10*time.Millisecond, 100*time.Millisecond
	kickMin := a.kickMin
	ctx, cancel := context.WithCancel(bg)
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	waitFor(t, "retries", func() bool { return e.tpm.quoteCount() >= 3 })
	if a.current() != nil {
		t.Fatal("identity without successful attestation")
	}
	e.tpm.set(e.tpm.boot, nil)
	waitFor(t, "node identity", func() bool { return a.current() != nil })
	held := a.current()

	// Renewal is at half-life, so no further attestation happens unprompted.
	n := e.tpm.quoteCount()
	time.Sleep(100 * time.Millisecond)
	if e.tpm.quoteCount() != n {
		t.Fatal("re-attested before half-life")
	}
	// Requests are honored but coalesce, and attestations they cause are
	// spaced by kickMin.
	for range 3 * kickMin / (5 * time.Millisecond) {
		a.requestAttestation()
		time.Sleep(5 * time.Millisecond)
	}
	if a.current() == held {
		t.Fatal("requested re-attestation did not happen")
	}
	times := e.tpm.quoteTimes()[n:]
	if len(times) < 2 || len(times) > 4 {
		t.Fatalf("%d attestations during 3 kickMin of requests", len(times))
	}
	for i := 1; i < len(times); i++ {
		// Quote times trail attempt starts by a challenge round trip.
		if gap := times[i].Sub(times[i-1]); gap < kickMin*3/4 {
			t.Fatalf("attestations %v apart, want >= %v", gap, kickMin)
		}
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v", err)
	}
	done <- context.Canceled
	if a.current() != nil {
		t.Fatal("node identity kept after Run returned")
	}
}

func TestRenewIn(t *testing.T) {
	e := newEnv(t)
	a := e.agent()
	if d := a.renewIn(); d != a.backoffMin {
		t.Fatalf("renewIn without identity = %v", d)
	}
	if err := a.Attest(bg); err != nil {
		t.Fatal(err)
	}
	c := a.current().cert
	half := c.NotAfter.Sub(c.NotBefore) / 2
	if d := a.renewIn(); d > half || d < half-time.Minute {
		t.Fatalf("renewIn = %v, want about %v", d, half)
	}
	e.clk.Add(2 * half)
	if d := a.renewIn(); d != a.backoffMin {
		t.Fatalf("renewIn past half-life = %v", d)
	}
}
