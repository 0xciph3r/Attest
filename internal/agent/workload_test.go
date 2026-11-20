package agent

import (
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	attestv1 "github.com/0xciph3r/attest/api/gen/attest/v1"
	"github.com/0xciph3r/attest/internal/api"
	"github.com/0xciph3r/attest/internal/identity"
)

func TestFetchX509Identity(t *testing.T) {
	e := newEnv(t)
	c := serve(t, e.attested(), as(apiCaller))
	key := p256(t)
	id, err := fetch(c, csrFor(t, key))
	if err != nil {
		t.Fatal(err)
	}
	if id.GetSpiffeId() != "spiffe://attest.local/workload/api" {
		t.Fatalf("spiffe_id = %q", id.GetSpiffeId())
	}
	leaf, err := x509.ParseCertificate(id.GetCertificate())
	if err != nil {
		t.Fatal(err)
	}
	if got, err := identity.Verify(e.ca.Bundle(), td, leaf, e.clk.Now(), x509.ExtKeyUsageClientAuth); err != nil || got.String() != id.GetSpiffeId() {
		t.Fatalf("issued identity %v does not verify: %v", got, err)
	}
	if !samePublicKey(leaf.PublicKey, key.Public()) || !id.GetNotAfter().AsTime().Equal(leaf.NotAfter) {
		t.Fatal("identity does not match the requested key or its certificate")
	}
}

func TestFetchDeniedWorkloads(t *testing.T) {
	e := newEnv(t)
	a := e.attested()
	for name, caller := range map[string]Caller{
		"unknown service": {PID: 1, UID: 1000, Unit: "other.service"},
		"wrong uid":       {PID: 1, UID: 1001, Unit: "api.service"},
		"root":            {PID: 1, UID: 0, Unit: "api.service"},
	} {
		_, err := fetch(serve(t, a, as(caller)), csrFor(t, p256(t)))
		wantCode(t, err, codes.PermissionDenied)
		if r := api.DenialReason(err); r != "workload_not_allowed" {
			t.Errorf("%s: reason = %q", name, r)
		}
	}
	if n := e.audited(identity.ActionIssueDenied); n != 3 {
		t.Fatalf("%d denials audited, want 3", n)
	}
}

func TestFetchRejectsCSR(t *testing.T) {
	e := newEnv(t)
	c := serve(t, e.attested(), as(apiCaller))
	good := csrFor(t, p256(t))
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-3] ^= 1
	for name, csr := range map[string][]byte{
		"empty":     nil,
		"garbage":   []byte("not a csr"),
		"truncated": good[:len(good)/2],
		"bad sig":   tampered,
		"oversized": make([]byte, MaxCSRSize+1),
	} {
		_, err := fetch(c, csr)
		if name == "oversized" {
			// Either our bound or gRPC's message limit refuses it.
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
			continue
		}
		wantCode(t, err, codes.InvalidArgument)
	}
	// A message far over the limit is refused by gRPC before decoding.
	if _, err := fetch(c, make([]byte, 1<<20)); err == nil {
		t.Fatal("1 MiB request accepted")
	}
	if n := e.audited(identity.ActionIssue) + e.audited(identity.ActionIssueDenied); n != 0 {
		t.Fatalf("%d malformed requests reached attestd", n)
	}
}

func TestFetchWithoutNodeIdentity(t *testing.T) {
	e := newEnv(t)
	a := e.agent()
	c := serve(t, a, as(apiCaller))
	_, err := fetch(c, csrFor(t, p256(t)))
	wantCode(t, err, codes.Unavailable)
	select {
	case <-a.kick:
	default:
		t.Fatal("no re-attestation requested")
	}

	// Expiry of the node identity has the same effect.
	if err := a.Attest(bg); err != nil {
		t.Fatal(err)
	}
	e.clk.Add(time.Hour)
	_, err = fetch(c, csrFor(t, p256(t)))
	wantCode(t, err, codes.Unavailable)
}

func TestFetchSupersededNodeIdentity(t *testing.T) {
	e := newEnv(t)
	a := e.attested()
	c := serve(t, a, as(apiCaller))
	// Another attestation of n1, e.g. by a restarted agent, supersedes the
	// identity this agent holds.
	if err := e.agent().Attest(bg); err != nil {
		t.Fatal(err)
	}
	_, err := fetch(c, csrFor(t, p256(t)))
	wantCode(t, err, codes.Unavailable)
	select {
	case <-a.kick:
	default:
		t.Fatal("no re-attestation requested")
	}
	if err := a.Attest(bg); err != nil {
		t.Fatal(err)
	}
	if _, err := fetch(c, csrFor(t, p256(t))); err != nil {
		t.Fatalf("fetch after re-attestation: %v", err)
	}
}

func TestFetchRefusesUnidentifiedCaller(t *testing.T) {
	e := newEnv(t)
	a := e.attested()
	cfgLogs := e.logs
	c := serve(t, a, func(*net.UnixConn) (*Caller, error) { return nil, ErrNotService })
	_, err := fetch(c, csrFor(t, p256(t)))
	wantCode(t, err, codes.Unavailable)
	if !strings.Contains(cfgLogs.String(), "local caller refused") {
		t.Fatal("refusal not logged")
	}
	if n := e.audited(identity.ActionIssue) + e.audited(identity.ActionIssueDenied); n != 0 {
		t.Fatal("unidentified caller reached attestd")
	}
}

func TestFetchRateLimited(t *testing.T) {
	e := newEnv(t)
	a := e.attested()
	c := serve(t, a, as(apiCaller))
	other := serve(t, a, as(Caller{PID: 2, UID: 1000, Unit: "other.service"}))
	limited := 0
	for range callerBurst + 3 {
		_, err := fetch(other, csrFor(t, p256(t)))
		if err == nil {
			t.Fatal("denied caller issued")
		}
		if status.Code(err) == codes.ResourceExhausted {
			limited++
		}
	}
	if limited < 2 {
		t.Fatalf("only %d of %d rapid requests limited", limited, callerBurst+3)
	}
	// Other callers keep their own budget.
	if _, err := fetch(c, csrFor(t, p256(t))); err != nil {
		t.Fatalf("api.service limited by other.service: %v", err)
	}
}

func TestCallerLimiter(t *testing.T) {
	l := newCallerLimiter()
	now := time.Now()
	for i := range callerBurst {
		if !l.allow("a.service", 1, now) {
			t.Fatalf("request %d of burst refused", i)
		}
	}
	if l.allow("a.service", 1, now) {
		t.Fatal("burst exceeded")
	}
	if !l.allow("a.service", 2, now) {
		t.Fatal("other UID shares the bucket")
	}
	if !l.allow("a.service", 1, now.Add(time.Second)) {
		t.Fatal("bucket did not refill")
	}
	// A clock step backwards must not mint tokens.
	if l.allow("a.service", 1, now.Add(-time.Hour)) {
		t.Fatal("backwards clock refilled the bucket")
	}

	// The table is bounded; idle full buckets are evicted to make room,
	// active ones are not.
	l = newCallerLimiter()
	for i := range maxCallers {
		l.allow("s.service", uint32(i), now) //nolint:gosec // small
	}
	if l.allow("new.service", 1, now) {
		t.Fatal("table grew past its bound with active callers")
	}
	if !l.allow("new.service", 1, now.Add(time.Hour)) {
		t.Fatal("idle callers not evicted")
	}
}

func TestNodeStale(t *testing.T) {
	deny := func(r identity.Reason) error {
		st, err := status.New(codes.PermissionDenied, "denied").
			WithDetails(&errdetails.ErrorInfo{Domain: api.ErrorDomain, Reason: strings.ToUpper(string(r))})
		if err != nil {
			t.Fatal(err)
		}
		return st.Err()
	}
	for _, r := range []identity.Reason{identity.ReasonAttestationSuperseded, identity.ReasonParentRevoked,
		identity.ReasonParentUnknown, identity.ReasonMeasurementPolicy} {
		if !nodeStale(deny(r)) {
			t.Errorf("%s not treated as a stale node identity", r)
		}
	}
	if !nodeStale(status.Error(codes.Unauthenticated, "no client certificate")) {
		t.Error("Unauthenticated not treated as a stale node identity")
	}
	for _, r := range []identity.Reason{identity.ReasonWorkloadNotAllowed, identity.ReasonCallerNodeMismatch,
		identity.ReasonWorkloadPolicyMissing} {
		if nodeStale(deny(r)) {
			t.Errorf("%s treated as a stale node identity", r)
		}
	}
	if nodeStale(errors.New("plain")) {
		t.Error("plain error treated as stale")
	}
}

func TestCheckWorkloadIdentityRejects(t *testing.T) {
	e := newEnv(t)
	a := e.agent()
	other, err := identity.Init(t.TempDir(), identity.Options{TrustDomain: td, Now: e.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	key := p256(t)
	der := csrFor(t, key)
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	wl, _ := identity.WorkloadID(td, "api")
	n1, _ := identity.NodeID(td, "n1")
	bundle := raw(e.ca.Bundle())
	if _, err := a.checkWorkloadIdentity(&attestv1.X509Identity{Certificate: issue(t, e.ca, wl, key.Public()), Bundle: bundle}, csr); err != nil {
		t.Fatalf("valid workload identity refused: %v", err)
	}
	for name, id := range map[string]*attestv1.X509Identity{
		"missing":   nil,
		"node cert": {Certificate: issue(t, e.ca, n1, key.Public()), Bundle: bundle},
		"other key": {Certificate: issue(t, e.ca, wl, p256(t).Public()), Bundle: bundle},
		"other ca":  {Certificate: issue(t, other, wl, key.Public()), Bundle: bundle},
		"no bundle": {Certificate: issue(t, e.ca, wl, key.Public())},
	} {
		if _, err := a.checkWorkloadIdentity(id, csr); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLimitListener(t *testing.T) {
	dir := shortDir(t)
	l, err := net.Listen("unix", dir+"/l.sock")
	if err != nil {
		t.Fatal(err)
	}
	ll := LimitListener(l, 1)
	defer ll.Close()
	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := ll.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	for range 2 {
		c, err := net.Dial("unix", dir+"/l.sock")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	first := <-accepted
	select {
	case <-accepted:
		t.Fatal("second connection accepted past the limit")
	case <-time.After(100 * time.Millisecond):
	}
	_ = first.Close()
	_ = first.Close() // double close releases once
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("slot not released on close")
	}
}
