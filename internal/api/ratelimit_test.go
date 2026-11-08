package api

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	attestv1 "github.com/0xciph3r/attest/api/gen/attest/v1"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newTestLimiter(lim RateLimits, log *slog.Logger) (*RateLimiter, *fakeClock) {
	r := NewRateLimiter(lim, log)
	c := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	r.now = c.now
	return r, c
}

func ip(s string) netip.Prefix { return peerKey(&net.TCPAddr{IP: net.ParseIP(s), Port: 1234}) }

// admitted counts how many of n calls from key are allowed.
func admitted(r *RateLimiter, key netip.Prefix, n int) int {
	ok := 0
	for range n {
		if r.allow(key) {
			ok++
		}
	}
	return ok
}

func TestRateLimiterPerPeer(t *testing.T) {
	r, clk := newTestLimiter(RateLimits{PerPeer: 2, PerPeerBurst: 5, Global: 1000, GlobalBurst: 1000, MaxPeers: 16}, nil)
	a, b := ip("192.0.2.1"), ip("192.0.2.2")
	if got := admitted(r, a, 50); got != 5 {
		t.Fatalf("burst admitted %d, want 5", got)
	}
	if got := admitted(r, b, 50); got != 5 {
		t.Fatalf("one peer's flood limited another: %d", got)
	}
	clk.t = clk.t.Add(time.Second)
	if got := admitted(r, a, 50); got != 2 {
		t.Fatalf("after 1s admitted %d, want 2", got)
	}
	clk.t = clk.t.Add(time.Hour)
	if got := admitted(r, a, 50); got != 5 {
		t.Fatalf("refill exceeded burst: %d", got)
	}
}

func TestRateLimiterGlobal(t *testing.T) {
	r, _ := newTestLimiter(RateLimits{PerPeer: 100, PerPeerBurst: 100, Global: 1, GlobalBurst: 10, MaxPeers: 1024}, nil)
	total := 0
	for i := range 100 {
		total += admitted(r, ip(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}).String()), 5)
	}
	if total != 10 {
		t.Fatalf("many peers admitted %d, want global burst 10", total)
	}
}

func TestPeerKey(t *testing.T) {
	for _, tc := range []struct{ a, b string }{
		{"2001:db8:1:2::1", "2001:db8:1:2:ffff::9"}, // same /64
		{"192.0.2.7", "::ffff:192.0.2.7"},           // IPv4-mapped
	} {
		if ip(tc.a) != ip(tc.b) {
			t.Errorf("%s and %s have different keys", tc.a, tc.b)
		}
	}
	for _, tc := range []struct{ a, b string }{
		{"2001:db8:1:2::1", "2001:db8:1:3::1"},
		{"192.0.2.7", "192.0.2.8"},
	} {
		if ip(tc.a) == ip(tc.b) {
			t.Errorf("%s and %s share a key", tc.a, tc.b)
		}
	}
	if peerKey(&net.UnixAddr{Name: "/x"}) != peerKey(nil) {
		t.Error("non-IP peers have different keys")
	}
}

// Rotating source addresses neither grows the table without bound nor
// resets a drained peer's budget.
func TestRateLimiterPeerTableBounded(t *testing.T) {
	r, clk := newTestLimiter(RateLimits{PerPeer: 1e-3, PerPeerBurst: 3, Global: 1e9, GlobalBurst: 1e9, MaxPeers: 64}, nil)
	victim := ip("192.0.2.1")
	admitted(r, victim, 3)
	overflowOK := 0
	for i := range 10_000 {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		overflowOK += admitted(r, ip(a.String()), 1)
		if i%1000 == 0 {
			clk.t = clk.t.Add(10 * time.Millisecond)
		}
	}
	if n := len(r.peers); n > 64 {
		t.Fatalf("peer table grew to %d", n)
	}
	// Past the table, new peers share one bucket rather than getting a
	// fresh burst each.
	if overflowOK > 63*3+3+1 {
		t.Fatalf("rotating peers admitted %d calls", overflowOK)
	}
	// Let a sweep run: the drained victim must survive it.
	clk.t = clk.t.Add(1100 * time.Millisecond)
	admitted(r, ip("203.0.113.1"), 1)
	if r.allow(victim) {
		t.Fatal("drained peer's budget reset by a rotation flood")
	}
	// Idle peers are swept, so new peers get their own bucket again.
	clk.t = clk.t.Add(time.Hour)
	if !r.allow(ip("203.0.113.9")) || len(r.peers) > 2 {
		t.Fatalf("idle peers not evicted: %d", len(r.peers))
	}
}

func TestRateLimiterClockSkew(t *testing.T) {
	r, clk := newTestLimiter(RateLimits{PerPeer: 1, PerPeerBurst: 2, Global: 1e9, GlobalBurst: 1e9, MaxPeers: 8}, nil)
	a := ip("192.0.2.1")
	admitted(r, a, 2)
	clk.t = clk.t.Add(-time.Hour)
	if r.allow(a) {
		t.Fatal("clock stepping back minted tokens")
	}
}

type countingHandler struct{ n atomic.Int64 }

func (h *countingHandler) Enabled(context.Context, slog.Level) bool  { return true }
func (h *countingHandler) Handle(context.Context, slog.Record) error { h.n.Add(1); return nil }
func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler        { return h }
func (h *countingHandler) WithGroup(string) slog.Handler             { return h }

// A flood produces at most one log line per interval.
func TestRateLimiterLogSampled(t *testing.T) {
	h := &countingHandler{}
	r, clk := newTestLimiter(RateLimits{PerPeer: 1, PerPeerBurst: 1, Global: 1e9, GlobalBurst: 1e9, MaxPeers: 8}, slog.New(h))
	a := ip("192.0.2.1")
	admitted(r, a, 10_000)
	if n := h.n.Load(); n != 1 {
		t.Fatalf("%d log lines for one flood", n)
	}
	clk.t = clk.t.Add(rateLimitLogInterval)
	admitted(r, a, 10_000)
	if n := h.n.Load(); n != 2 {
		t.Fatalf("%d log lines after the interval, want 2", n)
	}
}

// Refused calls fail with RESOURCE_EXHAUSTED before reaching a handler.
func TestNodeAPIRateLimited(t *testing.T) {
	e := newEnvLimited(t, RateLimits{PerPeer: 1e-9, PerPeerBurst: 3, Global: 1e9, GlobalBurst: 1e9, MaxPeers: 8})
	c := e.client(nil)
	for i := range 3 {
		// Malformed: a handler answers INVALID_ARGUMENT.
		_, err := c.Attest(bg, &attestv1.AttestRequest{})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	for _, call := range []func() error{
		func() error { _, err := c.Attest(bg, &attestv1.AttestRequest{}); return err },
		func() error { _, err := c.GetChallenge(bg, &attestv1.GetChallengeRequest{NodeId: "n1"}); return err },
		func() error {
			_, err := c.BeginEnrollment(bg, &attestv1.BeginEnrollmentRequest{NodeId: "n1"})
			return err
		},
	} {
		if err := call(); status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("over limit: %v", err)
		}
	}
}
