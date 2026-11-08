package api

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/tap"
)

// RateLimits bounds the call rate on the node listener, which accepts
// unauthenticated callers. Rates are calls per second.
type RateLimits struct {
	// PerPeer and PerPeerBurst limit each source address (IPv6 by /64).
	PerPeer      float64
	PerPeerBurst int
	// Global and GlobalBurst limit all callers together.
	Global      float64
	GlobalBurst int
	// MaxPeers bounds the per-peer table. Peers beyond it share one bucket.
	MaxPeers int
}

// DefaultRateLimits suit a control plane serving a few hundred nodes, each
// attesting and renewing identities every few minutes.
var DefaultRateLimits = RateLimits{PerPeer: 5, PerPeerBurst: 20, Global: 200, GlobalBurst: 400, MaxPeers: 4096}

// MaxNodeConnections bounds concurrent connections to the node listener.
const MaxNodeConnections = 1024

// rateLimitLogInterval is the minimum time between rate-limit log lines, so
// a flood cannot fill the disk through the log either.
const rateLimitLogInterval = 10 * time.Second

// errRateLimited is returned to limited callers.
var errRateLimited = status.Error(codes.ResourceExhausted, "rate limit exceeded")

type bucket struct {
	tokens float64
	last   time.Time
}

// take refills b at rate up to burst and spends one token if it can.
func (b *bucket) take(now time.Time, rate float64, burst int) bool {
	b.refill(now, rate, burst)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (b *bucket) refill(now time.Time, rate float64, burst int) {
	if d := now.Sub(b.last); d > 0 {
		b.tokens = min(float64(burst), b.tokens+d.Seconds()*rate)
	}
	b.last = now
}

// RateLimiter admits node API calls before their request is read.
type RateLimiter struct {
	lim RateLimits
	now func() time.Time
	log *slog.Logger

	mu        sync.Mutex
	global    bucket
	peers     map[netip.Prefix]*bucket
	overflow  bucket
	lastSweep time.Time
	limited   uint64
	lastLog   time.Time
}

// NewRateLimiter returns a limiter enforcing lim. A nil log discards.
func NewRateLimiter(lim RateLimits, log *slog.Logger) *RateLimiter {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &RateLimiter{lim: lim, now: time.Now, log: log, peers: make(map[netip.Prefix]*bucket),
		global: bucket{tokens: float64(lim.GlobalBurst)}, overflow: bucket{tokens: float64(lim.PerPeerBurst)}}
}

// TapHandle is a grpc.InTapHandle. It runs when a call's headers arrive,
// before the request message is read or any handler runs.
func (r *RateLimiter) TapHandle(ctx context.Context, _ *tap.Info) (context.Context, error) {
	var addr net.Addr
	if p, ok := peer.FromContext(ctx); ok {
		addr = p.Addr
	}
	if !r.allow(peerKey(addr)) {
		return ctx, errRateLimited
	}
	return ctx, nil
}

func (r *RateLimiter) allow(key netip.Prefix) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	ok := r.peer(key, now).take(now, r.lim.PerPeer, r.lim.PerPeerBurst) &&
		r.global.take(now, r.lim.Global, r.lim.GlobalBurst)
	if !ok {
		r.limited++
		if now.Sub(r.lastLog) >= rateLimitLogInterval {
			r.log.Warn("node API rate limit exceeded", "refused", r.limited, "peer", key.String(), "peers", len(r.peers))
			r.limited, r.lastLog = 0, now
		}
	}
	return ok
}

// peer returns key's bucket, creating it if the table has room.
func (r *RateLimiter) peer(key netip.Prefix, now time.Time) *bucket {
	if b := r.peers[key]; b != nil {
		return b
	}
	if len(r.peers) >= r.lim.MaxPeers && now.Sub(r.lastSweep) >= time.Second {
		r.lastSweep = now
		// A full bucket is indistinguishable from a new one.
		for k, b := range r.peers {
			if b.refill(now, r.lim.PerPeer, r.lim.PerPeerBurst); b.tokens >= float64(r.lim.PerPeerBurst) {
				delete(r.peers, k)
			}
		}
	}
	if len(r.peers) >= r.lim.MaxPeers {
		return &r.overflow
	}
	b := &bucket{tokens: float64(r.lim.PerPeerBurst), last: now}
	r.peers[key] = b
	return b
}

// peerKey groups callers by IPv4 address or IPv6 /64, since a single host
// commonly controls a whole /64. Non-IP peers share one key.
func peerKey(a net.Addr) netip.Prefix {
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		return netip.Prefix{}
	}
	ip, ok := netip.AddrFromSlice(ta.IP)
	if !ok {
		return netip.Prefix{}
	}
	ip = ip.Unmap()
	bits := 32
	if ip.Is6() {
		bits = 64
	}
	p, _ := ip.Prefix(bits)
	return p
}
