package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	attestv1 "github.com/0xciph3r/attest/api/gen/attest/v1"
	"github.com/0xciph3r/attest/internal/api"
	"github.com/0xciph3r/attest/internal/identity"
)

// Workload API limits.
const (
	// MaxCSRSize bounds a workload's certificate request; a P-256 request
	// is a few hundred bytes.
	MaxCSRSize = 4096
	// MaxWorkloadConns bounds concurrent local connections.
	MaxWorkloadConns = 256
	// Per-caller request rate: callers renew every few minutes at most.
	callerRate  = 1.0 // per second
	callerBurst = 5
	maxCallers  = 1024
)

// identifyFunc identifies the process on the far end of a connection.
type identifyFunc func(*net.UnixConn) (*Caller, error)

// callerInfo is the AuthInfo of an identified local connection.
type callerInfo struct {
	credentials.CommonAuthInfo
	caller *Caller
}

func (callerInfo) AuthType() string { return "attest-agent-caller" }

// callerCreds identifies the caller during the gRPC handshake, so a
// connection the kernel cannot attribute to a service never carries a
// request. The identity is bound to the connection: whoever holds the
// socket acts as the process that opened it.
type callerCreds struct {
	identify identifyFunc
	log      *slog.Logger
	lastLog  *atomic.Int64
}

func (c callerCreds) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	uc := unixConn(conn)
	if uc == nil {
		return nil, nil, errors.New("agent: not a Unix socket connection")
	}
	caller, err := c.identify(uc)
	if err != nil {
		// Refusals can be provoked by any local user; log at most once a
		// second.
		now := time.Now().Unix()
		if last := c.lastLog.Load(); now > last && c.lastLog.CompareAndSwap(last, now) {
			c.log.Warn("local caller refused", "err", err)
		}
		return nil, nil, err
	}
	return conn, callerInfo{CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.NoSecurity}, caller: caller}, nil
}

func (callerCreds) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("agent: server-only credentials")
}

func (callerCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "attest-agent-caller"}
}

func (c callerCreds) Clone() credentials.TransportCredentials { return c }

func (callerCreds) OverrideServerName(string) error { return nil }

func unixConn(c net.Conn) *net.UnixConn {
	switch c := c.(type) {
	case *net.UnixConn:
		return c
	case *limitedConn:
		return c.UnixConn
	}
	return nil
}

// NewWorkloadServer returns the gRPC server for the local Workload API.
// Serve it on a listener from LimitListener(api.ListenUnix(...)).
func (a *Agent) NewWorkloadServer() *grpc.Server { return a.newWorkloadServer(identify) }

func (a *Agent) newWorkloadServer(id identifyFunc) *grpc.Server {
	srv := grpc.NewServer(
		grpc.Creds(callerCreds{identify: id, log: a.log, lastLog: new(atomic.Int64)}),
		grpc.ConnectionTimeout(5*time.Second),
		grpc.MaxRecvMsgSize(MaxCSRSize+64),
		grpc.MaxConcurrentStreams(4),
	)
	attestv1.RegisterWorkloadServiceServer(srv, &workloadService{a: a, lim: newCallerLimiter()})
	return srv
}

type workloadService struct {
	attestv1.UnimplementedWorkloadServiceServer
	a   *Agent
	lim *callerLimiter
}

func (s *workloadService) FetchX509Identity(ctx context.Context, req *attestv1.FetchX509IdentityRequest) (*attestv1.FetchX509IdentityResponse, error) {
	p, ok := peer.FromContext(ctx)
	info, ok2 := p.AuthInfo.(callerInfo)
	if !ok || !ok2 {
		return nil, status.Error(codes.Unauthenticated, "caller not identified")
	}
	c := info.caller
	if !s.lim.allow(c.Unit, c.UID, time.Now()) {
		return nil, status.Error(codes.ResourceExhausted, "too many requests")
	}
	csrDER := req.GetCsr()
	if len(csrDER) == 0 || len(csrDER) > MaxCSRSize {
		return nil, status.Error(codes.InvalidArgument, "csr is empty or too large")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil {
		return nil, status.Error(codes.InvalidArgument, "csr is malformed or not self-signed")
	}
	id, err := s.issue(ctx, c, csr, true)
	if err != nil {
		return nil, err
	}
	return &attestv1.FetchX509IdentityResponse{Identity: id}, nil
}

// issue forwards the request over the node connection. A denial that means
// the node identity is no longer current triggers re-attestation and, if a
// newer identity is already in place, one retry.
func (s *workloadService) issue(ctx context.Context, c *Caller, csr *x509.CertificateRequest, retry bool) (*attestv1.X509Identity, error) {
	nc := s.a.acquire()
	if nc == nil {
		s.a.requestAttestation()
		return nil, status.Error(codes.Unavailable, ErrNoNodeIdentity.Error())
	}
	resp, err := nc.client.IssueWorkloadIdentity(ctx, &attestv1.IssueWorkloadIdentityRequest{
		SystemdUnit: c.Unit, Uid: c.UID, Csr: csr.Raw})
	s.a.release(nc)
	if err != nil {
		if !nodeStale(err) {
			return nil, passThrough(s.a.log, c, err)
		}
		s.a.log.Warn("node identity no longer accepted", "reason", api.DenialReason(err), "code", status.Code(err))
		s.a.requestAttestation()
		if retry && s.a.current() != nc {
			return s.issue(ctx, c, csr, false)
		}
		return nil, status.Error(codes.Unavailable, "node identity is being renewed")
	}
	id, err := s.a.checkWorkloadIdentity(resp.GetIdentity(), csr)
	if err != nil {
		s.a.log.Error("control plane returned an invalid workload identity", "unit", c.Unit, "uid", c.UID, "err", err)
		return nil, status.Error(codes.Internal, "invalid identity from control plane")
	}
	s.a.log.Info("workload identity issued", "unit", c.Unit, "uid", c.UID, "spiffe_id", id.GetSpiffeId())
	return id, nil
}

// nodeStale reports whether err means attestd no longer accepts the node
// certificate, as opposed to refusing this workload.
func nodeStale(err error) bool {
	if status.Code(err) == codes.Unauthenticated {
		return true
	}
	switch identity.Reason(api.DenialReason(err)) {
	case identity.ReasonAttestationSuperseded, identity.ReasonAttestationUnknown, identity.ReasonAttestationFailed,
		identity.ReasonMeasurementPolicy, identity.ReasonParentUnknown, identity.ReasonParentRevoked,
		identity.ReasonParentMismatch:
		return true
	}
	return false
}

// passThrough returns denials and argument errors to the caller as attestd
// stated them; anything else is reported as the control plane being
// unavailable.
func passThrough(log *slog.Logger, c *Caller, err error) error {
	switch status.Code(err) {
	case codes.PermissionDenied:
		log.Warn("workload identity denied", "unit", c.Unit, "uid", c.UID, "reason", api.DenialReason(err))
		return status.Convert(err).Err()
	case codes.InvalidArgument, codes.ResourceExhausted:
		return status.Convert(err).Err()
	}
	log.Warn("workload identity request failed", "unit", c.Unit, "uid", c.UID, "err", err)
	return status.Error(codes.Unavailable, "control plane unavailable")
}

// checkWorkloadIdentity accepts id only if it is a workload identity that
// chains to the bundle it carries, that bundle continues the agent's, and
// it certifies the key in csr.
func (a *Agent) checkWorkloadIdentity(id *attestv1.X509Identity, csr *x509.CertificateRequest) (*attestv1.X509Identity, error) {
	if id == nil {
		return nil, errors.New("no identity")
	}
	leaf, bundle, err := parseIdentity(id)
	if err != nil {
		return nil, err
	}
	if err := a.continuous(bundle); err != nil {
		return nil, err
	}
	got, err := identity.Verify(bundle, a.cfg.TrustDomain, leaf, a.cfg.Now(), x509.ExtKeyUsageClientAuth)
	if err != nil {
		return nil, err
	}
	if got.Kind != identity.KindWorkload {
		return nil, errors.New("not a workload identity: " + got.String())
	}
	if !samePublicKey(leaf.PublicKey, csr.PublicKey) {
		return nil, errors.New("certificate does not certify the requested key")
	}
	return &attestv1.X509Identity{SpiffeId: got.String(), Certificate: leaf.Raw, Bundle: id.GetBundle(),
		NotAfter: timestamppb.New(leaf.NotAfter)}, nil
}

// callerLimiter is a token bucket per service and UID.
type callerLimiter struct {
	mu      sync.Mutex
	buckets map[callerKey]*callerBucket
}

type callerKey struct {
	unit string
	uid  uint32
}

type callerBucket struct {
	tokens float64
	last   time.Time
}

func newCallerLimiter() *callerLimiter {
	return &callerLimiter{buckets: make(map[callerKey]*callerBucket)}
}

func (l *callerLimiter) allow(unit string, uid uint32, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := callerKey{unit, uid}
	b := l.buckets[k]
	if b == nil {
		if len(l.buckets) >= maxCallers {
			// Only services can connect, so the table is bounded by the
			// node's units; forgetting full buckets is harmless.
			for k, b := range l.buckets {
				if now.After(b.last) && b.tokens+now.Sub(b.last).Seconds()*callerRate >= callerBurst {
					delete(l.buckets, k)
				}
			}
			if len(l.buckets) >= maxCallers {
				return false
			}
		}
		b = &callerBucket{tokens: callerBurst, last: now}
		l.buckets[k] = b
	}
	if now.After(b.last) {
		b.tokens = min(callerBurst, b.tokens+now.Sub(b.last).Seconds()*callerRate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// LimitListener caps l at n concurrent connections; further connections
// wait in the kernel backlog.
func LimitListener(l net.Listener, n int) net.Listener {
	return &limitedListener{Listener: l, sem: make(chan struct{}, n)}
}

type limitedListener struct {
	net.Listener
	sem chan struct{}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		_ = c.Close()
		<-l.sem
		return nil, errors.New("agent: listener is not a Unix socket")
	}
	return &limitedConn{UnixConn: uc, release: func() { <-l.sem }}, nil
}

type limitedConn struct {
	*net.UnixConn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.UnixConn.Close()
	c.once.Do(c.release)
	return err
}
