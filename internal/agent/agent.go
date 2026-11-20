package agent

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	attestv1 "github.com/0xciph3r/attest/api/gen/attest/v1"
	"github.com/0xciph3r/attest/internal/api"
	"github.com/0xciph3r/attest/internal/identity"
	"github.com/0xciph3r/attest/internal/policy"
)

// Config configures an Agent.
type Config struct {
	NodeID      string
	TrustDomain string
	// Bundle authenticates attestd until a node identity arrives with the
	// control plane's current bundle.
	Bundle []*x509.Certificate
	// Addr is attestd's NodeService address, host:port.
	Addr string
	// Dial replaces TCP dialing; tests use it for in-memory connections.
	Dial func(ctx context.Context, addr string) (net.Conn, error)
	TPM  TPM
	Log  *slog.Logger
	Now  func() time.Time
}

// ErrNoNodeIdentity means the agent holds no valid node identity, so it
// cannot obtain workload identities.
var ErrNoNodeIdentity = errors.New("agent: no valid node identity")

// Default attestation retry timing.
const (
	defaultBackoffMin = time.Second
	defaultBackoffMax = time.Minute
	// defaultKickMin spaces re-attestations requested by workload calls,
	// so a misbehaving caller cannot drive the node into an attestation
	// loop.
	defaultKickMin = 10 * time.Second
)

// Agent attests the node, holds its identity and obtains workload
// identities from attestd on behalf of local callers.
type Agent struct {
	cfg  Config
	log  *slog.Logger
	kick chan struct{}
	// Retry timing; tests shorten it.
	backoffMin, backoffMax, kickMin time.Duration

	mu     sync.Mutex
	bundle []*x509.Certificate
	cur    *nodeConn
}

// nodeConn is an mTLS connection presenting one node certificate. It is
// closed once retired and no request is using it.
type nodeConn struct {
	cc      *grpc.ClientConn
	client  attestv1.NodeServiceClient
	cert    *x509.Certificate
	refs    int
	retired bool
}

// New validates cfg and returns an Agent with no node identity.
func New(cfg Config) (*Agent, error) {
	switch {
	case !policy.ValidNodeID(cfg.NodeID):
		return nil, fmt.Errorf("agent: invalid node ID %q", cfg.NodeID)
	case !identity.ValidTrustDomain(cfg.TrustDomain):
		return nil, fmt.Errorf("agent: invalid trust domain %q", cfg.TrustDomain)
	case len(cfg.Bundle) == 0:
		return nil, errors.New("agent: empty trust bundle")
	case cfg.Addr == "":
		return nil, errors.New("agent: no control plane address")
	case cfg.TPM == nil:
		return nil, errors.New("agent: no TPM")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Agent{cfg: cfg, log: cfg.Log, kick: make(chan struct{}, 1), bundle: cfg.Bundle,
		backoffMin: defaultBackoffMin, backoffMax: defaultBackoffMax, kickMin: defaultKickMin}, nil
}

func (a *Agent) dial(bundle []*x509.Certificate, cert *tls.Certificate) (*grpc.ClientConn, error) {
	cfg, err := api.ClientTLS(bundle, a.cfg.TrustDomain, cert, a.cfg.Now)
	if err != nil {
		return nil, err
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(cfg))}
	if a.cfg.Dial != nil {
		opts = append(opts, grpc.WithContextDialer(a.cfg.Dial))
	}
	return grpc.NewClient("passthrough:///"+a.cfg.Addr, opts...)
}

// anonymous connects without a client certificate, as enrollment and
// attestation require.
func (a *Agent) anonymous() (*grpc.ClientConn, attestv1.NodeServiceClient, error) {
	a.mu.Lock()
	bundle := a.bundle
	a.mu.Unlock()
	cc, err := a.dial(bundle, nil)
	if err != nil {
		return nil, nil, err
	}
	return cc, attestv1.NewNodeServiceClient(cc), nil
}

// Enroll proves to attestd that the AK is resident in the TPM holding the
// registered EK. The operator must have registered the node first.
func (a *Agent) Enroll(ctx context.Context) error {
	cc, c, err := a.anonymous()
	if err != nil {
		return err
	}
	defer cc.Close()
	ak := a.cfg.TPM.AKPublic()
	begin, err := c.BeginEnrollment(ctx, &attestv1.BeginEnrollmentRequest{NodeId: a.cfg.NodeID, AkPublic: ak})
	if err != nil {
		return fmt.Errorf("agent: begin enrollment: %w", err)
	}
	secret, err := a.cfg.TPM.ActivateCredential(begin.GetCredentialBlob(), begin.GetEncryptedSecret())
	if err != nil {
		return fmt.Errorf("agent: activate credential: %w", err)
	}
	defer clear(secret)
	if _, err := c.CompleteEnrollment(ctx, &attestv1.CompleteEnrollmentRequest{
		NodeId: a.cfg.NodeID, ChallengeId: begin.GetChallengeId(), Secret: secret, AkPublic: ak}); err != nil {
		return fmt.Errorf("agent: complete enrollment: %w", err)
	}
	return nil
}

// Attest attests the node once and, on success, replaces the node identity
// and trust bundle. A failure leaves the current identity in place until
// it expires.
func (a *Agent) Attest(ctx context.Context) error {
	cc, c, err := a.anonymous()
	if err != nil {
		return err
	}
	defer cc.Close()
	ch, err := c.GetChallenge(ctx, &attestv1.GetChallengeRequest{NodeId: a.cfg.NodeID})
	if err != nil {
		return fmt.Errorf("agent: challenge: %w", err)
	}
	ev, err := a.cfg.TPM.Evidence(ch.GetNonce(), ch.GetPcrs())
	if err != nil {
		return err
	}
	resp, err := c.Attest(ctx, &attestv1.AttestRequest{
		NodeId: a.cfg.NodeID, ChallengeId: ch.GetChallengeId(), Nonce: ch.GetNonce(), Evidence: ev})
	if err != nil {
		return fmt.Errorf("agent: attest: %w", err)
	}
	leaf, bundle, err := a.checkNodeIdentity(resp.GetIdentity())
	if err != nil {
		return err
	}
	conn, err := a.dial(bundle, &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: a.cfg.TPM.NodeKey(), Leaf: leaf})
	if err != nil {
		return err
	}
	a.mu.Lock()
	old := a.cur
	a.cur = &nodeConn{cc: conn, client: attestv1.NewNodeServiceClient(conn), cert: leaf}
	a.bundle = bundle
	a.retireLocked(old)
	a.mu.Unlock()
	a.log.InfoContext(ctx, "node identity renewed", "serial", leaf.SerialNumber.Text(16), "not_after", leaf.NotAfter)
	return nil
}

// checkNodeIdentity accepts id only if it names this node, chains to the
// bundle it carries and certifies the TPM node key. The bundle must also
// share a CA with the one the agent trusts now, so the control plane can
// rotate its CA, which keeps the previous one in the bundle, but cannot
// replace the agent's root of trust with an unrelated one.
func (a *Agent) checkNodeIdentity(id *attestv1.X509Identity) (*x509.Certificate, []*x509.Certificate, error) {
	if id == nil {
		return nil, nil, errors.New("agent: attestation returned no node identity")
	}
	leaf, bundle, err := parseIdentity(id)
	if err != nil {
		return nil, nil, err
	}
	if err := a.continuous(bundle); err != nil {
		return nil, nil, err
	}
	want, err := identity.NodeID(a.cfg.TrustDomain, a.cfg.NodeID)
	if err != nil {
		return nil, nil, err
	}
	got, err := identity.Verify(bundle, a.cfg.TrustDomain, leaf, a.cfg.Now(), x509.ExtKeyUsageClientAuth)
	if err != nil {
		return nil, nil, fmt.Errorf("agent: node identity: %w", err)
	}
	if got != want {
		return nil, nil, fmt.Errorf("agent: node identity is %s, want %s", got, want)
	}
	if !samePublicKey(leaf.PublicKey, a.cfg.TPM.NodeKey().Public()) {
		return nil, nil, errors.New("agent: node identity does not certify the TPM node key")
	}
	return leaf, bundle, nil
}

// ErrBundleDiscontinuous means the control plane returned a trust bundle
// sharing no CA with the one the agent trusts. The agent then needs a new
// bootstrap bundle, as it does after two CA rotations within the lifetime
// of its node identity.
var ErrBundleDiscontinuous = errors.New("agent: trust bundle shares no CA with the current one")

func (a *Agent) continuous(bundle []*x509.Certificate) error {
	a.mu.Lock()
	cur := a.bundle
	a.mu.Unlock()
	for _, c := range bundle {
		if slices.ContainsFunc(cur, c.Equal) {
			return nil
		}
	}
	return ErrBundleDiscontinuous
}

func parseIdentity(id *attestv1.X509Identity) (*x509.Certificate, []*x509.Certificate, error) {
	leaf, err := x509.ParseCertificate(id.GetCertificate())
	if err != nil {
		return nil, nil, fmt.Errorf("agent: identity certificate: %w", err)
	}
	if len(id.GetBundle()) == 0 {
		return nil, nil, errors.New("agent: identity has no trust bundle")
	}
	bundle := make([]*x509.Certificate, 0, len(id.GetBundle()))
	for _, der := range id.GetBundle() {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, fmt.Errorf("agent: trust bundle: %w", err)
		}
		bundle = append(bundle, c)
	}
	return leaf, bundle, nil
}

func samePublicKey(a, b crypto.PublicKey) bool {
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && b != nil && k.Equal(b)
}

// acquire returns the current node connection, or nil if there is no
// unexpired node identity. The caller must release it.
func (a *Agent) acquire() *nodeConn {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cur == nil {
		return nil
	}
	if !a.cfg.Now().Before(a.cur.cert.NotAfter) {
		a.log.Warn("node identity expired", "serial", a.cur.cert.SerialNumber.Text(16))
		a.retireLocked(a.cur)
		a.cur = nil
		return nil
	}
	a.cur.refs++
	return a.cur
}

func (a *Agent) current() *nodeConn {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cur
}

func (a *Agent) release(c *nodeConn) {
	a.mu.Lock()
	defer a.mu.Unlock()
	c.refs--
	if c.retired && c.refs == 0 {
		_ = c.cc.Close()
	}
}

func (a *Agent) retireLocked(c *nodeConn) {
	if c == nil || c.retired {
		return
	}
	c.retired = true
	if c.refs == 0 {
		_ = c.cc.Close()
	}
}

// requestAttestation asks Run to re-attest soon; extra requests coalesce.
func (a *Agent) requestAttestation() {
	select {
	case a.kick <- struct{}{}:
	default:
	}
}

// Run attests the node and keeps its identity renewed until ctx ends, at
// which point it drops the identity. It renews at half the certificate's
// lifetime and retries failures with jittered exponential backoff.
func (a *Agent) Run(ctx context.Context) error {
	defer a.Close()
	failures := 0
	var last time.Time
	for {
		last = time.Now()
		var wait time.Duration
		if err := a.Attest(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			failures++
			wait = backoff(failures, a.backoffMin, a.backoffMax)
			a.log.WarnContext(ctx, "attestation failed", "err", err, "reason", api.DenialReason(err), "retry_in", wait)
		} else {
			failures = 0
			wait = a.renewIn()
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		case <-a.kick:
			t.Stop()
			if err := sleep(ctx, time.Until(last.Add(a.kickMin))); err != nil {
				return err
			}
		}
	}
}

// renewIn is the time until the node identity reaches half its lifetime.
func (a *Agent) renewIn() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cur == nil {
		return a.backoffMin
	}
	c := a.cur.cert
	return max(c.NotBefore.Add(c.NotAfter.Sub(c.NotBefore)/2).Sub(a.cfg.Now()), a.backoffMin)
}

// backoff returns the delay before retry n (n >= 1): exponential from lo,
// capped at hi, with the upper half jittered.
func backoff(n int, lo, hi time.Duration) time.Duration {
	d := hi
	if n < 32 && lo<<(n-1) < hi {
		d = lo << (n - 1)
	}
	return d/2 + rand.N(d/2+1) //nolint:gosec // jitter needs no secrecy
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Close drops the node identity.
func (a *Agent) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.retireLocked(a.cur)
	a.cur = nil
}
