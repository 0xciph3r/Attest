package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/0xciph3r/attest/internal/audit"
	"github.com/0xciph3r/attest/internal/identity"
	"github.com/0xciph3r/attest/internal/store"
)

// ServerName is the name in attestd's SPIFFE server ID.
const ServerName = "attestd"

// DefaultServerCertTTL is the validity of attestd's TLS certificate.
const DefaultServerCertTTL = 24 * time.Hour

// ServerCert holds attestd's TLS server identity. The key is generated in
// memory and never stored; the certificate is renewed once half its
// lifetime has elapsed, and every issuance is audited.
type ServerCert struct {
	ca  *identity.CA
	st  *store.Store
	id  identity.ID
	ttl time.Duration
	now func() time.Time
	log *slog.Logger

	mu       sync.Mutex
	cur      *tls.Certificate
	renewAt  time.Time
	notAfter time.Time
}

// ServerCertConfig configures a ServerCert.
type ServerCertConfig struct {
	CA    *identity.CA
	Store *store.Store
	// TTL defaults to DefaultServerCertTTL.
	TTL time.Duration
	Now func() time.Time
	Log *slog.Logger
}

// NewServerCert issues attestd's initial server certificate.
func NewServerCert(ctx context.Context, cfg ServerCertConfig) (*ServerCert, error) {
	if cfg.CA == nil || cfg.Store == nil {
		return nil, errors.New("api: server certificate needs a CA and a store")
	}
	id, err := identity.ServerID(cfg.CA.TrustDomain(), ServerName)
	if err != nil {
		return nil, err
	}
	c := &ServerCert{ca: cfg.CA, st: cfg.Store, id: id, ttl: cfg.TTL, now: cfg.Now, log: cfg.Log}
	if c.ttl == 0 {
		c.ttl = DefaultServerCertTTL
	}
	if c.ttl < 0 || c.ttl > identity.MaxTTL {
		return nil, fmt.Errorf("api: server certificate TTL %s outside (0, %s]", c.ttl, identity.MaxTTL)
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.log == nil {
		c.log = slog.Default()
	}
	if err := c.renew(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// ID returns the server's SPIFFE ID.
func (c *ServerCert) ID() identity.ID { return c.id }

// Get returns the certificate to serve, renewing it when due. If renewal
// fails the current certificate is served until it expires; after that
// the handshake fails.
func (c *ServerCert) Get() (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if !now.Before(c.renewAt) {
		if err := c.renewLocked(context.Background()); err != nil {
			c.log.Error("server certificate renewal failed", "err", err)
			if !now.Before(c.notAfter) {
				return nil, fmt.Errorf("api: server certificate expired and renewal failed: %w", err)
			}
		}
	}
	return c.cur, nil
}

func (c *ServerCert) renew(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.renewLocked(ctx)
}

func (c *ServerCert) renewLocked(ctx context.Context) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	iss, err := c.ca.Issue(identity.IssueRequest{ID: c.id, PublicKey: key.Public(), TTL: c.ttl})
	if err != nil {
		return err
	}
	ca := sha256.Sum256(c.ca.Cert().Raw)
	spki := sha256.Sum256(iss.Cert.RawSubjectPublicKeyInfo)
	meta, err := json.Marshal(map[string]any{"kind": identity.KindServer, "spiffe_id": c.id.String(),
		"not_after": iss.Cert.NotAfter.UTC().Format(time.RFC3339), "public_key": hex.EncodeToString(spki[:]),
		"issuer": hex.EncodeToString(ca[:])})
	if err != nil {
		return err
	}
	// An unaudited server key is never used.
	if _, err := c.st.AppendAudit(ctx, audit.Record{Time: c.now(), Actor: "attestd", Action: identity.ActionIssue,
		Object: "identity/" + iss.Serial, Metadata: meta}); err != nil {
		return err
	}
	chain := [][]byte{iss.Cert.Raw}
	c.cur = &tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: iss.Cert}
	c.notAfter = iss.Cert.NotAfter
	c.renewAt = iss.Cert.NotBefore.Add(iss.Cert.NotAfter.Sub(iss.Cert.NotBefore) / 2)
	return nil
}

// ClientTLS returns the TLS configuration node agents use to reach attestd:
// the server must present attestd's SPIFFE server ID under bundle for
// trust domain td. cert, if non-nil, is the node identity to present.
func ClientTLS(bundle []*x509.Certificate, td string, cert *tls.Certificate, now func() time.Time) (*tls.Config, error) {
	want, err := identity.ServerID(td, ServerName)
	if err != nil {
		return nil, err
	}
	if len(bundle) == 0 {
		return nil, errors.New("api: empty trust bundle")
	}
	if now == nil {
		now = time.Now
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2"},
		// Hostname verification does not apply to SPIFFE IDs;
		// VerifyConnection performs the full check instead.
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("api: server sent no certificate")
			}
			id, err := identity.Verify(bundle, td, cs.PeerCertificates[0], now(), x509.ExtKeyUsageServerAuth)
			if err != nil {
				return err
			}
			if id != want {
				return fmt.Errorf("%w: server is %s, want %s", identity.ErrUntrusted, id, want)
			}
			return nil
		},
	}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return cfg, nil
}

// ServerTLS returns the TLS configuration NodeService is served with.
// Client certificates are requested but verified by the handlers that need
// them, against the trust bundle current at the time; Go's handshake still
// requires the client to prove possession of any certificate it sends.
func ServerTLS(cert *ServerCert) *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		ClientAuth:     tls.RequestClientCert,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert.Get() },
		NextProtos:     []string{"h2"},
	}
}
