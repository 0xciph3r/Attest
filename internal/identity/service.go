package identity

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/0xciph3r/attest/internal/audit"
	"github.com/0xciph3r/attest/internal/policy"
	"github.com/0xciph3r/attest/internal/store"
)

// Service defaults.
const (
	DefaultNodeTTL           = time.Hour
	DefaultAttestationMaxAge = 2 * time.Minute
)

// Audit actions.
const (
	ActionPolicyApply = "policy.apply"
	ActionIssue       = "identity.issue"
	ActionIssueDenied = "identity.issue.denied"
	actorNodePrefix   = "node:"
)

// Reason is a stable machine-readable denial code.
type Reason string

// Denial reasons.
const (
	ReasonAttestationUnknown    Reason = "attestation_unknown"
	ReasonAttestationWrongNode  Reason = "attestation_wrong_node"
	ReasonAttestationFailed     Reason = "attestation_failed"
	ReasonAttestationStale      Reason = "attestation_stale"
	ReasonAttestationSuperseded Reason = "attestation_superseded"
	ReasonMeasurementPolicy     Reason = "measurement_policy_changed"
	ReasonKeyNotAttested        Reason = "key_not_attested"
	ReasonKeyBinding            Reason = "key_binding_mismatch"
	ReasonNodeNotEnrolled       Reason = "node_not_enrolled"
	ReasonAlreadyIssued         Reason = "already_issued"
	ReasonParentUnknown         Reason = "parent_identity_unknown"
	ReasonParentRevoked         Reason = "parent_identity_revoked"
	ReasonParentMismatch        Reason = "parent_identity_mismatch"
	ReasonCallerNodeMismatch    Reason = "caller_node_mismatch"
	ReasonWorkloadPolicyMissing Reason = "workload_policy_missing"
	ReasonWorkloadNotAllowed    Reason = "workload_not_allowed"
)

// Error is an issuance denial. Denials of authenticated requests are
// audited; the request is refused either way.
type Error struct {
	Reason Reason
	Err    error
}

func (e *Error) Error() string { return fmt.Sprintf("identity: %s: %v", e.Reason, e.Err) }

func (e *Error) Unwrap() error { return e.Err }

func deny(r Reason, format string, args ...any) *Error {
	return &Error{Reason: r, Err: fmt.Errorf(format, args...)}
}

// ReasonOf returns the denial reason of err, or "" if err is not a denial.
func ReasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

// ErrInvalidRequest is returned for requests refused before any state is
// read.
var ErrInvalidRequest = errors.New("identity: invalid request")

// ServiceConfig configures a Service.
type ServiceConfig struct {
	Store *store.Store
	CA    *CA
	// NodeTTL bounds node identities; default DefaultNodeTTL.
	NodeTTL time.Duration
	// AttestationMaxAge is how recent the attestation backing a node
	// identity must be; default DefaultAttestationMaxAge.
	AttestationMaxAge time.Duration
	// Now defaults to time.Now. It should agree with the CA's clock.
	Now func() time.Time
}

// Service issues node identities from fresh attestations and workload
// identities under live node identities, recording each issuance and each
// denial with an audit entry in the same transaction.
type Service struct {
	st      *store.Store
	ca      *CA
	nodeTTL time.Duration
	maxAge  time.Duration
	now     func() time.Time
}

// NewService returns an identity service.
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Store == nil || cfg.CA == nil {
		return nil, errors.New("identity: service needs a store and a CA")
	}
	s := &Service{st: cfg.Store, ca: cfg.CA, nodeTTL: cfg.NodeTTL, maxAge: cfg.AttestationMaxAge, now: cfg.Now}
	if s.nodeTTL == 0 {
		s.nodeTTL = DefaultNodeTTL
	}
	if s.nodeTTL < 0 || s.nodeTTL > MaxTTL {
		return nil, fmt.Errorf("identity: node TTL %s outside (0, %s]", s.nodeTTL, MaxTTL)
	}
	if s.maxAge == 0 {
		s.maxAge = DefaultAttestationMaxAge
	}
	if s.maxAge < 0 {
		return nil, fmt.Errorf("identity: negative attestation max age %s", s.maxAge)
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// ApplyWorkloadPolicy validates doc and makes it the current workload
// policy. It takes effect for subsequent issuance; identities already
// issued remain valid until they expire.
func (s *Service) ApplyWorkloadPolicy(ctx context.Context, actor string, doc []byte) (int64, error) {
	if actor == "" {
		return 0, ErrInvalidRequest
	}
	p, err := policy.ParseWorkload(doc)
	if err != nil {
		return 0, err
	}
	now := s.now()
	var version int64
	err = s.st.Update(ctx, func(tx *store.Tx) error {
		var err error
		version, err = tx.InsertPolicy(&store.Policy{
			Kind: store.PolicyWorkload, Document: doc, Digest: p.Digest(), CreatedAt: now, CreatedBy: actor,
		})
		if err != nil {
			return err
		}
		return appendAudit(tx, now, actor, ActionPolicyApply, fmt.Sprintf("policy/v%d", version), map[string]any{
			"kind": store.PolicyWorkload, "digest": hex.EncodeToString(p.Digest()), "workloads": len(p.Workloads),
		})
	})
	return version, err
}

// Identity is an issued identity and the trust bundle to use it with.
type Identity struct {
	ID     ID
	Cert   *x509.Certificate
	Serial string
	// Bundle is the trust bundle to verify peers with.
	Bundle   []*x509.Certificate
	AuditSeq uint64
}

// IssueNode issues a node identity for pub, which the attestation must have
// bound to the node's TPM. The attestation must be the node's latest, have
// passed under the current measurement policy and be recent, and at most
// one identity is issued from it.
//
// IssueNode is meant to be called by the server immediately after it
// verified the attestation, not exposed as a separate request: that keeps
// anyone else from claiming the one issuance an attestation allows.
func (s *Service) IssueNode(ctx context.Context, nodeID string, attestationID int64, pub crypto.PublicKey) (*Identity, error) {
	if !policy.ValidNodeID(nodeID) || attestationID <= 0 {
		return nil, ErrInvalidRequest
	}
	sid, err := NodeID(s.ca.TrustDomain(), nodeID)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	keyHash, err := spkiHash(pub)
	if err != nil {
		return nil, err
	}
	actor := actorNodePrefix + nodeID
	now := s.now()
	var out *Identity
	denial, err := s.update(ctx, now, actor, "node/"+nodeID, map[string]any{"kind": KindNode, "attestation": attestationID},
		func(tx *store.Tx) error {
			a, err := tx.Attestation(attestationID)
			if errors.Is(err, store.ErrNotFound) {
				return deny(ReasonAttestationUnknown, "no attestation %d", attestationID)
			}
			if err != nil {
				return err
			}
			if a.NodeID != nodeID {
				return deny(ReasonAttestationWrongNode, "attestation %d belongs to another node", attestationID)
			}
			if err := s.checkAttestation(tx, a); err != nil {
				return err
			}
			if age := now.Sub(a.VerifiedAt); age > s.maxAge || age < -clockSkew {
				return deny(ReasonAttestationStale, "attestation verified at %s", a.VerifiedAt)
			}
			if a.KeyBinding == nil {
				return deny(ReasonKeyNotAttested, "attestation bound no node key")
			}
			if subtle.ConstantTimeCompare(a.KeyBinding, keyHash) != 1 {
				return deny(ReasonKeyBinding, "public key is not the one the attestation bound")
			}
			switch _, err := tx.NodeIdentityForAttestation(a.ID); {
			case err == nil:
				return deny(ReasonAlreadyIssued, "attestation %d already backs a node identity", a.ID)
			case !errors.Is(err, store.ErrNotFound):
				return err
			}
			iss, err := s.ca.Issue(IssueRequest{ID: sid, PublicKey: pub, TTL: s.nodeTTL})
			if err != nil {
				return err
			}
			rec := &store.Identity{Serial: iss.Serial, Kind: store.IdentityNode, SPIFFEID: sid.String(), NodeID: nodeID,
				AttestationID: a.ID, PublicKeyHash: keyHash}
			out, err = s.record(tx, now, actor, rec, iss, nil)
			return err
		})
	if err != nil {
		return nil, err
	}
	if denial != nil {
		return nil, denial
	}
	return out, nil
}

// checkAttestation requires a to be the node's latest attestation, to have
// passed under the current measurement policy, and the node to be enrolled.
func (s *Service) checkAttestation(tx *store.Tx, a *store.Attestation) error {
	n, err := tx.Node(a.NodeID)
	if err != nil {
		return err
	}
	if n.State != store.NodeEnrolled {
		return deny(ReasonNodeNotEnrolled, "node is %s", n.State)
	}
	latest, err := tx.LatestAttestation(a.NodeID)
	if err != nil {
		return err
	}
	if latest.ID != a.ID {
		return deny(ReasonAttestationSuperseded, "node attested again (attestation %d)", latest.ID)
	}
	if !a.Passed {
		return deny(ReasonAttestationFailed, "attestation %d failed: %s", a.ID, a.Reason)
	}
	m, err := tx.CurrentPolicy(store.PolicyMeasurement)
	if err != nil {
		// A passing attestation implies a measurement policy existed;
		// policies are append-only, so this is store corruption.
		return fmt.Errorf("identity: measurement policy: %w", err)
	}
	if m.Version != a.PolicyVersion {
		return deny(ReasonMeasurementPolicy, "attested under policy v%d, current is v%d", a.PolicyVersion, m.Version)
	}
	return nil
}

// update runs fn in a transaction. fn writes nothing before it decides, so
// a denial from fn is committed as an audit entry against object alone;
// any other error aborts the transaction.
func (s *Service) update(ctx context.Context, now time.Time, actor, object string, meta map[string]any,
	fn func(*store.Tx) error) (denial error, err error) {
	err = s.st.Update(ctx, func(tx *store.Tx) error {
		denial = nil
		err := fn(tx)
		r := ReasonOf(err)
		if r == "" {
			return err
		}
		denial = err
		m := map[string]any{"reason": r}
		for k, v := range meta {
			m[k] = v
		}
		return appendAudit(tx, now, actor, ActionIssueDenied, object, m)
	})
	if err != nil {
		return nil, err
	}
	return denial, nil
}

// record audits and stores an issued identity.
func (s *Service) record(tx *store.Tx, now time.Time, actor string, rec *store.Identity, iss *Issued,
	extra map[string]any) (*Identity, error) {
	ca := sha256.Sum256(s.ca.Cert().Raw)
	rec.Issuer = hex.EncodeToString(ca[:])
	rec.IssuedAt, rec.NotBefore, rec.NotAfter = now, iss.Cert.NotBefore, iss.Cert.NotAfter
	meta := map[string]any{"kind": rec.Kind, "spiffe_id": rec.SPIFFEID, "attestation": rec.AttestationID,
		"not_after": rec.NotAfter.UTC().Format(time.RFC3339), "public_key": hex.EncodeToString(rec.PublicKeyHash),
		"issuer": rec.Issuer}
	for k, v := range extra {
		if _, ok := meta[k]; !ok {
			meta[k] = v
		}
	}
	e, err := tx.AppendAudit(audit.Record{Time: now, Actor: actor, Action: ActionIssue, Object: "identity/" + rec.Serial,
		Metadata: mustJSON(meta)})
	if err != nil {
		return nil, err
	}
	rec.AuditSeq = e.Sequence
	if err := tx.InsertIdentity(rec); err != nil {
		return nil, err
	}
	id, err := parseURL(iss.Cert.URIs[0])
	if err != nil {
		return nil, err
	}
	return &Identity{ID: id, Cert: iss.Cert, Serial: iss.Serial, Bundle: s.ca.Bundle(), AuditSeq: e.Sequence}, nil
}

// spkiHash validates pub as an identity key and returns its SHA-256 SPKI
// digest, the form attestation key bindings use. An unusable key is a
// request error, not a denial.
func spkiHash(pub crypto.PublicKey) ([]byte, error) {
	if err := checkLeafKey(pub); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	h := sha256.Sum256(der)
	return h[:], nil
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func appendAudit(tx *store.Tx, now time.Time, actor, action, object string, meta map[string]any) error {
	_, err := tx.AppendAudit(audit.Record{Time: now, Actor: actor, Action: action, Object: object, Metadata: mustJSON(meta)})
	return err
}
