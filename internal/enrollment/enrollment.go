// Package enrollment registers nodes and proves that an attestation key lives
// in the TPM an operator approved.
//
// Enrollment establishes which key may attest for a node and nothing more: it
// grants no identity and no secret access. See docs/enrollment.md.
package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/google/go-tpm/tpm2"

	"github.com/0xciph3r/attest/internal/audit"
	"github.com/0xciph3r/attest/internal/store"
	"github.com/0xciph3r/attest/internal/verifier"
)

// Size limits for untrusted input.
const (
	MaxEKCertSize = 4096
	MaxAKSize     = 1024
	SecretSize    = 32
)

// DefaultChallengeTTL bounds how long a credential challenge can be answered.
const DefaultChallengeTTL = 2 * time.Minute

// Audit actions.
const (
	ActionRegister     = "node.register"
	ActionEnrollBegin  = "node.enroll.begin"
	ActionEnroll       = "node.enroll"
	ActionEnrollDenied = "node.enroll.denied"
	ActionRevoke       = "node.revoke"
)

// ErrInvalidNodeID is returned for node IDs outside the allowed syntax.
var ErrInvalidNodeID = errors.New("enrollment: node ID must match " + nodeIDPattern)

const nodeIDPattern = `^[a-z0-9][a-z0-9.-]{0,62}$`

var nodeIDRe = regexp.MustCompile(nodeIDPattern)

// ErrInvalidChallengeID is returned for malformed challenge IDs.
var ErrInvalidChallengeID = errors.New("enrollment: malformed challenge ID")

var challengeIDRe = regexp.MustCompile(`^enr_[0-9a-f]{32}$`)

// Config configures a Service.
type Config struct {
	Store *store.Store
	// Roots are the trusted EK certificate roots.
	Roots verifier.EKRoots
	// ChallengeTTL defaults to DefaultChallengeTTL.
	ChallengeTTL time.Duration
	// Now and Rand default to time.Now and crypto/rand.Reader.
	Now  func() time.Time
	Rand io.Reader
}

// Service implements node registration, enrollment and revocation.
type Service struct {
	st    *store.Store
	roots verifier.EKRoots
	ttl   time.Duration
	now   func() time.Time
	rand  io.Reader
}

// New returns an enrollment service.
func New(cfg Config) (*Service, error) {
	if cfg.Store == nil {
		return nil, errors.New("enrollment: no store")
	}
	s := &Service{st: cfg.Store, roots: cfg.Roots, ttl: cfg.ChallengeTTL, now: cfg.Now, rand: cfg.Rand}
	if s.ttl <= 0 {
		s.ttl = DefaultChallengeTTL
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.rand == nil {
		s.rand = rand.Reader
	}
	return s, nil
}

// Register records operator approval of a machine identified by its EK
// certificate. The certificate must chain to a configured root; a
// development root is accepted only if the current measurement policy allows
// it. Registration is the only way a node record comes into existence.
func (s *Service) Register(ctx context.Context, actor, nodeID string, ekCert []byte) (*store.Node, error) {
	if !nodeIDRe.MatchString(nodeID) {
		return nil, ErrInvalidNodeID
	}
	if len(ekCert) > MaxEKCertSize {
		return nil, verifier.Reject(verifier.ReasonEKCertInvalid, "certificate exceeds %d bytes", MaxEKCertSize)
	}
	now := s.now()
	ek, err := verifier.VerifyEKCert(ekCert, s.roots, now)
	if err != nil {
		return nil, err
	}
	ekPub := tpm2.Marshal(ek.Public)
	ekDigest := sha256.Sum256(ekPub)
	n := &store.Node{
		ID: nodeID, State: store.NodeRegistered, EKType: string(ek.Type),
		EKCert: ekCert, EKPublic: ekPub, EKDigest: ekDigest[:], EKDevelopment: ek.Development,
		RegisteredBy: actor, RegisteredAt: now,
	}
	err = s.st.Update(ctx, func(tx *store.Tx) error {
		if ek.Development {
			m, _, err := verifier.CurrentPolicy(tx)
			if err != nil {
				return err
			}
			if err := verifier.AdmitRoot(true, m); err != nil {
				return err
			}
		}
		if err := tx.InsertNode(n); err != nil {
			return err
		}
		return appendAudit(tx, now, actor, ActionRegister, nodeID, map[string]any{
			"ek_type": ek.Type, "ek_digest": hex.EncodeToString(ekDigest[:]), "ek_development": ek.Development,
		})
	})
	if err != nil {
		return nil, err
	}
	return n, nil
}

// Challenge is a credential-activation challenge for the node's TPM.
type Challenge struct {
	ID              string
	CredentialBlob  []byte
	EncryptedSecret []byte
	ExpiresAt       time.Time
}

// Begin starts enrollment of a registered node's attestation key. The secret
// is encrypted to the EK derived from the registered certificate and bound to
// the AK name computed here, so only the approved TPM holding that AK can
// recover it. Nothing the node supplies about its EK is trusted.
func (s *Service) Begin(ctx context.Context, nodeID string, akPublic []byte) (*Challenge, error) {
	if !nodeIDRe.MatchString(nodeID) {
		return nil, ErrInvalidNodeID
	}
	now := s.now()
	actor := "node:" + nodeID
	var ch *Challenge
	var denial error
	err := s.st.Update(ctx, func(tx *store.Tx) error {
		c, err := s.begin(tx, now, nodeID, akPublic)
		if verifier.ReasonOf(err) == "" {
			if err != nil {
				return err
			}
			ch = c
			return appendAudit(tx, now, actor, ActionEnrollBegin, nodeID, map[string]any{"challenge": c.ID})
		}
		denial = err
		return appendAudit(tx, now, actor, ActionEnrollDenied, nodeID, map[string]any{
			"stage": "begin", "reason": verifier.ReasonOf(err),
		})
	})
	if err != nil {
		return nil, err
	}
	if denial != nil {
		return nil, denial
	}
	return ch, nil
}

func (s *Service) begin(tx *store.Tx, now time.Time, nodeID string, akPublic []byte) (*Challenge, error) {
	n, err := registeredNode(tx, nodeID, store.NodeRegistered)
	if err != nil {
		return nil, err
	}
	if len(akPublic) > MaxAKSize {
		return nil, verifier.Reject(verifier.ReasonAKInvalid, "AK public area exceeds %d bytes", MaxAKSize)
	}
	ak, err := verifier.ParseAK(akPublic)
	if err != nil {
		return nil, err
	}
	ek, err := s.reverifyEK(tx, n, now)
	if err != nil {
		return nil, err
	}
	kem, err := tpm2.ImportEncapsulationKey(&ek.Public)
	if err != nil {
		return nil, fmt.Errorf("enrollment: EK encapsulation key: %w", err)
	}
	secret := make([]byte, SecretSize)
	if _, err := io.ReadFull(s.rand, secret); err != nil {
		return nil, fmt.Errorf("enrollment: generating secret: %w", err)
	}
	blob, enc, err := tpm2.CreateCredential(s.rand, kem, ak.Name, secret)
	if err != nil {
		return nil, fmt.Errorf("enrollment: creating credential: %w", err)
	}
	id, err := newID(s.rand, "enr_")
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(secret)
	c := &store.EnrollmentChallenge{
		ID: id, NodeID: nodeID, AKPublic: akPublic, AKName: ak.Name, SecretHash: hash[:],
		IssuedAt: now, ExpiresAt: now.Add(s.ttl),
	}
	if err := tx.InsertEnrollmentChallenge(c); err != nil {
		return nil, err
	}
	return &Challenge{ID: id, CredentialBlob: blob, EncryptedSecret: enc, ExpiresAt: c.ExpiresAt}, nil
}

// Complete finishes enrollment with the secret the node's TPM recovered. A
// challenge admits exactly one attempt: it is consumed whatever the outcome,
// and the outcome is audited in the same transaction.
func (s *Service) Complete(ctx context.Context, nodeID, challengeID string, secret []byte) error {
	if !nodeIDRe.MatchString(nodeID) {
		return ErrInvalidNodeID
	}
	if !challengeIDRe.MatchString(challengeID) {
		return ErrInvalidChallengeID
	}
	now := s.now()
	actor := "node:" + nodeID
	var denial error
	err := s.st.Update(ctx, func(tx *store.Tx) error {
		ch, err := tx.EnrollmentChallenge(challengeID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			denial = verifier.Reject(verifier.ReasonChallengeUnknown, "no such enrollment challenge")
		case err != nil:
			return err
		case !ch.ConsumedAt.IsZero():
			denial = verifier.Reject(verifier.ReasonChallengeConsumed, "enrollment challenge already used")
		default:
			if err := s.complete(tx, now, nodeID, ch, secret); verifier.ReasonOf(err) != "" {
				denial = err
			} else if err != nil {
				return err
			}
			if err := tx.ConsumeEnrollmentChallenge(ch.ID, now, denial == nil); err != nil {
				return err
			}
		}
		if denial == nil {
			return appendAudit(tx, now, actor, ActionEnroll, nodeID, map[string]any{
				"challenge": challengeID, "ak_name": hex.EncodeToString(ch.AKName),
			})
		}
		return appendAudit(tx, now, actor, ActionEnrollDenied, nodeID, map[string]any{
			"stage": "complete", "challenge": challengeID, "reason": verifier.ReasonOf(denial),
		})
	})
	if err != nil {
		return err
	}
	return denial
}

// complete checks an unconsumed challenge and enrolls the node. A
// verifier.Error is a denial; any other error aborts the transaction.
func (s *Service) complete(tx *store.Tx, now time.Time, nodeID string, ch *store.EnrollmentChallenge, secret []byte) error {
	if ch.NodeID != nodeID {
		return verifier.Reject(verifier.ReasonChallengeWrongNode, "challenge was issued to another node")
	}
	if !now.Before(ch.ExpiresAt) {
		return verifier.Reject(verifier.ReasonChallengeExpired, "challenge expired at %s", ch.ExpiresAt)
	}
	n, err := registeredNode(tx, nodeID, store.NodeRegistered)
	if err != nil {
		return err
	}
	if _, err := s.reverifyEK(tx, n, now); err != nil {
		return err
	}
	got := sha256.Sum256(secret)
	if len(secret) != SecretSize || subtle.ConstantTimeCompare(got[:], ch.SecretHash) != 1 {
		return verifier.Reject(verifier.ReasonActivationFailed, "recovered secret does not match")
	}
	err = tx.EnrollNode(nodeID, ch.AKPublic, ch.AKName, now)
	if errors.Is(err, store.ErrConflict) {
		return verifier.Reject(verifier.ReasonAKInUse, "AK is enrolled for another live node")
	}
	return err
}

// Revoke permanently revokes a node. Re-admitting the machine requires a new
// registration.
func (s *Service) Revoke(ctx context.Context, actor, nodeID string) error {
	now := s.now()
	return s.st.Update(ctx, func(tx *store.Tx) error {
		if err := tx.RevokeNode(nodeID, now); err != nil {
			return err
		}
		return appendAudit(tx, now, actor, ActionRevoke, nodeID, nil)
	})
}

// registeredNode loads nodeID and requires it to be in state want.
func registeredNode(tx *store.Tx, nodeID string, want store.NodeState) (*store.Node, error) {
	n, err := tx.Node(nodeID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, verifier.Reject(verifier.ReasonNodeUnknown, "node is not registered")
	}
	if err != nil {
		return nil, err
	}
	if n.State != want {
		return nil, verifier.Reject(verifier.ReasonNodeState, "node is %s, want %s", n.State, want)
	}
	return n, nil
}

// reverifyEK re-validates the registered certificate (roots or validity may
// have changed since registration), confirms it still derives the registered
// EK and applies the development-root policy.
func (s *Service) reverifyEK(tx *store.Tx, n *store.Node, now time.Time) (*verifier.EK, error) {
	ek, err := verifier.VerifyEKCert(n.EKCert, s.roots, now)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(tpm2.Marshal(ek.Public))
	if subtle.ConstantTimeCompare(digest[:], n.EKDigest) != 1 {
		return nil, verifier.Reject(verifier.ReasonEKCertInvalid, "certificate no longer derives the registered EK")
	}
	if ek.Development {
		m, _, err := verifier.CurrentPolicy(tx)
		if err != nil {
			return nil, err
		}
		if err := verifier.AdmitRoot(true, m); err != nil {
			return nil, err
		}
	}
	return ek, nil
}

func newID(r io.Reader, prefix string) (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", fmt.Errorf("enrollment: generating ID: %w", err)
	}
	return prefix + hex.EncodeToString(b[:]), nil
}

func appendAudit(tx *store.Tx, now time.Time, actor, action, nodeID string, meta map[string]any) error {
	var md []byte
	if meta != nil {
		var err error
		if md, err = json.Marshal(meta); err != nil {
			return err
		}
	}
	_, err := tx.AppendAudit(audit.Record{Time: now, Actor: actor, Action: action, Object: "node/" + nodeID, Metadata: md})
	return err
}
