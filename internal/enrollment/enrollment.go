// Package enrollment registers nodes and proves that an attestation key lives
// in the TPM an operator approved.
//
// Enrollment establishes which key may attest for a node and nothing more: it
// grants no identity and no secret access. See docs/enrollment.md.
package enrollment

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/google/go-tpm/tpm2"

	"github.com/0xciph3r/attest/internal/audit"
	"github.com/0xciph3r/attest/internal/policy"
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
	ActionEnroll       = "node.enroll"
	ActionEnrollDenied = "node.enroll.denied"
	ActionRevoke       = "node.revoke"
)

// ErrInvalidNodeID is returned for node IDs outside the allowed syntax.
var ErrInvalidNodeID = errors.New("enrollment: node ID must match " + policy.NodeIDPattern)

// ErrInvalidChallengeID is returned for malformed challenge IDs.
var ErrInvalidChallengeID = errors.New("enrollment: malformed challenge ID")

// A challenge ID is 16 random bytes and the big-endian expiry in Unix
// nanoseconds.
var challengeIDRe = regexp.MustCompile(`^enr_[0-9a-f]{48}$`)

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
//
// Enrollment challenges are stateless: the activation secret is a MAC, under
// a key held only in memory, of the node, the challenge ID (which carries the
// expiry) and the AK name. Beginning enrollment writes nothing, and a restart
// invalidates every outstanding challenge. A challenge is stored only when a
// node proves it recovered the secret, which is what makes it single-use.
type Service struct {
	st    *store.Store
	roots verifier.EKRoots
	ttl   time.Duration
	now   func() time.Time
	rand  io.Reader
	key   []byte
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
	s.key = make([]byte, sha256.Size)
	if _, err := io.ReadFull(s.rand, s.key); err != nil {
		return nil, fmt.Errorf("enrollment: generating challenge key: %w", err)
	}
	return s, nil
}

// Register records operator approval of a machine identified by its EK
// certificate. The certificate must chain to a configured root; a
// development root is accepted only if the current measurement policy allows
// it. Registration is the only way a node record comes into existence.
func (s *Service) Register(ctx context.Context, actor, nodeID string, ekCert []byte) (*store.Node, error) {
	if !policy.ValidNodeID(nodeID) {
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
		if err := admitRoot(ek, txPolicy(tx)); err != nil {
			return err
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
//
// Begin writes nothing, the audit ledger included: the caller is not
// authenticated.
func (s *Service) Begin(ctx context.Context, nodeID string, akPublic []byte) (*Challenge, error) {
	if !policy.ValidNodeID(nodeID) {
		return nil, ErrInvalidNodeID
	}
	now := s.now()
	n, err := registeredNode(s.st.Node(ctx, nodeID))
	if err != nil {
		return nil, err
	}
	ak, err := parseAK(akPublic)
	if err != nil {
		return nil, err
	}
	ek, err := s.reverifyEK(n, now, storePolicy(ctx, s.st))
	if err != nil {
		return nil, err
	}
	kem, err := tpm2.ImportEncapsulationKey(&ek.Public)
	if err != nil {
		return nil, fmt.Errorf("enrollment: EK encapsulation key: %w", err)
	}
	var b [24]byte
	if _, err := io.ReadFull(s.rand, b[:16]); err != nil {
		return nil, fmt.Errorf("enrollment: generating challenge: %w", err)
	}
	expires := now.Add(s.ttl).Round(0)
	binary.BigEndian.PutUint64(b[16:], uint64(expires.UnixNano())) //nolint:gosec // after 1970
	id := "enr_" + hex.EncodeToString(b[:])
	blob, enc, err := tpm2.CreateCredential(s.rand, kem, ak.Name, s.secret(nodeID, id, ak.Name))
	if err != nil {
		return nil, fmt.Errorf("enrollment: creating credential: %w", err)
	}
	return &Challenge{ID: id, CredentialBlob: blob, EncryptedSecret: enc, ExpiresAt: time.Unix(0, expires.UnixNano())}, nil
}

// secret derives the activation secret of challenge id for nodeID's AK.
func (s *Service) secret(nodeID, id string, akName []byte) []byte {
	m := hmac.New(sha256.New, s.key)
	// Node IDs and challenge IDs contain no NUL; the AK name comes last.
	m.Write([]byte("attest/v1/enrollment-secret\x00" + nodeID + "\x00" + id + "\x00"))
	m.Write(akName)
	return m.Sum(nil)
}

// challengeExpiry reads the expiry from a well-formed challenge ID.
func challengeExpiry(id string) time.Time {
	b, _ := hex.DecodeString(id[len(id)-16:])
	return time.Unix(0, int64(binary.BigEndian.Uint64(b))) //nolint:gosec // round-trips Begin
}

// Complete finishes enrollment with the secret the node's TPM recovered for
// akPublic.
//
// Until the secret is shown to match, the caller could be anyone, so a
// wrong secret, an expired challenge or a malformed request is refused
// without writing anything. A correct secret consumes the challenge, and the
// outcome, enrolled or denied, is audited in the same transaction. A
// challenge already consumed is refused without a record.
func (s *Service) Complete(ctx context.Context, nodeID, challengeID string, akPublic, secret []byte) error {
	if !policy.ValidNodeID(nodeID) {
		return ErrInvalidNodeID
	}
	if !challengeIDRe.MatchString(challengeID) {
		return ErrInvalidChallengeID
	}
	now := s.now()
	ak, err := parseAK(akPublic)
	if err != nil {
		return err
	}
	// A challenge issued to another node or AK has a different secret.
	if subtle.ConstantTimeCompare(secret, s.secret(nodeID, challengeID, ak.Name)) != 1 {
		return verifier.Reject(verifier.ReasonActivationFailed, "recovered secret does not match")
	}
	expires := challengeExpiry(challengeID)
	if !now.Before(expires) {
		return verifier.Reject(verifier.ReasonChallengeExpired, "challenge expired at %s", expires)
	}

	actor := "node:" + nodeID
	var denial error
	err = s.st.Update(ctx, func(tx *store.Tx) error {
		switch _, err := tx.EnrollmentChallenge(challengeID); {
		case err == nil:
			denial = verifier.Reject(verifier.ReasonChallengeConsumed, "enrollment challenge already used")
			return nil
		case !errors.Is(err, store.ErrNotFound):
			return err
		}
		hash := sha256.Sum256(secret)
		ch := &store.EnrollmentChallenge{
			ID: challengeID, NodeID: nodeID, AKPublic: akPublic, AKName: ak.Name, SecretHash: hash[:],
			IssuedAt: expires.Add(-s.ttl), ExpiresAt: expires,
		}
		if err := tx.InsertEnrollmentChallenge(ch); err != nil {
			return err
		}
		if err := s.complete(tx, now, ch); verifier.ReasonOf(err) != "" {
			denial = err
		} else if err != nil {
			return err
		}
		if err := tx.ConsumeEnrollmentChallenge(ch.ID, now, denial == nil); err != nil {
			return err
		}
		if denial == nil {
			return appendAudit(tx, now, actor, ActionEnroll, nodeID, map[string]any{
				"challenge": challengeID, "ak_name": hex.EncodeToString(ch.AKName),
			})
		}
		return appendAudit(tx, now, actor, ActionEnrollDenied, nodeID, map[string]any{
			"challenge": challengeID, "reason": verifier.ReasonOf(denial),
		})
	})
	if err != nil {
		return err
	}
	return denial
}

// complete enrolls the node of an authenticated challenge, re-reading the
// node and its EK under the write lock. A verifier.Error is a denial; any
// other error aborts the transaction.
func (s *Service) complete(tx *store.Tx, now time.Time, ch *store.EnrollmentChallenge) error {
	n, err := registeredNode(tx.Node(ch.NodeID))
	if err != nil {
		return err
	}
	if _, err := s.reverifyEK(n, now, txPolicy(tx)); err != nil {
		return err
	}
	err = tx.EnrollNode(ch.NodeID, ch.AKPublic, ch.AKName, now)
	if errors.Is(err, store.ErrConflict) {
		return verifier.Reject(verifier.ReasonAKInUse, "AK is enrolled for another live node")
	}
	return err
}

func parseAK(akPublic []byte) (*verifier.AK, error) {
	if len(akPublic) > MaxAKSize {
		return nil, verifier.Reject(verifier.ReasonAKInvalid, "AK public area exceeds %d bytes", MaxAKSize)
	}
	return verifier.ParseAK(akPublic)
}

// Revoke permanently revokes a node. Re-admitting the machine requires a new
// registration.
func (s *Service) Revoke(ctx context.Context, actor, nodeID string) error {
	if !policy.ValidNodeID(nodeID) {
		return ErrInvalidNodeID
	}
	now := s.now()
	return s.st.Update(ctx, func(tx *store.Tx) error {
		if err := tx.RevokeNode(nodeID, now); err != nil {
			return err
		}
		return appendAudit(tx, now, actor, ActionRevoke, nodeID, nil)
	})
}

// registeredNode requires a loaded node to be awaiting enrollment.
func registeredNode(n *store.Node, err error) (*store.Node, error) {
	if errors.Is(err, store.ErrNotFound) {
		return nil, verifier.Reject(verifier.ReasonNodeUnknown, "node is not registered")
	}
	if err != nil {
		return nil, err
	}
	if n.State != store.NodeRegistered {
		return nil, verifier.Reject(verifier.ReasonNodeState, "node is %s, want %s", n.State, store.NodeRegistered)
	}
	return n, nil
}

// policyLoader loads the current measurement policy, only when needed.
type policyLoader func() (*policy.Measurement, error)

func txPolicy(tx *store.Tx) policyLoader {
	return func() (*policy.Measurement, error) {
		m, _, err := verifier.CurrentPolicy(tx)
		return m, err
	}
}

func storePolicy(ctx context.Context, st *store.Store) policyLoader {
	return func() (*policy.Measurement, error) {
		m, _, err := verifier.StoredPolicy(ctx, st)
		return m, err
	}
}

// admitRoot applies the development-root policy to ek.
func admitRoot(ek *verifier.EK, load policyLoader) error {
	if !ek.Development {
		return nil
	}
	m, err := load()
	if err != nil {
		return err
	}
	return verifier.AdmitRoot(true, m)
}

// reverifyEK re-validates the registered certificate (roots or validity may
// have changed since registration), confirms it still derives the registered
// EK and applies the development-root policy.
func (s *Service) reverifyEK(n *store.Node, now time.Time, load policyLoader) (*verifier.EK, error) {
	ek, err := verifier.VerifyEKCert(n.EKCert, s.roots, now)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(tpm2.Marshal(ek.Public))
	if subtle.ConstantTimeCompare(digest[:], n.EKDigest) != 1 {
		return nil, verifier.Reject(verifier.ReasonEKCertInvalid, "certificate no longer derives the registered EK")
	}
	if err := admitRoot(ek, load); err != nil {
		return nil, err
	}
	return ek, nil
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
