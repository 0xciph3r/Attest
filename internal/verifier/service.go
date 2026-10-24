package verifier

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"time"

	"github.com/0xciph3r/attest/internal/audit"
	"github.com/0xciph3r/attest/internal/policy"
	"github.com/0xciph3r/attest/internal/store"
	"github.com/0xciph3r/attest/internal/tpm"
)

// NonceSize is the size of attestation nonces.
const NonceSize = 32

// DefaultChallengeTTL bounds how long an attestation nonce can be answered.
const DefaultChallengeTTL = time.Minute

// Audit actions.
const (
	ActionPolicyApply  = "policy.apply"
	ActionAttest       = "node.attest"
	ActionAttestDenied = "node.attest.denied"
)

// ErrInvalidRequest is returned for syntactically invalid requests, which
// are refused before any state is read or written.
var ErrInvalidRequest = errors.New("verifier: invalid request")

var (
	challengeIDRe = regexp.MustCompile(`^att_[0-9a-f]{32}$`)
	nodeIDRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)
)

// ServiceConfig configures a Service.
type ServiceConfig struct {
	Store *store.Store
	// ChallengeTTL defaults to DefaultChallengeTTL.
	ChallengeTTL time.Duration
	// Now and Rand default to time.Now and crypto/rand.Reader.
	Now  func() time.Time
	Rand io.Reader
}

// Service issues attestation challenges, verifies the resulting evidence
// against enrolled keys and the current policy, and records every verdict.
type Service struct {
	st   *store.Store
	ttl  time.Duration
	now  func() time.Time
	rand io.Reader
}

// NewService returns an attestation service.
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Store == nil {
		return nil, errors.New("verifier: no store")
	}
	s := &Service{st: cfg.Store, ttl: cfg.ChallengeTTL, now: cfg.Now, rand: cfg.Rand}
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

// ApplyPolicy validates doc and makes it the current measurement policy.
func (s *Service) ApplyPolicy(ctx context.Context, actor string, doc []byte) (int64, error) {
	m, err := policy.ParseMeasurement(doc)
	if err != nil {
		return 0, err
	}
	now := s.now()
	var version int64
	err = s.st.Update(ctx, func(tx *store.Tx) error {
		var err error
		version, err = tx.InsertPolicy(&store.Policy{
			Kind: store.PolicyMeasurement, Document: doc, Digest: m.Digest(), CreatedAt: now, CreatedBy: actor,
		})
		if err != nil {
			return err
		}
		return appendAudit(tx, now, actor, ActionPolicyApply, fmt.Sprintf("policy/v%d", version), map[string]any{
			"kind": store.PolicyMeasurement, "digest": hex.EncodeToString(m.Digest()),
			"references": len(m.References), "allow_development_roots": m.AllowDevelopmentRoots,
		})
	})
	return version, err
}

// Challenge is a fresh attestation nonce for one node.
type Challenge struct {
	ID    string
	Nonce []byte
	// PCRs is the selection the quote must cover.
	PCRs      []uint32
	ExpiresAt time.Time
}

// Challenge issues a single-use nonce to an enrolled node. Only the nonce's
// hash is stored.
func (s *Service) Challenge(ctx context.Context, nodeID string) (*Challenge, error) {
	if !nodeIDRe.MatchString(nodeID) {
		return nil, ErrInvalidRequest
	}
	now := s.now()
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(s.rand, nonce); err != nil {
		return nil, fmt.Errorf("verifier: generating nonce: %w", err)
	}
	id, err := newID(s.rand, "att_")
	if err != nil {
		return nil, err
	}
	var pcrs []uint32
	err = s.st.Update(ctx, func(tx *store.Tx) error {
		n, err := tx.Node(nodeID)
		if errors.Is(err, store.ErrNotFound) {
			return fail(ReasonNodeUnknown, "node is not registered")
		} else if err != nil {
			return err
		}
		if n.State != store.NodeEnrolled {
			return fail(ReasonNodeNotEnrolled, "node is %s", n.State)
		}
		m, _, err := CurrentPolicy(tx)
		if err != nil {
			return err
		}
		pcrs = m.PCRs
		h := sha256.Sum256(nonce)
		return tx.InsertAttestChallenge(&store.AttestChallenge{
			ID: id, NodeID: nodeID, NonceHash: h[:], IssuedAt: now, ExpiresAt: now.Add(s.ttl),
		})
	})
	if err != nil {
		return nil, err
	}
	return &Challenge{ID: id, Nonce: nonce, PCRs: pcrs, ExpiresAt: now.Add(s.ttl)}, nil
}

// Verdict is a successful attestation.
type Verdict struct {
	AttestationID int64
	NodeID        string
	PolicyVersion int64
	Reference     string
	VerifiedAt    time.Time
	AuditSeq      uint64
	Development   bool
}

// Verify checks evidence answering challengeID. Any attempt against a live
// challenge consumes it, and the verdict, pass or fail, is recorded with an
// audit entry in the same transaction; if either write fails, nothing is
// recorded and the attempt is refused. Attempts against unknown or consumed
// challenges are audited only.
func (s *Service) Verify(ctx context.Context, nodeID, challengeID string, nonce []byte, ev *Evidence) (*Verdict, error) {
	if !challengeIDRe.MatchString(challengeID) || !nodeIDRe.MatchString(nodeID) || ev == nil {
		return nil, ErrInvalidRequest
	}
	now := s.now()
	actor := "node:" + nodeID
	var (
		verdict *Verdict
		denial  error
	)
	err := s.st.Update(ctx, func(tx *store.Tx) error {
		ch, err := tx.AttestChallenge(challengeID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			denial = fail(ReasonChallengeUnknown, "no such attestation challenge")
		case err != nil:
			return err
		case !ch.ConsumedAt.IsZero():
			denial = fail(ReasonChallengeConsumed, "attestation challenge already used")
		}
		if denial != nil {
			return appendAudit(tx, now, actor, ActionAttestDenied, "node/"+nodeID, map[string]any{
				"challenge": challengeID, "reason": ReasonOf(denial),
			})
		}
		if err := tx.ConsumeAttestChallenge(ch.ID, now); err != nil {
			return err
		}
		a := &store.Attestation{NodeID: ch.NodeID, ChallengeID: ch.ID, VerifiedAt: now, EvidenceHash: evidenceHash(nonce, ev)}
		v, err := s.verify(tx, now, nodeID, ch, nonce, ev, a)
		if ReasonOf(err) == "" && err != nil {
			return err
		}
		meta := map[string]any{"challenge": ch.ID, "policy_version": a.PolicyVersion}
		action := ActionAttest
		if err != nil {
			denial = err
			action = ActionAttestDenied
			a.Reason = string(ReasonOf(err))
			meta["reason"] = a.Reason
			if ch.NodeID != nodeID {
				meta["claimed_node"] = nodeID
			}
		} else {
			a.Passed = true
			meta["reference"] = a.Reference
			meta["development"] = v.Development
		}
		// The verdict is attributed to the node the challenge was issued to.
		e, err := tx.AppendAudit(audit.Record{Time: now, Actor: actor, Action: action, Object: "node/" + ch.NodeID,
			Metadata: mustJSON(meta)})
		if err != nil {
			return err
		}
		a.AuditSeq = e.Sequence
		id, err := tx.InsertAttestation(a)
		if err != nil {
			return err
		}
		if v != nil {
			v.AttestationID, v.AuditSeq = id, e.Sequence
			verdict = v
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if denial != nil {
		return nil, denial
	}
	return verdict, nil
}

// verify evaluates a consumed challenge, filling a with what was learned. A
// *Error is a denial; any other error aborts the transaction.
func (s *Service) verify(tx *store.Tx, now time.Time, nodeID string, ch *store.AttestChallenge,
	nonce []byte, ev *Evidence, a *store.Attestation) (*Verdict, error) {
	if ch.NodeID != nodeID {
		return nil, fail(ReasonChallengeWrongNode, "challenge was issued to another node")
	}
	if !now.Before(ch.ExpiresAt) {
		return nil, fail(ReasonChallengeExpired, "challenge expired at %s", ch.ExpiresAt)
	}
	h := sha256.Sum256(nonce)
	if len(nonce) != NonceSize || subtle.ConstantTimeCompare(h[:], ch.NonceHash) != 1 {
		return nil, fail(ReasonNonceMismatch, "nonce does not match the challenge")
	}
	n, err := tx.Node(ch.NodeID)
	if err != nil {
		return nil, err
	}
	if n.State != store.NodeEnrolled {
		return nil, fail(ReasonNodeNotEnrolled, "node is %s", n.State)
	}
	m, version, err := CurrentPolicy(tx)
	if err != nil {
		return nil, err
	}
	a.PolicyVersion = version
	if err := AdmitRoot(n.EKDevelopment, m); err != nil {
		return nil, err
	}
	ak, err := ParseAK(n.AKPublic)
	if err != nil {
		return nil, fmt.Errorf("verifier: stored AK for %s: %w", n.ID, err)
	}
	res, err := VerifyEvidence(ak, nonce, m, ev)
	if err != nil {
		return nil, err
	}
	a.Reference = res.Reference
	a.PCRDigest = tpm.PCRDigest(res.Quote.PCRs)
	a.ResetCount, a.RestartCount = int64(res.Quote.ResetCount), int64(res.Quote.RestartCount)
	return &Verdict{NodeID: n.ID, PolicyVersion: version, Reference: res.Reference, VerifiedAt: now,
		Development: n.EKDevelopment}, nil
}

// evidenceHash commits to everything the node submitted, so a recorded
// verdict can be matched to retained evidence.
func evidenceHash(nonce []byte, ev *Evidence) []byte {
	h := sha256.New()
	field := func(b []byte) {
		_ = binary.Write(h, binary.BigEndian, uint64(len(b)))
		h.Write(b)
	}
	field(nonce)
	field(ev.Attest)
	field(ev.Signature)
	_ = binary.Write(h, binary.BigEndian, uint64(len(ev.PCRs)))
	for _, k := range slices.Sorted(maps.Keys(ev.PCRs)) {
		_ = binary.Write(h, binary.BigEndian, k)
		field(ev.PCRs[k])
	}
	field(ev.EventLog)
	return h.Sum(nil)
}

func newID(r io.Reader, prefix string) (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", fmt.Errorf("verifier: generating ID: %w", err)
	}
	return prefix + hex.EncodeToString(b[:]), nil
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
