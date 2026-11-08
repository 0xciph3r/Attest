package verifier

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

// A challenge ID is a random part and the challenge's expiry in Unix
// nanoseconds, hex encoded.
var challengeIDRe = regexp.MustCompile(`^att_[0-9a-f]{48}$`)

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
// against enrolled keys and the current policy, and records every verdict
// on evidence the node's TPM produced.
//
// Challenges are stateless: the nonce is a MAC, under a key held only in
// memory, of the node and the challenge ID, which carries the expiry. So
// issuing one writes nothing, and a restart invalidates every outstanding
// challenge. A challenge is stored only when it is consumed, which is what
// makes it single-use.
type Service struct {
	st   *store.Store
	ttl  time.Duration
	now  func() time.Time
	rand io.Reader
	key  []byte
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
	s.key = make([]byte, sha256.Size)
	if _, err := io.ReadFull(s.rand, s.key); err != nil {
		return nil, fmt.Errorf("verifier: generating challenge key: %w", err)
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

// Challenge issues a single-use nonce to an enrolled node. It writes
// nothing: the caller is not authenticated.
func (s *Service) Challenge(ctx context.Context, nodeID string) (*Challenge, error) {
	if !policy.ValidNodeID(nodeID) {
		return nil, ErrInvalidRequest
	}
	if _, err := s.enrolledNode(ctx, nodeID); err != nil {
		return nil, err
	}
	m, _, err := parseCurrent(s.st.CurrentPolicy(ctx, store.PolicyMeasurement))
	if err != nil {
		return nil, err
	}
	var b [24]byte
	if _, err := io.ReadFull(s.rand, b[:16]); err != nil {
		return nil, fmt.Errorf("verifier: generating challenge: %w", err)
	}
	expires := s.now().Add(s.ttl).Round(0)
	binary.BigEndian.PutUint64(b[16:], uint64(expires.UnixNano())) //nolint:gosec // after 1970
	id := "att_" + hex.EncodeToString(b[:])
	return &Challenge{ID: id, Nonce: s.nonce(nodeID, id), PCRs: m.PCRs, ExpiresAt: time.Unix(0, expires.UnixNano())}, nil
}

// nonce derives the nonce of challenge id for nodeID.
func (s *Service) nonce(nodeID, id string) []byte {
	m := hmac.New(sha256.New, s.key)
	// Node IDs and challenge IDs contain no NUL.
	m.Write([]byte("attest/v1/attestation-nonce\x00" + nodeID + "\x00" + id))
	return m.Sum(nil)
}

// challengeExpiry reads the expiry from a well-formed challenge ID.
func challengeExpiry(id string) time.Time {
	b, _ := hex.DecodeString(id[len(id)-16:])
	return time.Unix(0, int64(binary.BigEndian.Uint64(b))) //nolint:gosec // round-trips Challenge
}

func (s *Service) enrolledNode(ctx context.Context, nodeID string) (*store.Node, error) {
	n, err := s.st.Node(ctx, nodeID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fail(ReasonNodeUnknown, "node is not registered")
	} else if err != nil {
		return nil, err
	}
	if n.State != store.NodeEnrolled {
		return nil, fail(ReasonNodeNotEnrolled, "node is %s", n.State)
	}
	return n, nil
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
	// NodeKey is the TPM-resident key bound to this attestation, if the
	// node asked for one.
	NodeKey *NodeKey
}

// Verify checks evidence answering challengeID.
//
// Nothing is recorded until the evidence is shown to come from the node's
// TPM: the challenge must be live and issued to nodeID, and the quote signed
// by the node's enrolled AK over its nonce. Requests failing those checks
// can come from anyone, so they are refused without writing anything, the
// audit ledger included; otherwise anyone could grow the ledger, or record a
// failure that supersedes the node's last good attestation.
//
// Authenticated evidence consumes the challenge, and the verdict, pass or
// fail, is recorded with an audit entry in the same transaction; if either
// write fails, nothing is recorded and the attempt is refused. Evidence for
// a challenge already consumed is refused without a record.
func (s *Service) Verify(ctx context.Context, nodeID, challengeID string, nonce []byte, ev *Evidence) (*Verdict, error) {
	if !challengeIDRe.MatchString(challengeID) || !policy.ValidNodeID(nodeID) || ev == nil {
		return nil, ErrInvalidRequest
	}
	now := s.now()
	// A challenge issued to another node has a different nonce.
	if subtle.ConstantTimeCompare(nonce, s.nonce(nodeID, challengeID)) != 1 {
		return nil, fail(ReasonNonceMismatch, "nonce does not match the challenge")
	}
	expires := challengeExpiry(challengeID)
	if !now.Before(expires) {
		return nil, fail(ReasonChallengeExpired, "challenge expired at %s", expires)
	}
	n, err := s.enrolledNode(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	ak, err := ParseAK(n.AKPublic)
	if err != nil {
		return nil, fmt.Errorf("verifier: stored AK for %s: %w", n.ID, err)
	}
	if err := AuthenticateEvidence(ak, nonce, ev); err != nil {
		return nil, err
	}

	actor := "node:" + nodeID
	var (
		verdict *Verdict
		denial  error
	)
	err = s.st.Update(ctx, func(tx *store.Tx) error {
		switch _, err := tx.AttestChallenge(challengeID); {
		case err == nil:
			denial = fail(ReasonChallengeConsumed, "attestation challenge already used")
			return nil
		case !errors.Is(err, store.ErrNotFound):
			return err
		}
		h := sha256.Sum256(nonce)
		ch := &store.AttestChallenge{ID: challengeID, NodeID: nodeID, NonceHash: h[:],
			IssuedAt: expires.Add(-s.ttl), ExpiresAt: expires}
		if err := tx.InsertAttestChallenge(ch); err != nil {
			return err
		}
		if err := tx.ConsumeAttestChallenge(ch.ID, now); err != nil {
			return err
		}
		a := &store.Attestation{NodeID: ch.NodeID, ChallengeID: ch.ID, VerifiedAt: now, EvidenceHash: evidenceHash(nonce, ev)}
		v, err := s.verify(tx, now, ch, nonce, ev, a)
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
		} else {
			a.Passed = true
			meta["reference"] = a.Reference
			meta["development"] = v.Development
			if v.NodeKey != nil {
				meta["key_binding"] = hex.EncodeToString(v.NodeKey.SPKIHash)
			}
		}
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
// The node and its AK are read again here, under the write lock, so a
// concurrent revocation or re-enrollment is seen.
func (s *Service) verify(tx *store.Tx, now time.Time, ch *store.AttestChallenge,
	nonce []byte, ev *Evidence, a *store.Attestation) (*Verdict, error) {
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
	if res.NodeKey != nil {
		a.KeyBinding = res.NodeKey.SPKIHash
	}
	return &Verdict{NodeID: n.ID, PolicyVersion: version, Reference: res.Reference, VerifiedAt: now,
		Development: n.EKDevelopment, NodeKey: res.NodeKey}, nil
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
	// Absent key evidence leaves the hash of plain attestations unchanged;
	// present, it is length-delimited like every other field.
	if k := ev.NodeKey; k != nil {
		field(k.Public)
		field(k.Certify)
		field(k.CertifySignature)
	}
	return h.Sum(nil)
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
