package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Attestation is the recorded outcome of one attestation challenge.
type Attestation struct {
	ID            int64
	NodeID        string
	ChallengeID   string
	VerifiedAt    time.Time
	Passed        bool
	Reason        string // empty when Passed
	PolicyVersion int64  // 0 if no policy was evaluated
	Reference     string
	PCRDigest     []byte
	ResetCount    int64
	RestartCount  int64
	EvidenceHash  []byte
	AuditSeq      uint64
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

// InsertAttestation records an attestation outcome.
func (t *Tx) InsertAttestation(a *Attestation) (int64, error) {
	result := "fail"
	if a.Passed {
		result = "pass"
	}
	var pcr any
	if len(a.PCRDigest) > 0 {
		pcr = a.PCRDigest
	}
	res, err := t.exec(`INSERT INTO attestations
		(node_id, challenge_id, verified_at, result, reason, policy_version, reference, pcr_digest,
		 reset_count, restart_count, evidence_hash, audit_seq)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.NodeID, a.ChallengeID, a.VerifiedAt.UnixNano(), result, nullString(a.Reason), nullInt(a.PolicyVersion),
		nullString(a.Reference), pcr, a.ResetCount, a.RestartCount, a.EvidenceHash, int64(a.AuditSeq)) //nolint:gosec // audit seq <= MaxInt64
	if err != nil {
		return 0, fmt.Errorf("store: insert attestation: %w", err)
	}
	return res.LastInsertId()
}

// LatestAttestation returns the most recent attestation for a node.
func (s *Store) LatestAttestation(ctx context.Context, nodeID string) (*Attestation, error) {
	var (
		a                   Attestation
		verified, auditSeq  int64
		result              string
		reason, ref         sql.NullString
		policy, reset, rest sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx, `SELECT id, node_id, challenge_id, verified_at, result, reason,
		policy_version, reference, pcr_digest, reset_count, restart_count, evidence_hash, audit_seq
		FROM attestations WHERE node_id = ? ORDER BY id DESC LIMIT 1`, nodeID).
		Scan(&a.ID, &a.NodeID, &a.ChallengeID, &verified, &result, &reason, &policy, &ref, &a.PCRDigest,
			&reset, &rest, &a.EvidenceHash, &auditSeq)
	if err != nil {
		return nil, notFound(err, "attestation for node "+nodeID)
	}
	a.VerifiedAt = time.Unix(0, verified).UTC()
	a.Passed = result == "pass"
	a.Reason, a.Reference = reason.String, ref.String
	a.PolicyVersion, a.ResetCount, a.RestartCount = policy.Int64, reset.Int64, rest.Int64
	a.AuditSeq = uint64(auditSeq) //nolint:gosec // schema: audit_seq > 0
	return &a, nil
}
