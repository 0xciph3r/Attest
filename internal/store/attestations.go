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
	KeyBinding    []byte // SHA-256 of the key bound into the quote, if any
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
	var pcr, binding any
	if len(a.PCRDigest) > 0 {
		pcr = a.PCRDigest
	}
	if len(a.KeyBinding) > 0 {
		binding = a.KeyBinding
	}
	res, err := t.exec(`INSERT INTO attestations
		(node_id, challenge_id, verified_at, result, reason, policy_version, reference, pcr_digest,
		 reset_count, restart_count, evidence_hash, key_binding, audit_seq)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.NodeID, a.ChallengeID, a.VerifiedAt.UnixNano(), result, nullString(a.Reason), nullInt(a.PolicyVersion),
		nullString(a.Reference), pcr, a.ResetCount, a.RestartCount, a.EvidenceHash, binding, int64(a.AuditSeq)) //nolint:gosec // audit seq <= MaxInt64
	if err != nil {
		return 0, fmt.Errorf("store: insert attestation: %w", err)
	}
	return res.LastInsertId()
}

const attestationColumns = `id, node_id, challenge_id, verified_at, result, reason, policy_version,
	reference, pcr_digest, reset_count, restart_count, evidence_hash, key_binding, audit_seq`

// LatestAttestation returns the most recent attestation for a node.
func (s *Store) LatestAttestation(ctx context.Context, nodeID string) (*Attestation, error) {
	return scanAttestation(s.db.QueryRowContext(ctx, `SELECT `+attestationColumns+`
		FROM attestations WHERE node_id = ? ORDER BY id DESC LIMIT 1`, nodeID), "attestation for node "+nodeID)
}

// LatestAttestation returns the most recent attestation for a node within
// the transaction.
func (t *Tx) LatestAttestation(nodeID string) (*Attestation, error) {
	return scanAttestation(t.queryRow(`SELECT `+attestationColumns+`
		FROM attestations WHERE node_id = ? ORDER BY id DESC LIMIT 1`, nodeID), "attestation for node "+nodeID)
}

// Attestation returns the attestation with the given ID.
func (t *Tx) Attestation(id int64) (*Attestation, error) {
	return scanAttestation(t.queryRow(`SELECT `+attestationColumns+`
		FROM attestations WHERE id = ?`, id), fmt.Sprintf("attestation %d", id))
}

func scanAttestation(row scanner, what string) (*Attestation, error) {
	var (
		a                   Attestation
		verified, auditSeq  int64
		result              string
		reason, ref         sql.NullString
		policy, reset, rest sql.NullInt64
	)
	err := row.Scan(&a.ID, &a.NodeID, &a.ChallengeID, &verified, &result, &reason, &policy, &ref, &a.PCRDigest,
		&reset, &rest, &a.EvidenceHash, &a.KeyBinding, &auditSeq)
	if err != nil {
		return nil, notFound(err, what)
	}
	a.VerifiedAt = time.Unix(0, verified).UTC()
	a.Passed = result == "pass"
	a.Reason, a.Reference = reason.String, ref.String
	a.PolicyVersion, a.ResetCount, a.RestartCount = policy.Int64, reset.Int64, rest.Int64
	a.AuditSeq = uint64(auditSeq) //nolint:gosec // schema: audit_seq > 0
	return &a, nil
}
