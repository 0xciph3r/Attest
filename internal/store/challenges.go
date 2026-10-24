package store

import (
	"database/sql"
	"fmt"
	"time"
)

// EnrollmentChallenge is an outstanding credential-activation challenge.
type EnrollmentChallenge struct {
	ID         string
	NodeID     string
	AKPublic   []byte
	AKName     []byte
	SecretHash []byte
	IssuedAt   time.Time
	ExpiresAt  time.Time
	ConsumedAt time.Time
}

// InsertEnrollmentChallenge stores a new enrollment challenge.
func (t *Tx) InsertEnrollmentChallenge(c *EnrollmentChallenge) error {
	_, err := t.exec(`INSERT INTO enrollment_challenges
		(id, node_id, ak_public, ak_name, secret_hash, issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.NodeID, c.AKPublic, c.AKName, c.SecretHash, c.IssuedAt.UnixNano(), c.ExpiresAt.UnixNano())
	if err != nil {
		return fmt.Errorf("store: insert enrollment challenge: %w", err)
	}
	return nil
}

// EnrollmentChallenge loads an enrollment challenge.
func (t *Tx) EnrollmentChallenge(id string) (*EnrollmentChallenge, error) {
	var (
		c               EnrollmentChallenge
		issued, expires int64
		consumed        sql.NullInt64
	)
	err := t.queryRow(`SELECT id, node_id, ak_public, ak_name, secret_hash, issued_at, expires_at, consumed_at
		FROM enrollment_challenges WHERE id = ?`, id).
		Scan(&c.ID, &c.NodeID, &c.AKPublic, &c.AKName, &c.SecretHash, &issued, &expires, &consumed)
	if err != nil {
		return nil, notFound(err, "enrollment challenge")
	}
	c.IssuedAt, c.ExpiresAt, c.ConsumedAt = time.Unix(0, issued).UTC(), time.Unix(0, expires).UTC(), fromNanos(consumed)
	return &c, nil
}

// ConsumeEnrollmentChallenge marks the challenge used. It returns
// ErrConsumed if it was already used.
func (t *Tx) ConsumeEnrollmentChallenge(id string, at time.Time, success bool) error {
	outcome := "failure"
	if success {
		outcome = "success"
	}
	res, err := t.exec(`UPDATE enrollment_challenges SET consumed_at = ?, outcome = ?
		WHERE id = ? AND consumed_at IS NULL`, at.UnixNano(), outcome, id)
	if err != nil {
		return fmt.Errorf("store: consume enrollment challenge: %w", err)
	}
	if ok, err := oneRow(res); err != nil || !ok {
		return ErrConsumed
	}
	return nil
}

// AttestChallenge is an outstanding attestation nonce.
type AttestChallenge struct {
	ID         string
	NodeID     string
	NonceHash  []byte
	IssuedAt   time.Time
	ExpiresAt  time.Time
	ConsumedAt time.Time
}

// InsertAttestChallenge stores a new attestation challenge.
func (t *Tx) InsertAttestChallenge(c *AttestChallenge) error {
	_, err := t.exec(`INSERT INTO attest_challenges (id, node_id, nonce_hash, issued_at, expires_at)
		VALUES (?, ?, ?, ?, ?)`, c.ID, c.NodeID, c.NonceHash, c.IssuedAt.UnixNano(), c.ExpiresAt.UnixNano())
	if err != nil {
		return fmt.Errorf("store: insert attestation challenge: %w", err)
	}
	return nil
}

// AttestChallenge loads an attestation challenge.
func (t *Tx) AttestChallenge(id string) (*AttestChallenge, error) {
	var (
		c               AttestChallenge
		issued, expires int64
		consumed        sql.NullInt64
	)
	err := t.queryRow(`SELECT id, node_id, nonce_hash, issued_at, expires_at, consumed_at
		FROM attest_challenges WHERE id = ?`, id).
		Scan(&c.ID, &c.NodeID, &c.NonceHash, &issued, &expires, &consumed)
	if err != nil {
		return nil, notFound(err, "attestation challenge")
	}
	c.IssuedAt, c.ExpiresAt, c.ConsumedAt = time.Unix(0, issued).UTC(), time.Unix(0, expires).UTC(), fromNanos(consumed)
	return &c, nil
}

// ConsumeAttestChallenge marks the challenge used. It returns ErrConsumed
// if it was already used.
func (t *Tx) ConsumeAttestChallenge(id string, at time.Time) error {
	res, err := t.exec(`UPDATE attest_challenges SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL`,
		at.UnixNano(), id)
	if err != nil {
		return fmt.Errorf("store: consume attestation challenge: %w", err)
	}
	if ok, err := oneRow(res); err != nil || !ok {
		return ErrConsumed
	}
	return nil
}
