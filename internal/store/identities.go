package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// IdentityKind distinguishes node and workload identities.
type IdentityKind string

// Identity kinds.
const (
	IdentityNode     IdentityKind = "node"
	IdentityWorkload IdentityKind = "workload"
)

// Identity records one issued X.509 identity.
type Identity struct {
	Serial        string // 32 hex characters
	Kind          IdentityKind
	SPIFFEID      string
	NodeID        string
	Workload      string // empty for node identities
	ParentSerial  string // node identity a workload identity was issued under
	AttestationID int64
	PolicyVersion int64 // workload policy version; 0 for node identities
	PublicKeyHash []byte
	Issuer        string
	IssuedAt      time.Time
	NotBefore     time.Time
	NotAfter      time.Time
	RevokedAt     time.Time // zero if not revoked
	AuditSeq      uint64
}

// InsertIdentity records an issued identity.
func (t *Tx) InsertIdentity(id *Identity) error {
	_, err := t.exec(`INSERT INTO identity_records
		(serial, kind, spiffe_id, node_id, workload, parent_serial, attestation_id, policy_version,
		 public_key_hash, issuer, issued_at, not_before, not_after, audit_seq)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id.Serial, id.Kind, id.SPIFFEID, id.NodeID, nullString(id.Workload), nullString(id.ParentSerial),
		id.AttestationID, nullInt(id.PolicyVersion), id.PublicKeyHash, id.Issuer,
		id.IssuedAt.UnixNano(), id.NotBefore.UnixNano(), id.NotAfter.UnixNano(),
		int64(id.AuditSeq)) //nolint:gosec // audit seq <= MaxInt64
	if err != nil {
		return fmt.Errorf("store: insert identity: %w", err)
	}
	return nil
}

// RevokeIdentity marks an identity revoked. It returns ErrNotFound if the
// serial is unknown or already revoked.
func (t *Tx) RevokeIdentity(serial string, at time.Time) error {
	res, err := t.exec(`UPDATE identity_records SET revoked_at = ? WHERE serial = ? AND revoked_at IS NULL`,
		at.UnixNano(), serial)
	if err != nil {
		return fmt.Errorf("store: revoke identity: %w", err)
	}
	if ok, err := oneRow(res); err != nil || !ok {
		return notFound(sql.ErrNoRows, "live identity "+serial)
	}
	return nil
}

// Identity returns the identity with the given serial within the
// transaction.
func (t *Tx) Identity(serial string) (*Identity, error) { return getIdentity(t.ctx, t.tx, serial) }

// Identity returns the identity with the given serial.
func (s *Store) Identity(ctx context.Context, serial string) (*Identity, error) {
	return getIdentity(ctx, s.db, serial)
}

func getIdentity(ctx context.Context, q querier, serial string) (*Identity, error) {
	var (
		id                             Identity
		workload, parent               sql.NullString
		policy, revoked                sql.NullInt64
		issued, notBefore, notAfter, a int64
	)
	err := q.QueryRowContext(ctx, `SELECT serial, kind, spiffe_id, node_id, workload, parent_serial,
		attestation_id, policy_version, public_key_hash, issuer, issued_at, not_before, not_after,
		revoked_at, audit_seq FROM identity_records WHERE serial = ?`, serial).
		Scan(&id.Serial, &id.Kind, &id.SPIFFEID, &id.NodeID, &workload, &parent, &id.AttestationID,
			&policy, &id.PublicKeyHash, &id.Issuer, &issued, &notBefore, &notAfter, &revoked, &a)
	if err != nil {
		return nil, notFound(err, "identity "+serial)
	}
	id.Workload, id.ParentSerial, id.PolicyVersion = workload.String, parent.String, policy.Int64
	id.IssuedAt = time.Unix(0, issued).UTC()
	id.NotBefore = time.Unix(0, notBefore).UTC()
	id.NotAfter = time.Unix(0, notAfter).UTC()
	id.RevokedAt = fromNanos(revoked)
	id.AuditSeq = uint64(a) //nolint:gosec // schema: audit_seq > 0
	return &id, nil
}
