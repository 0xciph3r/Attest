package store

import (
	"context"
	"fmt"
	"time"
)

// PolicyKind names a policy document type.
type PolicyKind string

// PolicyMeasurement is the measured-boot reference policy.
const PolicyMeasurement PolicyKind = "measurement"

// Policy is a stored policy version.
type Policy struct {
	Version   int64
	Kind      PolicyKind
	Document  []byte
	Digest    []byte
	CreatedAt time.Time
	CreatedBy string
}

// InsertPolicy appends a new policy version and returns its number.
func (t *Tx) InsertPolicy(p *Policy) (int64, error) {
	var v int64
	if err := t.queryRow(`SELECT COALESCE(MAX(version), 0) + 1 FROM policies`).Scan(&v); err != nil {
		return 0, fmt.Errorf("store: next policy version: %w", err)
	}
	if _, err := t.exec(`INSERT INTO policies (version, kind, document, digest, created_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?)`, v, p.Kind, p.Document, p.Digest, p.CreatedAt.UnixNano(), p.CreatedBy); err != nil {
		return 0, fmt.Errorf("store: insert policy: %w", err)
	}
	return v, nil
}

// CurrentPolicy returns the newest policy of kind within the transaction.
func (t *Tx) CurrentPolicy(kind PolicyKind) (*Policy, error) {
	return currentPolicy(t.ctx, t.tx, kind)
}

// CurrentPolicy returns the newest policy of kind.
func (s *Store) CurrentPolicy(ctx context.Context, kind PolicyKind) (*Policy, error) {
	return currentPolicy(ctx, s.db, kind)
}

func currentPolicy(ctx context.Context, q querier, kind PolicyKind) (*Policy, error) {
	var (
		p  Policy
		at int64
	)
	err := q.QueryRowContext(ctx, `SELECT version, kind, document, digest, created_at, created_by
		FROM policies WHERE kind = ? ORDER BY version DESC LIMIT 1`, kind).
		Scan(&p.Version, &p.Kind, &p.Document, &p.Digest, &at, &p.CreatedBy)
	if err != nil {
		return nil, notFound(err, "policy "+string(kind))
	}
	p.CreatedAt = time.Unix(0, at).UTC()
	return &p, nil
}
