package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"iter"
	"math"
	"time"

	"github.com/0xciph3r/attest/internal/audit"
)

// AppendAudit atomically extends the audit chain with rec and returns the
// stored entry. Callers performing a security-sensitive operation must treat
// an error here as a failure of that operation (fail closed).
func (s *Store) AppendAudit(ctx context.Context, rec audit.Record) (audit.Entry, error) {
	var e audit.Entry
	err := s.Update(ctx, func(tx *Tx) error {
		var err error
		e, err = tx.AppendAudit(rec)
		return err
	})
	return e, err
}

// AppendAudit extends the audit chain within the transaction.
func (t *Tx) AppendAudit(rec audit.Record) (audit.Entry, error) {
	head, err := auditHead(t.ctx, t.tx)
	if err != nil {
		return audit.Entry{}, err
	}
	e, err := audit.Next(head, rec)
	if err != nil {
		return audit.Entry{}, err
	}
	if e.Sequence > math.MaxInt64 {
		return audit.Entry{}, errors.New("store: audit sequence exhausted")
	}
	var metadata any
	if len(e.Metadata) > 0 {
		metadata = e.Metadata
	}
	if _, err := t.tx.ExecContext(t.ctx, `INSERT INTO audit_entries
		(seq, recorded_at, actor, action, object, metadata, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		int64(e.Sequence), e.Time.UnixNano(), e.Actor, e.Action, e.Object, metadata, e.PrevHash[:], e.Hash[:]); err != nil {
		return audit.Entry{}, fmt.Errorf("store: insert audit entry: %w", err)
	}
	return e, nil
}

// AuditHead returns the current head of the audit chain.
func (s *Store) AuditHead(ctx context.Context) (audit.Head, error) {
	return auditHead(ctx, s.db)
}

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func auditHead(ctx context.Context, q queryer) (audit.Head, error) {
	var (
		seq  int64
		hash []byte
	)
	err := q.QueryRowContext(ctx, `SELECT seq, hash FROM audit_entries ORDER BY seq DESC LIMIT 1`).Scan(&seq, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return audit.Head{}, nil
	}
	if err != nil {
		return audit.Head{}, fmt.Errorf("store: read audit head: %w", err)
	}
	if seq <= 0 {
		return audit.Head{}, fmt.Errorf("store: audit head has invalid sequence %d", seq)
	}
	h, err := audit.HashFromBytes(hash)
	if err != nil {
		return audit.Head{}, fmt.Errorf("store: audit head: %w", err)
	}
	return audit.Head{Sequence: uint64(seq), Hash: h}, nil
}

// AuditEntries streams the audit ledger in sequence order. The iterator
// stops at the first error, which it yields.
func (s *Store) AuditEntries(ctx context.Context) iter.Seq2[audit.Entry, error] {
	return func(yield func(audit.Entry, error) bool) {
		rows, err := s.db.QueryContext(ctx, `SELECT seq, recorded_at, actor, action, object, metadata, prev_hash, hash
			FROM audit_entries ORDER BY seq`)
		if err != nil {
			yield(audit.Entry{}, fmt.Errorf("store: query audit entries: %w", err))
			return
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var (
				seq, nanos int64
				e          audit.Entry
				prev, hash []byte
				metadata   []byte
			)
			if err := rows.Scan(&seq, &nanos, &e.Actor, &e.Action, &e.Object, &metadata, &prev, &hash); err != nil {
				yield(audit.Entry{}, fmt.Errorf("store: scan audit entry: %w", err))
				return
			}
			// The schema forbids seq <= 0, but a tampered database need not
			// honour the schema.
			if seq <= 0 {
				yield(audit.Entry{}, fmt.Errorf("store: audit entry has invalid sequence %d", seq))
				return
			}
			e.Sequence = uint64(seq)
			e.Time = time.Unix(0, nanos).UTC()
			if len(metadata) > 0 {
				e.Metadata = metadata
			}
			if e.PrevHash, err = audit.HashFromBytes(prev); err != nil {
				yield(audit.Entry{}, fmt.Errorf("store: audit entry %d prev_hash: %w", seq, err))
				return
			}
			if e.Hash, err = audit.HashFromBytes(hash); err != nil {
				yield(audit.Entry{}, fmt.Errorf("store: audit entry %d hash: %w", seq, err))
				return
			}
			if !yield(e, nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(audit.Entry{}, fmt.Errorf("store: iterate audit entries: %w", err))
		}
	}
}
