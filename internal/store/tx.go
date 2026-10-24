package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Errors returned by record accessors.
var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: conflicts with existing state")
	ErrConsumed = errors.New("store: challenge already consumed")
)

// Tx is a write transaction. State changes and the audit entries that
// describe them are committed together or not at all.
type Tx struct {
	ctx context.Context
	tx  *sql.Tx
}

// Update runs fn in a BEGIN IMMEDIATE transaction and commits it if fn
// returns nil. Any error rolls back every change, including audit entries.
func (s *Store) Update(ctx context.Context, fn func(*Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(&Tx{ctx: ctx, tx: tx}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

func (t *Tx) exec(query string, args ...any) (sql.Result, error) {
	res, err := t.tx.ExecContext(t.ctx, query, args...)
	return res, classify(err)
}

func (t *Tx) queryRow(query string, args ...any) *sql.Row {
	return t.tx.QueryRowContext(t.ctx, query, args...)
}

// classify maps constraint violations to ErrConflict.
func classify(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "constraint failed") {
		return fmt.Errorf("%w: %w", ErrConflict, err)
	}
	return err
}

func notFound(err error, what string) error {
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: %s", ErrNotFound, what)
	}
	return err
}

func oneRow(res sql.Result) (bool, error) {
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}
