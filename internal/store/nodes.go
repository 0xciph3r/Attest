package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// NodeState is a node's enrollment state.
type NodeState string

// Node states. Transitions: registered -> enrolled -> revoked, and
// registered -> revoked.
const (
	NodeRegistered NodeState = "registered"
	NodeEnrolled   NodeState = "enrolled"
	NodeRevoked    NodeState = "revoked"
)

// Node is a registered machine.
type Node struct {
	ID            string
	State         NodeState
	EKType        string
	EKCert        []byte // DER, as registered by the operator
	EKPublic      []byte // TPMT_PUBLIC derived from EKCert
	EKDigest      []byte // SHA-256 of EKPublic
	EKDevelopment bool
	AKPublic      []byte // TPMT_PUBLIC, set at enrollment
	AKName        []byte
	RegisteredBy  string
	RegisteredAt  time.Time
	EnrolledAt    time.Time
	RevokedAt     time.Time
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func fromNanos(n sql.NullInt64) time.Time {
	if !n.Valid {
		return time.Time{}
	}
	return time.Unix(0, n.Int64).UTC()
}

// InsertNode registers a node in state NodeRegistered.
func (t *Tx) InsertNode(n *Node) error {
	_, err := t.exec(`INSERT INTO nodes
		(id, state, ek_type, ek_cert, ek_public, ek_digest, ek_development, registered_by, registered_at)
		VALUES (?, 'registered', ?, ?, ?, ?, ?, ?, ?)`,
		n.ID, n.EKType, n.EKCert, n.EKPublic, n.EKDigest, n.EKDevelopment, n.RegisteredBy, n.RegisteredAt.UnixNano())
	if err != nil {
		return fmt.Errorf("store: insert node %q: %w", n.ID, err)
	}
	return nil
}

// EnrollNode records the node's AK and moves it to NodeEnrolled. It fails
// unless the node is currently registered.
func (t *Tx) EnrollNode(id string, akPublic, akName []byte, at time.Time) error {
	res, err := t.exec(`UPDATE nodes SET state = 'enrolled', ak_public = ?, ak_name = ?, enrolled_at = ?
		WHERE id = ? AND state = 'registered'`, akPublic, akName, at.UnixNano(), id)
	if err != nil {
		return fmt.Errorf("store: enroll node %q: %w", id, err)
	}
	if ok, err := oneRow(res); err != nil || !ok {
		return fmt.Errorf("%w: node %q is not awaiting enrollment", ErrConflict, id)
	}
	return nil
}

// RevokeNode moves a node to NodeRevoked.
func (t *Tx) RevokeNode(id string, at time.Time) error {
	res, err := t.exec(`UPDATE nodes SET state = 'revoked', revoked_at = ? WHERE id = ? AND state <> 'revoked'`,
		at.UnixNano(), id)
	if err != nil {
		return fmt.Errorf("store: revoke node %q: %w", id, err)
	}
	if ok, err := oneRow(res); err != nil || !ok {
		return fmt.Errorf("%w: node %q is unknown or already revoked", ErrNotFound, id)
	}
	return nil
}

// Node returns a node by ID within the transaction.
func (t *Tx) Node(id string) (*Node, error) { return getNode(t.ctx, t.tx, id) }

// Node returns a node by ID.
func (s *Store) Node(ctx context.Context, id string) (*Node, error) { return getNode(ctx, s.db, id) }

// Nodes lists all nodes ordered by ID.
func (s *Store) Nodes(ctx context.Context) ([]*Node, error) {
	rows, err := s.db.QueryContext(ctx, nodeSelect+` ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: list nodes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

const nodeSelect = `SELECT id, state, ek_type, ek_cert, ek_public, ek_digest, ek_development,
	ak_public, ak_name, registered_by, registered_at, enrolled_at, revoked_at FROM nodes`

type scanner interface{ Scan(dest ...any) error }

func scanNode(r scanner) (*Node, error) {
	var (
		n                 Node
		reg               int64
		enrolled, revoked sql.NullInt64
	)
	if err := r.Scan(&n.ID, &n.State, &n.EKType, &n.EKCert, &n.EKPublic, &n.EKDigest, &n.EKDevelopment,
		&n.AKPublic, &n.AKName, &n.RegisteredBy, &reg, &enrolled, &revoked); err != nil {
		return nil, err
	}
	n.RegisteredAt = time.Unix(0, reg).UTC()
	n.EnrolledAt = fromNanos(enrolled)
	n.RevokedAt = fromNanos(revoked)
	return &n, nil
}

func getNode(ctx context.Context, q querier, id string) (*Node, error) {
	n, err := scanNode(q.QueryRowContext(ctx, nodeSelect+` WHERE id = ?`, id))
	if err != nil {
		return nil, notFound(err, "node "+id)
	}
	return n, nil
}
