// Package store persists Attest control-plane state in SQLite.
//
// The MVP runs a single control-plane instance. Writes are serialized with
// BEGIN IMMEDIATE transactions so that read-modify-write sequences such as
// extending the audit chain cannot interleave.
package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"modernc.org/sqlite" // registers the "sqlite" driver
	sqlite3 "modernc.org/sqlite/lib"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// ErrSchemaTooNew is returned when the database was migrated by a newer
// version of Attest. Running an older binary against it could silently ignore
// newer security state, so the store refuses to open it.
var ErrSchemaTooNew = errors.New("store: database schema is newer than this binary supports")

// ErrSchemaOutdated is returned when a read-only open finds unapplied
// migrations.
var ErrSchemaOutdated = errors.New("store: database schema is older than this binary expects")

// ErrSchemaHistory is returned when the recorded migrations are not a
// contiguous prefix of this binary's migrations, so the schema did not come
// from this code.
var ErrSchemaHistory = errors.New("store: database migration history does not match this binary")

// Store is a handle to the control-plane database.
type Store struct {
	db *sql.DB
}

// Open opens (creating if necessary) the database at path and applies any
// pending migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	if err := checkPath(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrateRetryingBusy(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// openBusyTimeout bounds how long Open waits for another process that is
// creating or migrating the same database.
const openBusyTimeout = 10 * time.Second

// migrateRetryingBusy runs migrate, retrying while SQLite reports the
// database busy. When several processes open a new database at once, WAL
// initialisation can fail with SQLITE_BUSY without consulting the busy
// timeout. Each attempt is transactional, so retrying is safe.
func (s *Store) migrateRetryingBusy(ctx context.Context) error {
	deadline := time.Now().Add(openBusyTimeout)
	for delay := time.Millisecond; ; delay = min(2*delay, 100*time.Millisecond) {
		err := s.migrate(ctx)
		var se *sqlite.Error
		if err == nil || !errors.As(err, &se) || se.Code()&0xff != sqlite3.SQLITE_BUSY || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(delay):
		}
	}
}

// OpenReadOnly opens an existing database without modifying it. It is used by
// offline verification, which must not alter the evidence it inspects.
func OpenReadOnly(ctx context.Context, path string) (*Store, error) {
	if err := checkPath(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn(path, true))
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.checkSchema(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// checkPath rejects names SQLite would open as a temporary or in-memory
// database: the control plane's state must survive a restart.
func checkPath(path string) error {
	if path == "" || path == ":memory:" || strings.HasPrefix(path, "file:") {
		return fmt.Errorf("store: %q is not a database file path", path)
	}
	return nil
}

// uriEscaper escapes the characters that would otherwise end the path in a
// SQLite URI filename and let it carry its own query parameters, such as
// "x.db?_pragma=foreign_keys(0)" or "x.db?mode=rw".
var uriEscaper = strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23")

func dsn(path string, readOnly bool) string {
	q := url.Values{}
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	// Make REPLACE conflict resolution fire DELETE triggers, so it cannot
	// remove rows the triggers protect (see migration 0004).
	q.Add("_pragma", "recursive_triggers(1)")
	if readOnly {
		q.Set("mode", "ro")
	} else {
		q.Add("_pragma", "journal_mode(WAL)")
		q.Add("_pragma", "synchronous(FULL)")
		q.Set("_txlock", "immediate")
	}
	return "file:" + uriEscaper.Replace(path) + "?" + q.Encode()
}

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations() ([]migration, error) {
	files, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		return nil, err
	}
	var ms []migration
	for _, f := range files {
		base := strings.TrimPrefix(f, "migrations/")
		prefix, _, ok := strings.Cut(base, "_")
		if !ok {
			return nil, fmt.Errorf("store: migration %s lacks a version prefix", base)
		}
		v, err := strconv.Atoi(prefix)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("store: migration %s has invalid version", base)
		}
		body, err := migrationFS.ReadFile(f)
		if err != nil {
			return nil, err
		}
		ms = append(ms, migration{version: v, name: base, sql: string(body)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	for i, m := range ms {
		if m.version != i+1 {
			return nil, fmt.Errorf("store: migrations must be numbered contiguously from 1; found %s", m.name)
		}
	}
	return ms, nil
}

func (s *Store) migrate(ctx context.Context) error {
	ms, err := loadMigrations()
	if err != nil {
		return err
	}
	// An immediate transaction takes the write lock up front; an autocommit
	// statement would upgrade a read lock, which SQLite refuses with BUSY
	// instead of waiting when another connection is migrating.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		name       TEXT    NOT NULL,
		applied_at INTEGER NOT NULL
	) STRICT`); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}
	current, err := schemaHistory(ctx, s.db, ms)
	if err != nil {
		return err
	}
	for _, m := range ms[current:] {
		if err := s.apply(ctx, m); err != nil {
			return err
		}
	}
	return nil
}

// foreignKeysOff marks a migration that rebuilds a table referenced by
// foreign keys. SQLite cannot change a table's constraints in place, and
// dropping a parent table with enforcement on would fail, so such
// migrations follow SQLite's documented procedure: disable enforcement on a
// dedicated connection, rebuild inside a transaction, and require
// PRAGMA foreign_key_check to pass before committing.
const foreignKeysOff = "-- attest:foreign-keys-off\n"

func (s *Store) apply(ctx context.Context, m migration) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if strings.HasPrefix(m.sql, foreignKeysOff) {
		if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
			return fmt.Errorf("store: apply %s: %w", m.name, err)
		}
		defer func() {
			// Never return a connection without enforcement to the pool.
			if _, err := conn.ExecContext(context.Background(), `PRAGMA foreign_keys = ON`); err != nil {
				_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			}
		}()
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// The transaction holds the write lock, so this sees a migration that a
	// concurrent Open applied after our history check.
	var applied bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = ?)`, m.version).Scan(&applied); err != nil {
		return fmt.Errorf("store: apply %s: %w", m.name, err)
	}
	if applied {
		return nil
	}
	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return fmt.Errorf("store: apply %s: %w", m.name, err)
	}
	rows, err := tx.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("store: apply %s: %w", m.name, err)
	}
	violation := rows.Next()
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("store: apply %s: %w", m.name, err)
	}
	if violation {
		return fmt.Errorf("store: apply %s: foreign key check failed", m.name)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
		m.version, m.name, time.Now().UTC().UnixNano()); err != nil {
		return fmt.Errorf("store: record %s: %w", m.name, err)
	}
	return tx.Commit()
}

func (s *Store) checkSchema(ctx context.Context) error {
	ms, err := loadMigrations()
	if err != nil {
		return err
	}
	current, err := schemaHistory(ctx, s.db, ms)
	if err != nil {
		return err
	}
	if current < len(ms) {
		return fmt.Errorf("%w (database %d, binary %d)", ErrSchemaOutdated, current, len(ms))
	}
	return nil
}

// schemaHistory returns the database's schema version after checking that
// the applied migrations are exactly versions 1..n of ms, by name.
func schemaHistory(ctx context.Context, q querier, ms []migration) (int, error) {
	rows, err := q.QueryContext(ctx, `SELECT version, name FROM schema_migrations ORDER BY version`)
	if err != nil {
		return 0, fmt.Errorf("store: read schema version: %w", err)
	}
	defer func() { _ = rows.Close() }()
	n := 0
	for rows.Next() {
		var v int
		var name string
		if err := rows.Scan(&v, &name); err != nil {
			return 0, fmt.Errorf("store: read schema version: %w", err)
		}
		switch {
		case v > len(ms) && v > n:
			return 0, fmt.Errorf("%w (database %d, binary %d)", ErrSchemaTooNew, v, len(ms))
		case v != n+1 || name != ms[n].name:
			return 0, fmt.Errorf("%w: unexpected migration %d %q", ErrSchemaHistory, v, name)
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("store: read schema version: %w", err)
	}
	return n, nil
}
