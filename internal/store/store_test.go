package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/0xciph3r/attest/internal/audit"
)

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "attest.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func appendN(t *testing.T, s *Store, n int) {
	t.Helper()
	for i := range n {
		if _, err := s.AppendAudit(context.Background(), audit.Record{
			Time:   time.Now(),
			Actor:  "operator:alice",
			Action: "policy.apply",
			Object: fmt.Sprintf("policy/v%d", i+1),
		}); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}
}

func verify(t *testing.T, s *Store, cps []audit.SignedCheckpoint, keys audit.KeyRing) (audit.Report, error) {
	t.Helper()
	return audit.Verify(s.AuditEntries(context.Background()), audit.VerifyOptions{
		Checkpoints: cps, Keys: keys, AllowUnanchored: len(cps) == 0,
	})
}

func TestAppendAndVerify(t *testing.T) {
	s, _ := openTemp(t)
	appendN(t, s, 5)
	if _, err := s.AppendAudit(context.Background(), audit.Record{
		Time: time.Now(), Actor: "a", Action: "b", Object: "c", Metadata: []byte(`{"k":"v"}`),
	}); err != nil {
		t.Fatal(err)
	}
	rep, err := verify(t, s, nil, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	head, err := s.AuditHead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Head != head || head.Sequence != 6 {
		t.Fatalf("report head %+v, store head %+v", rep.Head, head)
	}
}

func TestConcurrentAppendsFormOneChain(t *testing.T) {
	s, _ := openTemp(t)
	const writers, each = 8, 20
	var wg sync.WaitGroup
	errs := make(chan error, writers*each)
	for w := range writers {
		wg.Go(func() {
			for i := range each {
				_, err := s.AppendAudit(context.Background(), audit.Record{
					Time: time.Now(), Actor: fmt.Sprintf("writer:%d", w), Action: "test.append", Object: fmt.Sprintf("obj/%d", i),
				})
				if err != nil {
					errs <- err
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent append: %v", err)
	}
	rep, err := verify(t, s, nil, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Head.Sequence != writers*each {
		t.Fatalf("head %d, want %d", rep.Head.Sequence, writers*each)
	}
}

func TestDatabaseEnforcesAppendOnly(t *testing.T) {
	s, _ := openTemp(t)
	appendN(t, s, 3)
	head, _ := s.AuditHead(context.Background())
	zero := make([]byte, 32)

	for name, stmt := range map[string]struct {
		q    string
		args []any
	}{
		"update":           {`UPDATE audit_entries SET actor = 'mallory' WHERE seq = 2`, nil},
		"delete":           {`DELETE FROM audit_entries WHERE seq = 3`, nil},
		"skip sequence":    {`INSERT INTO audit_entries VALUES (5, 0, 'a', 'b', 'c', NULL, ?, ?)`, []any{head.Hash[:], zero}},
		"wrong prev hash":  {`INSERT INTO audit_entries VALUES (4, 0, 'a', 'b', 'c', NULL, ?, ?)`, []any{zero, zero}},
		"replace existing": {`INSERT OR REPLACE INTO audit_entries VALUES (2, 0, 'a', 'b', 'c', NULL, ?, ?)`, []any{zero, zero}},
		"short hash":       {`INSERT INTO audit_entries VALUES (4, 0, 'a', 'b', 'c', NULL, ?, x'00')`, []any{head.Hash[:]}},
	} {
		if _, err := s.db.Exec(stmt.q, stmt.args...); err == nil {
			t.Errorf("%s: expected the database to reject the write", name)
		}
	}
	if _, err := verify(t, s, nil, nil); err != nil {
		t.Fatalf("ledger damaged by rejected writes: %v", err)
	}
}

// The triggers are not a security boundary. This test plays an attacker with
// direct database access who removes them, rewrites history and recomputes
// the chain. Only the externally held checkpoint detects it.
func TestCheckpointDetectsPrivilegedRewrite(t *testing.T) {
	s, _ := openTemp(t)
	appendN(t, s, 5)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	head, _ := s.AuditHead(context.Background())
	cp, err := audit.SignCheckpoint(head, time.Now(), priv)
	if err != nil {
		t.Fatal(err)
	}
	keys := audit.NewKeyRing(pub)

	if _, err := verify(t, s, []audit.SignedCheckpoint{cp}, keys); err != nil {
		t.Fatalf("baseline verify: %v", err)
	}

	rewriteAsAttacker(t, s.db)

	if _, err := verify(t, s, nil, nil); err != nil {
		t.Fatalf("rewritten chain should be internally consistent, got %v", err)
	}
	if _, err := verify(t, s, []audit.SignedCheckpoint{cp}, keys); !errors.Is(err, audit.ErrCheckpointMismatch) {
		t.Fatalf("got %v, want ErrCheckpointMismatch", err)
	}
}

func rewriteAsAttacker(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, q := range []string{
		`DROP TRIGGER audit_entries_no_update`,
		`DROP TRIGGER audit_entries_no_delete`,
		`DROP TRIGGER audit_entries_extend_head`,
		`UPDATE audit_entries SET actor = 'operator:mallory' WHERE seq = 2`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// Recompute every hash so the chain is self-consistent.
	s := &Store{db: db}
	var entries []audit.Entry
	for e, err := range s.AuditEntries(context.Background()) {
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}
	var head audit.Head
	for _, e := range entries {
		ne, err := audit.Next(head, audit.Record{Time: e.Time, Actor: e.Actor, Action: e.Action, Object: e.Object, Metadata: e.Metadata})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`UPDATE audit_entries SET prev_hash = ?, hash = ? WHERE seq = ?`, ne.PrevHash[:], ne.Hash[:], int64(ne.Sequence)); err != nil {
			t.Fatal(err)
		}
		head = audit.Head{Sequence: ne.Sequence, Hash: ne.Hash}
	}
}

func TestRestoredBackupIsDetectedAsTruncation(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	appendN(t, s, 3)
	backup := filepath.Join(t.TempDir(), "backup.db")
	if _, err := s.db.Exec(`VACUUM INTO ?`, backup); err != nil {
		t.Fatal(err)
	}
	appendN(t, s, 3)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	head, _ := s.AuditHead(ctx)
	cp, _ := audit.SignCheckpoint(head, time.Now(), priv)

	restored, err := OpenReadOnly(ctx, backup)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restored.Close() }()
	_, err = audit.Verify(restored.AuditEntries(ctx), audit.VerifyOptions{
		Checkpoints: []audit.SignedCheckpoint{cp}, Keys: audit.NewKeyRing(pub),
	})
	if !errors.Is(err, audit.ErrTruncated) {
		t.Fatalf("got %v, want ErrTruncated", err)
	}
}

func TestMigrations(t *testing.T) {
	ctx := context.Background()
	s, path := openTemp(t)
	appendN(t, s, 1)
	_ = s.Close()

	t.Run("reopen is idempotent", func(t *testing.T) {
		s2, err := Open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s2.Close() }()
		head, err := s2.AuditHead(ctx)
		if err != nil || head.Sequence != 1 {
			t.Fatalf("head %+v err %v", head, err)
		}
	})

	t.Run("newer schema refused", func(t *testing.T) {
		db, err := sql.Open("sqlite", dsn(path, false))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations VALUES (999, 'future', 0)`); err != nil {
			t.Fatal(err)
		}
		_ = db.Close()
		if _, err := Open(ctx, path); !errors.Is(err, ErrSchemaTooNew) {
			t.Fatalf("Open: got %v", err)
		}
		if _, err := OpenReadOnly(ctx, path); !errors.Is(err, ErrSchemaTooNew) {
			t.Fatalf("OpenReadOnly: got %v", err)
		}
	})
}

func TestReadOnlyOpenCannotWrite(t *testing.T) {
	ctx := context.Background()
	s, path := openTemp(t)
	appendN(t, s, 1)
	ro, err := OpenReadOnly(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	if _, err := ro.AppendAudit(ctx, audit.Record{Time: time.Now(), Actor: "a", Action: "b", Object: "c"}); err == nil {
		t.Fatal("read-only store accepted a write")
	}
	if _, err := OpenReadOnly(ctx, filepath.Join(t.TempDir(), "missing.db")); err == nil {
		t.Fatal("read-only open of a missing database must fail")
	}
}
