package store

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/0xciph3r/attest/internal/store/storetest"
)

func TestFailedMigrationLeavesNoTrace(t *testing.T) {
	ctx := context.Background()
	s, path := openTemp(t)
	before := storetest.DumpDB(t, s.db)
	ms, _ := loadMigrations()
	bad := migration{version: len(ms) + 1, name: "bad", sql: `CREATE TABLE half (x INTEGER); INSERT INTO half VALUES (1); SELECT * FROM nope;`}
	if err := s.apply(ctx, bad); err == nil {
		t.Fatal("broken migration applied")
	}
	if after := storetest.DumpDB(t, s.db); after != before {
		t.Fatalf("failed migration left state:\n%s", after)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE name = 'half'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("partial table survived (n=%d, err=%v)", n, err)
	}
	_ = s.Close()
	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen after failed migration: %v", err)
	}
	_ = s2.Close()
}

func TestConcurrentOpenOfFreshDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "attest.db")
	const n = 8
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			s, err := Open(ctx, path)
			if err == nil {
				err = s.Close()
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Open: %v", err)
		}
	}
	ms, _ := loadMigrations()
	s, err := OpenReadOnly(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	var rows int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&rows); err != nil || rows != len(ms) {
		t.Fatalf("%d migration rows, want %d (err %v)", rows, len(ms), err)
	}
}

// The recorded history must be exactly this binary's migrations; a gap or a
// differently named migration means the schema did not come from this code.
func TestOpenRejectsNonDatabases(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage.db")
	if err := os.WriteFile(garbage, []byte("this is not an sqlite database, it is just text padding padding padding padding padding"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty-ro.db")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"garbage":   garbage,
		"directory": dir,
		"no parent": filepath.Join(dir, "missing", "attest.db"),
	} {
		if s, err := Open(ctx, path); err == nil {
			_ = s.Close()
			t.Errorf("Open(%s) succeeded", name)
		}
	}
	for name, path := range map[string]string{"garbage": garbage, "directory": dir, "empty file": empty} {
		if s, err := OpenReadOnly(ctx, path); err == nil {
			_ = s.Close()
			t.Errorf("OpenReadOnly(%s) succeeded", name)
		}
	}
	if b, _ := os.ReadFile(garbage); string(b[:7]) != "this is" {
		t.Fatal("Open modified a non-database file")
	}
}

func TestOpenHonoursCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path := filepath.Join(t.TempDir(), "attest.db")
	if s, err := Open(ctx, path); err == nil {
		_ = s.Close()
		t.Fatal("Open with cancelled context succeeded")
	}
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open after cancelled attempt: %v", err)
	}
	_ = s.Close()
}
