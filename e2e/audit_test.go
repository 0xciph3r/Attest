//go:build e2e

// Package e2e exercises Attest binaries as an operator would. Run with
// `make e2e`.
package e2e

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xciph3r/attest/internal/audit"
	"github.com/0xciph3r/attest/internal/store"
)

var attestctl string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "attest-e2e-bin")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	attestctl = filepath.Join(dir, "attestctl")
	build := exec.Command("go", "build", "-o", attestctl, "../cmd/attestctl")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build attestctl:", err)
		os.Exit(2)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

type result struct {
	code   int
	stdout string
	stderr string
}

func ctl(t *testing.T, args ...string) result {
	t.Helper()
	cmd := exec.Command(attestctl, args...)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run attestctl: %v", err)
	}
	return result{code: code, stdout: out.String(), stderr: errb.String()}
}

func expect(t *testing.T, r result, code int, contains string) {
	t.Helper()
	if r.code != code || !strings.Contains(r.stdout+r.stderr, contains) {
		t.Fatalf("exit %d (want %d), want output containing %q\nstdout: %s\nstderr: %s", r.code, code, contains, r.stdout, r.stderr)
	}
}

func populate(t *testing.T, path string, n int) {
	t.Helper()
	s, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	for i := range n {
		if _, err := s.AppendAudit(context.Background(), audit.Record{
			Time: time.Now(), Actor: "operator:alice", Action: "node.register", Object: fmt.Sprintf("node/%d", i),
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAuditLedgerLifecycle(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "attest.db")
	key, pub := filepath.Join(dir, "auditor.key"), filepath.Join(dir, "auditor.pub")
	cp1, cp2 := filepath.Join(dir, "cp1.json"), filepath.Join(dir, "cp2.json")

	populate(t, db, 5)
	backup := filepath.Join(dir, "backup.db")
	copyDB(t, db, backup)
	populate(t, db, 5)

	expect(t, ctl(t, "audit", "keygen", "--key", key, "--pub", pub), 0, "key id: ed25519:")
	expect(t, ctl(t, "audit", "checkpoint", "--db", db, "--key", key, "-o", cp1), 0, "seq=10")
	expect(t, ctl(t, "audit", "checkpoint", "--db", db, "--key", key, "-o", cp1), 2, "exists")

	t.Run("verified database", func(t *testing.T) {
		expect(t, ctl(t, "audit", "verify", "--db", db, "--pubkey", pub, "--checkpoint", cp1), 0, "anchored through seq=10")
	})

	t.Run("checkpoint chaining", func(t *testing.T) {
		populate(t, db, 2)
		expect(t, ctl(t, "audit", "verify", "--db", db, "--pubkey", pub, "--checkpoint", cp1), 0, "2 entries after the latest checkpoint")
		expect(t, ctl(t, "audit", "checkpoint", "--db", db, "--key", key, "--checkpoint", cp1, "-o", cp2), 0, "seq=12")
		expect(t, ctl(t, "audit", "verify", "--db", db, "--pubkey", pub, "--checkpoint", cp1, "--checkpoint", cp2), 0, "by 2 checkpoint(s)")
	})

	t.Run("verified export", func(t *testing.T) {
		export := filepath.Join(dir, "export.jsonl")
		expect(t, ctl(t, "audit", "export", "--db", db, "-o", export), 0, "exported 12 entries")
		expect(t, ctl(t, "audit", "verify", "--input", export, "--pubkey", pub, "--checkpoint", cp2), 0, "OK: 12 entries")

		b, err := os.ReadFile(export)
		if err != nil {
			t.Fatal(err)
		}
		tampered := filepath.Join(dir, "tampered.jsonl")
		if err := os.WriteFile(tampered, []byte(strings.Replace(string(b), "node/3", "node/X", 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		expect(t, ctl(t, "audit", "verify", "--input", tampered, "--pubkey", pub, "--checkpoint", cp2), 1, "entry hash mismatch at sequence 4")
	})

	t.Run("unanchored requires explicit opt-in", func(t *testing.T) {
		expect(t, ctl(t, "audit", "verify", "--db", db), 1, "no trusted checkpoint")
		expect(t, ctl(t, "audit", "verify", "--db", db, "--allow-unanchored"), 0, "internal consistency only")
	})

	t.Run("restored backup is rollback", func(t *testing.T) {
		expect(t, ctl(t, "audit", "verify", "--db", backup, "--pubkey", pub, "--checkpoint", cp1), 1, "truncated")
	})

	t.Run("untrusted key", func(t *testing.T) {
		otherKey, otherPub := filepath.Join(dir, "other.key"), filepath.Join(dir, "other.pub")
		expect(t, ctl(t, "audit", "keygen", "--key", otherKey, "--pub", otherPub), 0, "key id")
		expect(t, ctl(t, "audit", "verify", "--db", db, "--pubkey", otherPub, "--checkpoint", cp1), 1, "untrusted key")
	})

	t.Run("privileged rewrite", func(t *testing.T) {
		rewritten := filepath.Join(dir, "rewritten.db")
		copyDB(t, db, rewritten)
		rewriteChain(t, rewritten)
		expect(t, ctl(t, "audit", "verify", "--db", rewritten, "--allow-unanchored"), 0, "OK")
		expect(t, ctl(t, "audit", "verify", "--db", rewritten, "--pubkey", pub, "--checkpoint", cp1), 1, "does not match trusted checkpoint")
	})

	t.Run("operational errors", func(t *testing.T) {
		expect(t, ctl(t, "audit", "verify", "--db", filepath.Join(dir, "missing.db"), "--allow-unanchored"), 2, "error")
		if err := os.Chmod(key, 0o644); err != nil {
			t.Fatal(err)
		}
		expect(t, ctl(t, "audit", "checkpoint", "--db", db, "--key", key, "-o", filepath.Join(dir, "cp3.json")), 2, "require 0600")
	})
}

func copyDB(t *testing.T, src, dst string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+src)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`VACUUM INTO ?`, dst); err != nil {
		t.Fatal(err)
	}
}

// rewriteChain plays an attacker with write access to the database file: it
// removes the append-only triggers, alters an entry and recomputes the chain.
func rewriteChain(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for _, q := range []string{
		`DROP TRIGGER audit_entries_no_update`,
		`DROP TRIGGER audit_entries_extend_head`,
		`UPDATE audit_entries SET actor = 'operator:mallory' WHERE seq = 2`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.Query(`SELECT seq, recorded_at, actor, action, object, metadata FROM audit_entries ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	var recs []audit.Record
	for rows.Next() {
		var (
			seq, nanos int64
			r          audit.Record
		)
		if err := rows.Scan(&seq, &nanos, &r.Actor, &r.Action, &r.Object, &r.Metadata); err != nil {
			t.Fatal(err)
		}
		r.Time = time.Unix(0, nanos)
		recs = append(recs, r)
	}
	_ = rows.Close()
	var head audit.Head
	for _, r := range recs {
		e, err := audit.Next(head, r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`UPDATE audit_entries SET prev_hash = ?, hash = ? WHERE seq = ?`, e.PrevHash[:], e.Hash[:], int64(e.Sequence)); err != nil {
			t.Fatal(err)
		}
		head = audit.Head{Sequence: e.Sequence, Hash: e.Hash}
	}
}
