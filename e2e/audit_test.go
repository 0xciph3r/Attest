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
	"regexp"
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

func TestAuditRejects(t *testing.T) {
	dir := t.TempDir()
	path := func(name string) string { return filepath.Join(dir, name) }
	db, key, pub := path("attest.db"), path("auditor.key"), path("auditor.pub")
	populate(t, db, 6)
	expect(t, ctl(t, "audit", "keygen", "--key", key, "--pub", pub), 0, "key id")
	cp := path("cp.json")
	expect(t, ctl(t, "audit", "checkpoint", "--db", db, "--key", key, "-o", cp), 0, "seq=6")
	export := path("export.jsonl")
	expect(t, ctl(t, "audit", "export", "--db", db, "-o", export), 0, "exported 6")

	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	write := func(name, data string) string {
		p := path(name)
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	lines := strings.SplitAfter(read(export), "\n")
	lines = lines[:len(lines)-1] // trailing ""
	join := func(ls ...string) string { return strings.Join(ls, "") }
	swapField := func(line, field, from, to string) string {
		return strings.Replace(line, `"`+field+`":`+from, `"`+field+`":`+to, 1)
	}
	verifyExport := func(data string) result {
		return ctl(t, "audit", "verify", "--input", write("t.jsonl", data), "--pubkey", pub, "--checkpoint", cp)
	}

	t.Run("tampered export", func(t *testing.T) {
		otherHash := strings.Repeat("0", 64)
		for _, tc := range []struct{ name, data, want string }{
			{"reordered", join(lines[0], lines[2], lines[1], join(lines[3:]...)), "sequence discontinuity"},
			{"duplicated", join(lines[0], lines[1], lines[1], join(lines[2:]...)), "sequence discontinuity"},
			{"deleted middle", join(lines[0], join(lines[2:]...)), "sequence discontinuity"},
			{"deleted last", join(lines[:5]...), "truncated"},
			{"empty", "", "truncated"},
			{"truncated mid-line", join(lines...)[:len(join(lines...))-10], "malformed"},
			{"renumbered", join(lines[0], swapField(lines[1], "seq", "2", "3"), join(lines[2:]...)), "sequence discontinuity"},
			{"altered hash", join(lines[0], lines[1], swapJSON(lines[2], "hash", otherHash), join(lines[3:]...)), "entry hash mismatch at sequence 3"},
			{"altered prev_hash", join(lines[0], swapJSON(lines[1], "prev_hash", otherHash), join(lines[2:]...)), "previous-hash mismatch"},
			{"altered object", join(lines[0], strings.Replace(lines[1], "node/1", "node/X", 1), join(lines[2:]...)), "entry hash mismatch"},
			{"garbage appended", join(join(lines...), "garbage\n"), "malformed"},
			{"extra entry appended", join(join(lines...), lines[5]), "sequence discontinuity"},
			{"duplicate key", join(strings.Replace(lines[0], `"actor":`, `"actor":"x","actor":`, 1), join(lines[1:]...)), "malformed"},
			{"case-variant key", join(strings.Replace(lines[0], `"actor":`, `"ACTOR":`, 1), join(lines[1:]...)), "malformed"},
			{"blank line", join(lines[0], "\n", join(lines[1:]...)), "malformed"},
		} {
			t.Run(tc.name, func(t *testing.T) { expect(t, verifyExport(tc.data), 1, tc.want) })
		}
	})

	t.Run("tampered checkpoint", func(t *testing.T) {
		good := read(cp)
		otherKey, otherPub := path("other.key"), path("other.pub")
		expect(t, ctl(t, "audit", "keygen", "--key", otherKey, "--pub", otherPub), 0, "key id")
		otherCP := path("other-cp.json")
		expect(t, ctl(t, "audit", "checkpoint", "--db", db, "--key", otherKey, "-o", otherCP), 0, "seq=6")

		otherDB := path("other.db")
		populate(t, otherDB, 6)
		foreignCP := path("foreign-cp.json")
		expect(t, ctl(t, "audit", "checkpoint", "--db", otherDB, "--key", key, "-o", foreignCP), 0, "seq=6")

		for _, tc := range []struct {
			name, file, want string
		}{
			{"signed by untrusted key", otherCP, "untrusted key"},
			{"for another ledger", foreignCP, "does not match trusted checkpoint"},
			{"sequence lowered", write("c1.json", strings.Replace(good, `"sequence": 6`, `"sequence": 5`, 1)), "invalid checkpoint signature"},
			{"time moved", write("c2.json", strings.Replace(good, `"time": "20`, `"time": "19`, 1)), "invalid checkpoint signature"},
			{"signature emptied", write("c3.json", swapJSON(good, "signature", "")), "invalid checkpoint signature"},
			{"signature not base64", write("c3b.json", swapJSON(good, "signature", "!!")), "malformed checkpoint"},
			{"unknown field", write("c4.json", strings.Replace(good, "{", `{"trusted": true,`, 1)), "malformed checkpoint"},
			{"duplicate key", write("c5.json", strings.Replace(good, "{", `{"sequence": 1,`, 1)), "malformed checkpoint"},
			{"truncated", write("c6.json", good[:len(good)/2]), "malformed checkpoint"},
			{"two objects", write("c7.json", good+good), "malformed checkpoint"},
			{"empty", write("c8.json", ""), "malformed checkpoint"},
			{"oversized", write("c9.json", good+strings.Repeat(" ", 20<<10)), "malformed checkpoint"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				expect(t, ctl(t, "audit", "verify", "--db", db, "--pubkey", pub, "--checkpoint", tc.file), 1, tc.want)
			})
		}
		// One bad checkpoint among good ones still fails.
		expect(t, ctl(t, "audit", "verify", "--db", db, "--pubkey", pub, "--checkpoint", cp, "--checkpoint", foreignCP), 1, "conflict")
	})

	t.Run("checkpoint refuses to extend untrusted history", func(t *testing.T) {
		rewritten := path("rewritten.db")
		copyDB(t, db, rewritten)
		rewriteChain(t, rewritten)
		out := path("never.json")
		expect(t, ctl(t, "audit", "checkpoint", "--db", rewritten, "--key", key, "--checkpoint", cp, "-o", out), 1, "does not match")
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatal("checkpoint written for a ledger that failed verification")
		}
	})

	t.Run("operational errors", func(t *testing.T) {
		corrupt := write("corrupt.db", strings.Repeat("not a database ", 512))
		for _, tc := range []struct {
			name string
			args []string
		}{
			{"input is a directory", []string{"audit", "verify", "--input", dir, "--allow-unanchored"}},
			{"missing checkpoint file", []string{"audit", "verify", "--db", db, "--pubkey", pub, "--checkpoint", path("nope.json")}},
			{"checkpoint without pubkey", []string{"audit", "verify", "--db", db, "--checkpoint", cp}},
			{"pubkey is private key", []string{"audit", "verify", "--db", db, "--pubkey", key, "--checkpoint", cp}},
			{"pubkey is a directory", []string{"audit", "verify", "--db", db, "--pubkey", dir, "--checkpoint", cp}},
			{"corrupt database", []string{"audit", "verify", "--db", corrupt, "--allow-unanchored"}},
			{"db and input", []string{"audit", "verify", "--db", db, "--input", export, "--allow-unanchored"}},
			{"no source", []string{"audit", "verify", "--allow-unanchored"}},
			{"export over existing file", []string{"audit", "export", "--db", db, "-o", export}},
			{"checkpoint into missing dir", []string{"audit", "checkpoint", "--db", db, "--key", key, "-o", path("missing/cp.json")}},
			{"checkpoint key is public", []string{"audit", "checkpoint", "--db", db, "--key", pub, "-o", path("cp-pub.json")}},
			{"keygen same path", []string{"audit", "keygen", "--key", path("same"), "--pub", path("same")}},
		} {
			t.Run(tc.name, func(t *testing.T) { expect(t, ctl(t, tc.args...), 2, "error") })
		}
		if read(export) != join(lines...) {
			t.Fatal("refused export modified the existing file")
		}
		if _, err := os.Stat(path("same")); !os.IsNotExist(err) {
			t.Fatal("failed keygen left a private key behind")
		}
	})
}

// swapJSON replaces the string value of field in a JSON document, written
// compactly or indented.
func swapJSON(doc, field, value string) string {
	re := regexp.MustCompile(`("` + field + `":\s*")[^"]*"`)
	if !re.MatchString(doc) {
		panic("field " + field + " not found")
	}
	return re.ReplaceAllString(doc, "${1}"+value+`"`)
}
