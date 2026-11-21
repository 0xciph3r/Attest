package secfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, mode os.FileMode, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRead(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o644, 0o400} {
		b, err := Read(write(t, mode, "ok"), 2)
		if err != nil || string(b) != "ok" {
			t.Errorf("mode %o: Read = %q, %v", mode, b, err)
		}
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(write(t, 0o644, "ok"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(link, 2); err != nil {
		t.Errorf("symlink to a private file: %v", err)
	}
}

func TestReadRejects(t *testing.T) {
	dir := t.TempDir()
	badLink := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(write(t, 0o666, "x"), badLink); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		path string
		want string
	}{
		"missing":          {filepath.Join(dir, "missing"), "no such file"},
		"directory":        {dir, "not a regular file"},
		"group writable":   {write(t, 0o664, "x"), "writable by group or others"},
		"world writable":   {write(t, 0o646, "x"), "writable by group or others"},
		"link to writable": {badLink, "writable by group or others"},
		"oversized":        {write(t, 0o600, "abc"), "exceeds 2 bytes"},
	} {
		if _, err := Read(tc.path, 2); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
	if _, err := Read("/dev/null", 2); err == nil {
		t.Error("device accepted")
	}
}

func TestReadRejectsOtherOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give a file to another user")
	}
	p := write(t, 0o644, "x")
	if err := os.Chown(p, 1000, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(p, 2); err == nil || !strings.Contains(err.Error(), "owned by uid 1000") {
		t.Fatalf("file owned by another user: err = %v", err)
	}
}
