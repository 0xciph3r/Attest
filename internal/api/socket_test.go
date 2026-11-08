package api

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shortDir returns a private directory whose socket paths fit sun_path.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "att")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

func TestListenUnix(t *testing.T) {
	dir := shortDir(t)
	path := filepath.Join(dir, "s.sock")

	l, err := ListenUnix(path, 0o600, -1)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, %v", fi.Mode(), err)
	}
	if _, err := ListenUnix(path, 0o600, -1); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("live socket replaced: %v", err)
	}

	// A socket left behind by a crashed process is replaced.
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = l.Close()
	l, err = ListenUnix(path, 0o660, -1)
	if err != nil {
		t.Fatalf("stale socket: %v", err)
	}
	_ = l.Close()

	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	open := filepath.Join(dir, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		path string
		mode os.FileMode
	}{
		"regular file":        {file, 0o600},
		"symlink":             {link, 0o600},
		"world-writable dir":  {filepath.Join(open, "s"), 0o600},
		"missing dir":         {filepath.Join(dir, "none", "s"), 0o600},
		"parent is a file":    {filepath.Join(file, "s"), 0o600},
		"world-readable mode": {filepath.Join(dir, "a"), 0o666},
		"executable mode":     {filepath.Join(dir, "b"), 0o700},
	} {
		if l, err := ListenUnix(tc.path, tc.mode, -1); err == nil {
			_ = l.Close()
			t.Errorf("%s: accepted", name)
		}
	}
	if b, _ := os.ReadFile(file); string(b) != "keep" {
		t.Fatal("regular file clobbered")
	}
}

func TestPeerCredentials(t *testing.T) {
	l, err := ListenUnix(filepath.Join(shortDir(t), "s"), 0o600, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		if c, err := net.Dial("unix", l.Addr().String()); err == nil {
			defer func() { _ = c.Close() }()
			_, _ = c.Read(make([]byte, 1))
		}
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, info, err := peerCredentials{}.ServerHandshake(c)
	if err != nil {
		t.Fatal(err)
	}
	if cred := info.(PeerCred); cred.UID != uint32(os.Getuid()) {
		t.Fatalf("UID %d, want %d", cred.UID, os.Getuid())
	}

	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	if _, _, err := (peerCredentials{}).ServerHandshake(a); err == nil {
		t.Fatal("non-Unix connection authenticated")
	}
	if _, _, err := (peerCredentials{}).ClientHandshake(bg, "", a); err == nil {
		t.Fatal("client handshake succeeded")
	}
}
