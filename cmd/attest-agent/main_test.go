package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	attestv1 "github.com/0xciph3r/attest/api/gen/attest/v1"
	"github.com/0xciph3r/attest/internal/identity"
	"github.com/0xciph3r/attest/internal/tpm"
)

const td = "attest.local"

// tmp returns a short private directory so socket paths fit sun_path.
func tmp(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "aag")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

func writeFile(t *testing.T, path string, b []byte, mode os.FileMode) string {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// setup writes a CA bundle and returns a valid configuration as a JSON
// object, for tests to adjust.
func setup(t *testing.T) (dir string, cfg map[string]any) {
	t.Helper()
	dir = tmp(t)
	ca, err := identity.Init(t.TempDir(), identity.Options{TrustDomain: td})
	if err != nil {
		t.Fatal(err)
	}
	return dir, map[string]any{
		"node_id":         "n1",
		"trust_domain":    td,
		"control_plane":   "127.0.0.1:1",
		"bundle":          writeFile(t, filepath.Join(dir, "bundle.pem"), ca.BundlePEM(), 0o644),
		"workload_socket": filepath.Join(dir, "w.sock"),
		"tpm":             map[string]any{},
	}
}

func writeConfig(t *testing.T, dir string, cfg any) string {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, filepath.Join(dir, "agent.json"), b, 0o600)
}

func load(t *testing.T, dir string, cfg any) *Config {
	t.Helper()
	c, err := LoadConfig(writeConfig(t, dir, cfg))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLoadConfigDefaults(t *testing.T) {
	dir, raw := setup(t)
	c := load(t, dir, raw)
	if c.TPM.Device != DefaultTPMDevice || c.TPM.EventLog != tpm.DefaultEventLogPath || c.ekType != tpm.EKRSA2048 ||
		c.mode != 0o660 || c.socketGID() != -1 {
		t.Fatalf("defaults: %+v mode %o gid %d", c.TPM, c.mode, c.socketGID())
	}
	raw["workload_socket_mode"], raw["workload_socket_gid"] = "0600", 7
	raw["tpm"] = map[string]any{"swtpm": "127.0.0.1:2321", "ek_type": "eccp256", "event_log": "/run/log"}
	c = load(t, dir, raw)
	if c.TPM.Device != "" || c.TPM.Swtpm != "127.0.0.1:2321" || c.ekType != tpm.EKECCP256 || c.mode != 0o600 ||
		c.socketGID() != 7 || c.TPM.EventLog != "/run/log" {
		t.Fatalf("explicit: %+v mode %o gid %d", c.TPM, c.mode, c.socketGID())
	}
	if b, err := c.loadBundle(); err != nil || len(b) != 1 {
		t.Fatalf("loadBundle = %v, %v", b, err)
	}
}

func TestLoadConfigRejects(t *testing.T) {
	dir, _ := setup(t)
	set := func(k string, v any) func(map[string]any) { return func(m map[string]any) { m[k] = v } }
	setTPM := func(k string, v any) func(map[string]any) {
		return func(m map[string]any) { m["tpm"].(map[string]any)[k] = v }
	}
	for name, mutate := range map[string]func(map[string]any){
		"no node_id":          func(m map[string]any) { delete(m, "node_id") },
		"bad node_id":         set("node_id", "../n1"),
		"bad trust_domain":    set("trust_domain", "Attest.Local"),
		"no port":             set("control_plane", "attestd"),
		"no host":             set("control_plane", ":8443"),
		"no control_plane":    set("control_plane", ""),
		"relative bundle":     set("bundle", "bundle.pem"),
		"relative socket":     set("workload_socket", "w.sock"),
		"world socket":        set("workload_socket_mode", "0666"),
		"setuid socket":       set("workload_socket_mode", "4660"),
		"decimal mode":        set("workload_socket_mode", "660x"),
		"negative gid":        set("workload_socket_gid", -1),
		"device and swtpm":    setTPM("swtpm", "127.0.0.1:2321"),
		"swtpm without port":  func(m map[string]any) { m["tpm"] = map[string]any{"swtpm": "localhost"} },
		"swtpm without host":  func(m map[string]any) { m["tpm"] = map[string]any{"swtpm": ":2321"} },
		"relative device":     func(m map[string]any) { m["tpm"] = map[string]any{"device": "tpmrm0"} },
		"relative event log":  setTPM("event_log", "log"),
		"unknown ek_type":     setTPM("ek_type", "rsa4096"),
		"unknown field":       set("socket", "/x"),
		"unknown tpm field":   setTPM("pcrs", []int{7}),
		"tpm is not object":   set("tpm", "/dev/tpm0"),
		"string gid":          set("workload_socket_gid", "0"),
		"null node_id":        set("node_id", nil),
		"node_id is a number": set("node_id", 1),
	} {
		_, raw := setup(t)
		raw["tpm"] = map[string]any{"device": "/dev/tpmrm0"}
		mutate(raw)
		if _, err := LoadConfig(writeConfig(t, dir, raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	_, raw := setup(t)
	good, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"empty":         nil,
		"not JSON":      []byte("node_id = n1"),
		"array":         []byte("[]"),
		"trailing data": append(bytes.Clone(good), []byte("{}")...),
		"duplicate key": bytes.Replace(good, []byte(`{`), []byte(`{"node_id":"n2",`), 1),
		"oversized":     append(bytes.Clone(good), bytes.Repeat([]byte(" "), maxConfigSize)...),
	} {
		if _, err := LoadConfig(writeFile(t, filepath.Join(dir, "agent.json"), b, 0o600)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p := writeFile(t, filepath.Join(dir, "agent.json"), good, 0o620)
	if _, err := LoadConfig(p); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("group-writable config: %v", err)
	}
	if _, err := LoadConfig(filepath.Join(dir, "missing.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing config: %v", err)
	}
}

func TestLoadBundleRejects(t *testing.T) {
	dir, raw := setup(t)
	other, err := identity.Init(t.TempDir(), identity.Options{TrustDomain: "other.test"})
	if err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(raw["bundle"].(string))
	if err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"missing":        filepath.Join(dir, "none.pem"),
		"group writable": writeFile(t, filepath.Join(dir, "gw.pem"), good, 0o664),
		"other domain":   writeFile(t, filepath.Join(dir, "od.pem"), other.BundlePEM(), 0o644),
		"garbage":        writeFile(t, filepath.Join(dir, "g.pem"), []byte("not a bundle"), 0o644),
		"empty":          writeFile(t, filepath.Join(dir, "e.pem"), nil, 0o644),
		"directory":      dir,
	} {
		raw["bundle"] = path
		c := load(t, dir, raw)
		if _, err := c.loadBundle(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// noTPM cannot attest, so the agent serves without a node identity.
type noTPM struct{ key crypto.Signer }

func (noTPM) AKPublic() []byte { return nil }
func (noTPM) ActivateCredential(_, _ []byte) ([]byte, error) {
	return nil, errors.New("no TPM")
}

func (noTPM) Evidence([]byte, []uint32) (*attestv1.Evidence, error) {
	return nil, errors.New("no TPM")
}
func (n noTPM) NodeKey() crypto.Signer { return n.key }

func newNoTPM(t *testing.T) noTPM {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return noTPM{key: k}
}

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestRunServesAndStops(t *testing.T) {
	dir, raw := setup(t)
	raw["workload_socket_mode"], raw["workload_socket_gid"] = "0600", os.Getgid()
	c := load(t, dir, raw)
	ctx, cancel := context.WithCancel(context.Background())
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() { done <- run(ctx, c, quiet(), newNoTPM(t), func() { close(ready) }) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("run returned before serving: %v", err)
	}
	fi, err := os.Lstat(c.WorkloadSocket)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Type() != fs.ModeSocket || fi.Mode().Perm() != 0o600 || int(fi.Sys().(*syscall.Stat_t).Gid) != os.Getgid() {
		t.Fatalf("socket mode %s gid %d", fi.Mode(), fi.Sys().(*syscall.Stat_t).Gid)
	}

	// This test process is not a systemd service, so the agent refuses
	// it at the handshake whatever the platform.
	cc, err := grpc.NewClient("unix://"+c.WorkloadSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer rcancel()
	if _, err := attestv1.NewWorkloadServiceClient(cc).FetchX509Identity(rctx, &attestv1.FetchX509IdentityRequest{Csr: []byte("x")}); err == nil {
		t.Fatal("unidentified caller served")
	}

	// A second agent must not take over the live socket.
	if err := run(context.Background(), c, quiet(), newNoTPM(t), nil); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("second agent on a live socket: %v", err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run = %v", err)
		}
	case <-time.After(shutdownTimeout + 5*time.Second):
		t.Fatal("run did not stop")
	}
	if _, err := os.Lstat(c.WorkloadSocket); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("socket left behind: %v", err)
	}
}

func TestRunRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		prepare func(t *testing.T, dir string, raw map[string]any)
		want    string
	}{
		"missing bundle": {func(t *testing.T, dir string, raw map[string]any) {
			raw["bundle"] = filepath.Join(dir, "none.pem")
		}, "bundle"},
		"socket dir writable by group": {func(t *testing.T, dir string, raw map[string]any) {
			sub := filepath.Join(dir, "s")
			if err := os.Mkdir(sub, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(sub, 0o770); err != nil {
				t.Fatal(err)
			}
			raw["workload_socket"] = filepath.Join(sub, "w.sock")
		}, "writable by group or others"},
		"socket dir missing": {func(t *testing.T, dir string, raw map[string]any) {
			raw["workload_socket"] = filepath.Join(dir, "none", "w.sock")
		}, "socket directory"},
		"regular file at socket path": {func(t *testing.T, dir string, raw map[string]any) {
			writeFile(t, filepath.Join(dir, "w.sock"), []byte("x"), 0o600)
		}, "not a socket"},
	} {
		t.Run(name, func(t *testing.T) {
			dir, raw := setup(t)
			tc.prepare(t, dir, raw)
			c := load(t, dir, raw)
			err := run(context.Background(), c, quiet(), newNoTPM(t), func() { t.Error("served") })
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestStaleSocketReplaced(t *testing.T) {
	dir, raw := setup(t)
	c := load(t, dir, raw)
	l, err := net.Listen("unix", c.WorkloadSocket)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() { done <- run(ctx, c, quiet(), newNoTPM(t), func() { close(ready) }) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("stale socket not replaced: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCommands(t *testing.T) {
	dir, raw := setup(t)
	raw["tpm"] = map[string]any{"device": filepath.Join(dir, "no-tpm")}
	cfg := writeConfig(t, dir, raw)
	exec := func(args ...string) (string, error) {
		cmd := newRootCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(args)
		err := cmd.ExecuteContext(context.Background())
		return out.String(), err
	}
	if out, err := exec("version"); err != nil || out != version+"\n" {
		t.Fatalf("version = %q, %v", out, err)
	}
	for _, sub := range []string{"ek-cert", "enroll", "run"} {
		if _, err := exec(sub, "--config", filepath.Join(dir, "missing.json")); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s without config: %v", sub, err)
		}
		if _, err := exec(sub, "--config", cfg); err == nil || !strings.Contains(err.Error(), "no-tpm") {
			t.Errorf("%s without a TPM: %v", sub, err)
		}
		if _, err := exec(sub, "--config", cfg, "extra"); err == nil {
			t.Errorf("%s accepted an argument", sub)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "w.sock")); !errors.Is(err, fs.ErrNotExist) {
		t.Error("run without a TPM created the socket")
	}
}
