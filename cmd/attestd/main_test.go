package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	_ "modernc.org/sqlite"

	attestv1 "github.com/0xciph3r/attest/api/gen/attest/v1"
	"github.com/0xciph3r/attest/internal/api"
	"github.com/0xciph3r/attest/internal/audit"
	"github.com/0xciph3r/attest/internal/identity"
	"github.com/0xciph3r/attest/internal/store"
)

var bg = context.Background()

// tmp returns a short private directory so socket paths fit sun_path.
func tmp(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "atd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

func rootPEM(t *testing.T, dir string) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "EK root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "ek-root.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// baseConfig returns a valid configuration document as a map so tests can
// alter single fields.
func baseConfig(t *testing.T, dir string) map[string]any {
	t.Helper()
	return map[string]any{
		"trust_domain": "attest.local",
		"state_dir":    filepath.Join(dir, "state"),
		"node_listen":  "127.0.0.1:0",
		"admin_socket": filepath.Join(dir, "admin.sock"),
		"operators":    []any{map[string]any{"uid": os.Getuid(), "name": "alice", "role": "admin"}},
		"ek_roots":     map[string]any{"production": []string{rootPEM(t, dir)}},
	}
}

func writeConfig(t *testing.T, dir string, doc any) string {
	t.Helper()
	var b []byte
	switch d := doc.(type) {
	case string:
		b = []byte(d)
	default:
		var err error
		if b, err = json.Marshal(d); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(dir, "attestd.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func loadConfig(t *testing.T, dir string, doc any) *Config {
	t.Helper()
	cfg, err := LoadConfig(writeConfig(t, dir, doc))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestLoadConfigRejects(t *testing.T) {
	dir := tmp(t)
	mutate := map[string]func(m map[string]any){
		"bad trust domain":      func(m map[string]any) { m["trust_domain"] = "Attest Local" },
		"relative state_dir":    func(m map[string]any) { m["state_dir"] = "state" },
		"relative admin_socket": func(m map[string]any) { m["admin_socket"] = "admin.sock" },
		"node_listen no port":   func(m map[string]any) { m["node_listen"] = "127.0.0.1" },
		"socket mode 0666":      func(m map[string]any) { m["admin_socket_mode"] = "0666" },
		"socket mode not octal": func(m map[string]any) { m["admin_socket_mode"] = "rw" },
		"socket mode setuid":    func(m map[string]any) { m["admin_socket_mode"] = "4600" },
		"negative gid":          func(m map[string]any) { m["admin_socket_gid"] = -1 },
		"no operators":          func(m map[string]any) { m["operators"] = []any{} },
		"operator without uid":  func(m map[string]any) { m["operators"] = []any{map[string]any{"name": "a", "role": "admin"}} },
		"negative uid": func(m map[string]any) {
			m["operators"] = []any{map[string]any{"uid": -1, "name": "a", "role": "admin"}}
		},
		"no EK roots":            func(m map[string]any) { m["ek_roots"] = map[string]any{} },
		"zero TTL":               func(m map[string]any) { m["server_cert_ttl"] = "0s" },
		"TTL over max":           func(m map[string]any) { m["server_cert_ttl"] = "25h" },
		"garbage TTL":            func(m map[string]any) { m["server_cert_ttl"] = "soon" },
		"unknown field":          func(m map[string]any) { m["insecure"] = true },
		"duplicate operator uid": func(m map[string]any) { m["operators"] = []any{m["operators"].([]any)[0], m["operators"].([]any)[0]} },
	}
	for name, f := range mutate {
		m := baseConfig(t, dir)
		f(m)
		if _, err := LoadConfig(writeConfig(t, dir, m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// Duplicate keys are rejected, so a later key cannot silently override
	// an earlier one in review.
	b, _ := json.Marshal(baseConfig(t, dir))
	dup := strings.Replace(string(b), `{`, `{"trust_domain":"evil.local",`, 1)
	if _, err := LoadConfig(writeConfig(t, dir, dup)); err == nil {
		t.Error("duplicate key accepted")
	}

	p := writeConfig(t, dir, baseConfig(t, dir))
	if err := os.Chmod(p, 0o620); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(p); err == nil {
		t.Error("group-writable config accepted")
	}
	if _, err := LoadConfig(dir); err == nil {
		t.Error("directory accepted as config")
	}
	if err := os.WriteFile(p, bytes.Repeat([]byte(" "), maxConfigSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(p); err == nil {
		t.Error("oversized config accepted")
	}
}

func TestEKRootsRejectNonCertificates(t *testing.T) {
	dir := tmp(t)
	good, err := os.ReadFile(rootPEM(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}})
	for name, content := range map[string][]byte{
		"empty":             nil,
		"not PEM":           []byte("hello"),
		"private key block": append(bytes.Clone(good), key...),
		"trailing garbage":  append(bytes.Clone(good), "junk"...),
		"bad certificate":   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0}}),
	} {
		p := filepath.Join(dir, "bad.pem")
		if err := os.WriteFile(p, content, 0o600); err != nil {
			t.Fatal(err)
		}
		m := baseConfig(t, dir)
		m["ek_roots"] = map[string]any{"production": []string{p}}
		if _, err := loadConfig(t, dir, m).ekRoots(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	m := baseConfig(t, dir)
	m["ek_roots"] = map[string]any{"production": []string{filepath.Join(dir, "missing.pem")}}
	if _, err := loadConfig(t, dir, m).ekRoots(); err == nil {
		t.Error("missing root file accepted")
	}
}

func TestInitRefusesExistingOrUnsafeState(t *testing.T) {
	dir := tmp(t)
	cfg := loadConfig(t, dir, baseConfig(t, dir))
	if _, err := initState(bg, cfg); err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(filepath.Join(cfg.CADir(), identity.CAFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initState(bg, cfg); err == nil {
		t.Fatal("re-initialized existing state")
	}
	if again, _ := os.ReadFile(filepath.Join(cfg.CADir(), identity.CAFile)); !bytes.Equal(again, ca) {
		t.Fatal("CA replaced")
	}

	// A database without a CA is still existing state.
	if err := os.RemoveAll(cfg.CADir()); err != nil {
		t.Fatal(err)
	}
	if _, err := initState(bg, cfg); err == nil {
		t.Fatal("initialized over an existing database")
	}

	for name, setup := range map[string]func(p string) error{
		"world-readable": func(p string) error { return os.Mkdir(p, 0o755) },
		"symlink":        func(p string) error { return os.Symlink(dir, p) },
		"file":           func(p string) error { return os.WriteFile(p, nil, 0o600) },
	} {
		m := baseConfig(t, dir)
		m["state_dir"] = filepath.Join(dir, "s-"+strings.ReplaceAll(name, " ", ""))
		c := loadConfig(t, dir, m)
		if err := setup(c.StateDir); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(c.StateDir, 0o755); err != nil && name == "world-readable" {
			t.Fatal(err)
		}
		if _, err := initState(bg, c); err == nil {
			t.Errorf("%s state dir: accepted", name)
		}
	}
}

// running is a served attestd.
type running struct {
	cfg    *Config
	node   attestv1.NodeServiceClient
	admin  attestv1.AdminServiceClient
	cancel context.CancelFunc
	done   chan error
}

func start(t *testing.T, cfg *Config) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(bg)
	r := &running{cfg: cfg, cancel: cancel, done: make(chan error, 1)}
	addr := make(chan net.Addr, 1)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() { r.done <- serve(ctx, cfg, log, func(a net.Addr) { addr <- a }) }()
	var a net.Addr
	select {
	case a = <-addr:
	case err := <-r.done:
		cancel()
		t.Fatalf("serve: %v", err)
	}
	t.Cleanup(func() { _ = r.stop(t) })

	ca, err := identity.Load(cfg.CADir(), identity.Options{TrustDomain: cfg.TrustDomain})
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := api.ClientTLS(ca.Bundle(), cfg.TrustDomain, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	nc, err := grpc.NewClient("passthrough:///"+a.String(), grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		t.Fatal(err)
	}
	ac, err := grpc.NewClient("unix://"+cfg.AdminSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nc.Close(); _ = ac.Close() })
	r.node, r.admin = attestv1.NewNodeServiceClient(nc), attestv1.NewAdminServiceClient(ac)
	return r
}

func (r *running) stop(t *testing.T) error {
	t.Helper()
	r.cancel()
	select {
	case err, ok := <-r.done:
		if ok {
			close(r.done)
		}
		return err
	case <-time.After(shutdownTimeout + 5*time.Second):
		t.Fatal("serve did not stop")
		return nil
	}
}

func actions(t *testing.T, cfg *Config) []string {
	t.Helper()
	st, err := store.OpenReadOnly(bg, cfg.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	var out []string
	for e, err := range st.AuditEntries(bg) {
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, e.Action)
	}
	return out
}

func TestServe(t *testing.T) {
	dir := tmp(t)
	cfg := loadConfig(t, dir, baseConfig(t, dir))
	if _, err := initState(bg, cfg); err != nil {
		t.Fatal(err)
	}
	r := start(t, cfg)

	st, err := r.admin.GetStatus(bg, &attestv1.GetStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetTrustDomain() != "attest.local" || st.GetAuditSequence() < 3 {
		t.Fatalf("status %v", st)
	}
	// NodeService is reachable over TLS that authenticates attestd.
	_, err = r.node.GetChallenge(bg, &attestv1.GetChallengeRequest{NodeId: "n1"})
	if status.Code(err) != codes.PermissionDenied || api.DenialReason(err) != "node_unknown" {
		t.Fatalf("challenge for unregistered node: %v", err)
	}
	if fi, err := os.Stat(cfg.AdminSocket); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("admin socket %v, %v", fi, err)
	}

	if err := r.stop(t); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if _, err := os.Lstat(cfg.AdminSocket); err == nil {
		t.Error("admin socket left behind")
	}
	got := strings.Join(actions(t, cfg), ",")
	if !strings.HasPrefix(got, ActionInit+",") || !strings.Contains(got, ActionStart) || !strings.Contains(got, identity.ActionIssue) {
		t.Fatalf("audit %s", got)
	}

	// A restart reuses the same state.
	r = start(t, cfg)
	if _, err := r.admin.GetStatus(bg, &attestv1.GetStatusRequest{}); err != nil {
		t.Fatal(err)
	}
}

func TestServeFailsClosed(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	// A server that wrongly starts is reported and stopped rather than
	// left running until the test times out.
	serve := func(ctx context.Context, cfg *Config, log *slog.Logger, _ func(net.Addr)) error {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		err := serve(ctx, cfg, log, func(net.Addr) { t.Error("served"); cancel() })
		if err == nil {
			err = errors.New("served")
		}
		return err
	}
	var ready func(net.Addr)

	t.Run("uninitialized", func(t *testing.T) {
		dir := tmp(t)
		cfg := loadConfig(t, dir, baseConfig(t, dir))
		if err := os.Mkdir(cfg.StateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := serve(bg, cfg, log, ready); err == nil {
			t.Fatal("served without state")
		}
		if _, err := os.Lstat(cfg.DBPath()); err == nil {
			t.Fatal("serve created a database")
		}
	})

	initialized := func(t *testing.T) *Config {
		dir := tmp(t)
		cfg := loadConfig(t, dir, baseConfig(t, dir))
		if _, err := initState(bg, cfg); err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	t.Run("tampered ledger", func(t *testing.T) {
		cfg := initialized(t)
		// Someone with write access to the file rewrites an entry,
		// working around the append-only trigger.
		db, err := sql.Open("sqlite", cfg.DBPath())
		if err != nil {
			t.Fatal(err)
		}
		var trigger string
		if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE name = 'audit_entries_no_update'`).Scan(&trigger); err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{`DROP TRIGGER audit_entries_no_update`,
			`UPDATE audit_entries SET actor = 'mallory' WHERE seq = 1`, trigger} {
			if _, err := db.Exec(q); err != nil {
				t.Fatal(q, err)
			}
		}
		_ = db.Close()
		err = serve(bg, cfg, log, ready)
		if err == nil || !strings.Contains(err.Error(), "audit ledger does not verify") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("missing CA", func(t *testing.T) {
		cfg := initialized(t)
		if err := os.Remove(filepath.Join(cfg.CADir(), identity.CAFile)); err != nil {
			t.Fatal(err)
		}
		if err := serve(bg, cfg, log, ready); err == nil {
			t.Fatal("served without a CA")
		}
	})

	t.Run("other trust domain", func(t *testing.T) {
		cfg := initialized(t)
		cfg.TrustDomain = "other.local"
		if err := serve(bg, cfg, log, ready); err == nil {
			t.Fatal("served a CA for another trust domain")
		}
	})

	t.Run("state dir opened up", func(t *testing.T) {
		cfg := initialized(t)
		if err := os.Chmod(cfg.StateDir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := serve(bg, cfg, log, ready); err == nil {
			t.Fatal("served from a group-readable state dir")
		}
	})

	t.Run("node port in use", func(t *testing.T) {
		cfg := initialized(t)
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		cfg.NodeListen = l.Addr().String()
		before := len(actions(t, cfg))
		if err := serve(bg, cfg, log, ready); err == nil {
			t.Fatal("served on a busy port")
		}
		if _, err := os.Lstat(cfg.AdminSocket); err == nil {
			t.Error("admin socket left behind")
		}
		// Only the server certificate issuance is recorded; no start.
		if got := actions(t, cfg)[before:]; len(got) != 1 || got[0] != identity.ActionIssue {
			t.Errorf("audited %v", got)
		}
	})

	t.Run("admin socket in use", func(t *testing.T) {
		cfg := initialized(t)
		r := start(t, cfg)
		other := *cfg
		other.NodeListen = "127.0.0.1:0"
		if err := serve(bg, &other, log, ready); err == nil {
			t.Fatal("second instance served")
		}
		if _, err := r.admin.GetStatus(bg, &attestv1.GetStatusRequest{}); err != nil {
			t.Fatalf("first instance disrupted: %v", err)
		}
	})
}

func TestAuditTrailVerifies(t *testing.T) {
	dir := tmp(t)
	cfg := loadConfig(t, dir, baseConfig(t, dir))
	if _, err := initState(bg, cfg); err != nil {
		t.Fatal(err)
	}
	r := start(t, cfg)
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenReadOnly(bg, cfg.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if _, err := audit.Verify(st.AuditEntries(bg), audit.VerifyOptions{AllowUnanchored: true}); err != nil {
		t.Fatal(err)
	}
}
