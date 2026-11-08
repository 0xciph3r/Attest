package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/0xciph3r/attest/internal/api"
	"github.com/0xciph3r/attest/internal/audit"
	"github.com/0xciph3r/attest/internal/enrollment"
	"github.com/0xciph3r/attest/internal/identity"
	"github.com/0xciph3r/attest/internal/store"
	"github.com/0xciph3r/attest/internal/verifier"
)

// Audit actions recorded by attestd itself.
const (
	ActionInit  = "server.init"
	ActionStart = "server.start"
)

// shutdownTimeout bounds how long in-flight calls may run after a stop
// signal before connections are closed.
const shutdownTimeout = 10 * time.Second

// initState creates the state directory, the CA and the database, and
// returns the CA certificate fingerprint. It refuses to touch existing
// state, so it cannot replace a trust root or reset a ledger.
func initState(ctx context.Context, cfg *Config) (string, error) {
	if err := os.Mkdir(cfg.StateDir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", err
	}
	if err := checkStateDir(cfg.StateDir); err != nil {
		return "", err
	}
	for _, p := range []string{cfg.CADir(), cfg.DBPath()} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("init: %s already exists", p)
		}
	}
	if err := os.Mkdir(cfg.CADir(), 0o700); err != nil {
		return "", err
	}
	ca, err := identity.Init(cfg.CADir(), identity.Options{TrustDomain: cfg.TrustDomain})
	if err != nil {
		return "", err
	}
	st, err := store.Open(ctx, cfg.DBPath())
	if err != nil {
		return "", err
	}
	defer func() { _ = st.Close() }()
	fp := sha256.Sum256(ca.Cert().Raw)
	meta, err := json.Marshal(map[string]any{"trust_domain": cfg.TrustDomain, "ca": hex.EncodeToString(fp[:])})
	if err != nil {
		return "", err
	}
	if _, err := st.AppendAudit(ctx, audit.Record{Time: time.Now(), Actor: "attestd", Action: ActionInit,
		Object: "trust-domain/" + cfg.TrustDomain, Metadata: meta}); err != nil {
		return "", err
	}
	return hex.EncodeToString(fp[:]), nil
}

// checkStateDir requires a real directory owned by this user and
// inaccessible to anyone else.
func checkStateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("state_dir %s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("state_dir %s has mode %s; want 0700", dir, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("state_dir %s is owned by uid %d", dir, st.Uid)
	}
	return nil
}

// serve runs attestd until ctx is done or a listener fails. ready, if
// non-nil, is called with the node address once both services accept
// connections.
//
// Startup fails closed: missing state is an error rather than recreated,
// and an audit ledger that does not verify stops the server from starting.
func serve(ctx context.Context, cfg *Config, log *slog.Logger, ready func(node net.Addr)) error {
	if err := checkStateDir(cfg.StateDir); err != nil {
		return err
	}
	if fi, err := os.Lstat(cfg.DBPath()); err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("database %s is missing or not a regular file; run attestd init", cfg.DBPath())
	}
	st, err := store.Open(ctx, cfg.DBPath())
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	rep, err := audit.Verify(st.AuditEntries(ctx), audit.VerifyOptions{AllowUnanchored: true})
	if err != nil {
		return fmt.Errorf("audit ledger does not verify; refusing to start: %w", err)
	}
	ca, err := identity.Load(cfg.CADir(), identity.Options{TrustDomain: cfg.TrustDomain})
	if err != nil {
		return err
	}
	roots, err := cfg.ekRoots()
	if err != nil {
		return err
	}

	enr, err := enrollment.New(enrollment.Config{Store: st, Roots: roots})
	if err != nil {
		return err
	}
	ver, err := verifier.NewService(verifier.ServiceConfig{Store: st})
	if err != nil {
		return err
	}
	ident, err := identity.NewService(identity.ServiceConfig{Store: st, CA: ca})
	if err != nil {
		return err
	}
	ns, err := api.NewNodeServer(api.NodeConfig{Enrollment: enr, Verifier: ver, Identity: ident, Log: log})
	if err != nil {
		return err
	}
	as, err := api.NewAdminServer(api.AdminConfig{Store: st, CA: ca, Enrollment: enr, Verifier: ver, Identity: ident,
		Operators: cfg.operators(), Version: version, Log: log})
	if err != nil {
		return err
	}
	cert, err := api.NewServerCert(ctx, api.ServerCertConfig{CA: ca, Store: st, TTL: cfg.serverCertTTL, Log: log})
	if err != nil {
		return err
	}

	nodeLis, err := net.Listen("tcp", cfg.NodeListen)
	if err != nil {
		return err
	}
	adminLis, err := api.ListenUnix(cfg.AdminSocket, cfg.adminMode, cfg.socketGID())
	if err != nil {
		_ = nodeLis.Close()
		return err
	}
	meta, err := json.Marshal(map[string]any{"version": version, "verified_sequence": rep.Head.Sequence,
		"node_listen": nodeLis.Addr().String()})
	if err == nil {
		_, err = st.AppendAudit(ctx, audit.Record{Time: time.Now(), Actor: "attestd", Action: ActionStart,
			Object: "server/" + api.ServerName, Metadata: meta})
	}
	if err != nil {
		_ = nodeLis.Close()
		_ = adminLis.Close()
		return err
	}

	nodeSrv, adminSrv := api.NewNodeGRPCServer(ns, cert), api.NewAdminGRPCServer(as)
	errc := make(chan error, 2)
	go func() { errc <- fmt.Errorf("node listener: %w", nodeSrv.Serve(nodeLis)) }()
	go func() { errc <- fmt.Errorf("admin listener: %w", adminSrv.Serve(adminLis)) }()
	log.Info("attestd serving", "version", version, "trust_domain", cfg.TrustDomain,
		"node", nodeLis.Addr().String(), "admin", cfg.AdminSocket, "audit_sequence", rep.Head.Sequence)
	if ready != nil {
		ready(nodeLis.Addr())
	}

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
	}
	log.Info("attestd stopping")
	stopAll(shutdownTimeout, nodeSrv, adminSrv)
	return runErr
}

// stopAll drains in-flight calls on every server, forcing them closed once
// timeout has passed.
func stopAll(timeout time.Duration, servers ...*grpc.Server) {
	done := make(chan struct{})
	go func() {
		for _, s := range servers {
			s.GracefulStop()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		for _, s := range servers {
			s.Stop()
		}
		<-done
	}
}
