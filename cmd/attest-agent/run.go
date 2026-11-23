package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"

	"github.com/0xciph3r/attest/internal/agent"
	"github.com/0xciph3r/attest/internal/api"
	"github.com/0xciph3r/attest/internal/tpm"
	"github.com/0xciph3r/attest/internal/tpm/swtpm"
)

// shutdownTimeout bounds how long in-flight workload calls may take to
// finish once the agent is asked to stop.
const shutdownTimeout = 10 * time.Second

func openTPM(c TPMConfig) (transport.TPMCloser, error) {
	if c.Swtpm != "" {
		return swtpm.Dial(c.Swtpm, "")
	}
	t, err := linuxtpm.Open(c.Device)
	if err != nil {
		return nil, fmt.Errorf("tpm: open %s: %w", c.Device, err)
	}
	return t, nil
}

// withDevice opens the configured TPM and calls fn with it. Each call
// derives a fresh node key, so no key material or key selector outlives
// the process; node identities are reissued at every attestation anyway.
func withDevice(cfg *Config, fn func(*agent.Device) error) error {
	t, err := openTPM(cfg.TPM)
	if err != nil {
		return err
	}
	defer func() { _ = t.Close() }()
	unique := make([]byte, tpm.NodeKeyUniqueSize)
	if _, err := rand.Read(unique); err != nil {
		return err
	}
	d, err := agent.OpenDevice(t, agent.DeviceConfig{EKType: cfg.ekType, NodeKeyUnique: unique, EventLogPath: cfg.TPM.EventLog})
	if err != nil {
		return err
	}
	defer d.Close()
	return fn(d)
}

func newAgent(cfg *Config, log *slog.Logger, t agent.TPM) (*agent.Agent, error) {
	bundle, err := cfg.loadBundle()
	if err != nil {
		return nil, err
	}
	return agent.New(agent.Config{NodeID: cfg.NodeID, TrustDomain: cfg.TrustDomain, Bundle: bundle,
		Addr: cfg.ControlPlane, TPM: t, Log: log})
}

// run serves the Workload API and keeps the node attested until ctx is
// done or the listener fails. ready, if non-nil, is called once the socket
// accepts connections.
func run(ctx context.Context, cfg *Config, log *slog.Logger, t agent.TPM, ready func()) error {
	a, err := newAgent(cfg, log, t)
	if err != nil {
		return err
	}
	l, err := api.ListenUnix(cfg.WorkloadSocket, cfg.mode, cfg.socketGID())
	if err != nil {
		return err
	}
	srv := a.NewWorkloadServer()
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(agent.LimitListener(l, agent.MaxWorkloadConns)) }()

	attestCtx, stopAttest := context.WithCancel(ctx)
	defer stopAttest()
	attested := make(chan struct{})
	go func() {
		defer close(attested)
		_ = a.Run(attestCtx)
	}()
	log.Info("attest-agent serving", "version", version, "node_id", cfg.NodeID, "trust_domain", cfg.TrustDomain,
		"control_plane", cfg.ControlPlane, "workload_socket", cfg.WorkloadSocket)
	if ready != nil {
		ready()
	}

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-serveErr:
		runErr = fmt.Errorf("workload listener: %w", err)
	}
	log.Info("attest-agent stopping")
	// Drain workload calls while the node identity they use still exists,
	// then drop it.
	done := make(chan struct{})
	go func() { srv.GracefulStop(); close(done) }()
	select {
	case <-done:
	case <-time.After(shutdownTimeout):
		srv.Stop()
		<-done
	}
	stopAttest()
	<-attested
	return runErr
}
