// Command attest-agent is the Attest node agent. It proves the node's
// measured boot to attestd with the TPM, holds the node identity that
// results, and serves workload identities to local services.
package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/0xciph3r/attest/internal/agent"
	"github.com/0xciph3r/attest/internal/tpm"
)

// version is set at build time.
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := newRootCmd().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "attest-agent",
		Short:         "Attest node agent",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	var configPath string
	root.PersistentFlags().StringVar(&configPath, "config", "/etc/attest/agent.json", "configuration file")
	logger := func() *slog.Logger { return slog.New(slog.NewJSONHandler(os.Stderr, nil)) }

	ekCertCmd := &cobra.Command{
		Use:   "ek-cert",
		Short: "Print the TPM's EK certificate for the operator to register the node with",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := LoadConfig(configPath)
			if err != nil {
				return err
			}
			t, err := openTPM(cfg.TPM)
			if err != nil {
				return err
			}
			defer func() { _ = t.Close() }()
			der, err := tpm.ReadEKCert(t, cfg.ekType)
			if err != nil {
				return err
			}
			return pem.Encode(cmd.OutOrStdout(), &pem.Block{Type: "CERTIFICATE", Bytes: der})
		},
	}
	enrollCmd := &cobra.Command{
		Use:   "enroll",
		Short: "Prove to attestd that the attestation key is in the registered TPM",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := LoadConfig(configPath)
			if err != nil {
				return err
			}
			err = withDevice(cfg, func(d *agent.Device) error {
				a, err := newAgent(cfg, logger(), d)
				if err != nil {
					return err
				}
				return a.Enroll(cmd.Context())
			})
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "node %s enrolled\n", cfg.NodeID)
			return err
		},
	}
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Attest the node, keep its identity renewed and serve the Workload API",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := LoadConfig(configPath)
			if err != nil {
				return err
			}
			return withDevice(cfg, func(d *agent.Device) error {
				return run(cmd.Context(), cfg, logger(), d, nil)
			})
		},
	}
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), version)
			return err
		},
	}
	root.AddCommand(ekCertCmd, enrollCmd, runCmd, versionCmd)
	return root
}
