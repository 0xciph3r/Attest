// Command attestd is the Attest control plane.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
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
		Use:           "attestd",
		Short:         "Attest control plane",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	var configPath string
	root.PersistentFlags().StringVar(&configPath, "config", "/etc/attest/attestd.json", "configuration file")

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Create the state directory, CA and database",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := LoadConfig(configPath)
			if err != nil {
				return err
			}
			fp, err := initState(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "initialized %s\nCA certificate SHA-256: %s\n", cfg.StateDir, fp)
			return err
		},
	}
	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve NodeService and AdminService",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := LoadConfig(configPath)
			if err != nil {
				return err
			}
			log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
			return serve(cmd.Context(), cfg, log, nil)
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
	root.AddCommand(initCmd, serveCmd, versionCmd)
	return root
}
