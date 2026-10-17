package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/0xciph3r/attest/internal/audit"
	"github.com/0xciph3r/attest/internal/store"
)

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Verify, export and checkpoint the audit ledger",
		Long: `Offline audit-ledger tools.

These commands read a database file or a JSONL export directly and do not
contact attestd, so an auditor does not have to trust the control plane to
check its own records. Verification is only meaningful against a trusted
checkpoint kept outside the control plane.`,
	}
	cmd.AddCommand(newAuditVerifyCmd(), newAuditExportCmd(), newAuditCheckpointCmd(), newAuditKeygenCmd())
	return cmd
}

// ledgerSource selects exactly one of a database or an export file.
type ledgerSource struct {
	db    string
	input string
}

func (s *ledgerSource) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&s.db, "db", "", "path to an attestd SQLite database (opened read-only)")
	cmd.Flags().StringVar(&s.input, "input", "", "path to a JSONL export produced by 'attestctl audit export'")
	cmd.MarkFlagsMutuallyExclusive("db", "input")
	cmd.MarkFlagsOneRequired("db", "input")
}

func (s *ledgerSource) open(ctx context.Context) (iter.Seq2[audit.Entry, error], func(), error) {
	if s.db != "" {
		st, err := store.OpenReadOnly(ctx, s.db)
		if err != nil {
			return nil, nil, err
		}
		return st.AuditEntries(ctx), func() { _ = st.Close() }, nil
	}
	f, err := os.Open(s.input)
	if err != nil {
		return nil, nil, err
	}
	return audit.ReadJSONL(f), func() { _ = f.Close() }, nil
}

// trustOptions are the checkpoint and key flags shared by verify and
// checkpoint.
type trustOptions struct {
	checkpoints []string
	pubkeys     []string
}

func (t *trustOptions) register(cmd *cobra.Command) {
	cmd.Flags().StringArrayVar(&t.checkpoints, "checkpoint", nil, "trusted signed checkpoint file (repeatable)")
	cmd.Flags().StringArrayVar(&t.pubkeys, "pubkey", nil, "trusted checkpoint public key, PEM (repeatable)")
}

func (t *trustOptions) load(extra ...audit.KeyRing) ([]audit.SignedCheckpoint, audit.KeyRing, error) {
	keys := audit.KeyRing{}
	for _, r := range extra {
		for id, k := range r {
			keys[id] = k
		}
	}
	for _, p := range t.pubkeys {
		k, err := audit.LoadPublicKey(p)
		if err != nil {
			return nil, nil, err
		}
		keys[audit.KeyID(k)] = k
	}
	var cps []audit.SignedCheckpoint
	for _, p := range t.checkpoints {
		cp, err := readCheckpoint(p)
		if err != nil {
			return nil, nil, err
		}
		cps = append(cps, cp)
	}
	if len(cps) > 0 && len(keys) == 0 {
		return nil, nil, errors.New("--checkpoint requires at least one --pubkey")
	}
	return cps, keys, nil
}

func newAuditVerifyCmd() *cobra.Command {
	var (
		src             ledgerSource
		trust           trustOptions
		allowUnanchored bool
	)
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify ledger integrity against trusted checkpoints",
		Long: `Verify that the ledger is a contiguous, correctly hashed chain and that it
matches every supplied trusted checkpoint. Alteration, reordering and
truncation relative to a checkpoint are reported.

Exit status: 0 verified, 1 verification failed, 2 the check could not run.`,
		Example: `  attestctl audit verify --db /var/lib/attest/attest.db \
      --pubkey auditor.pub --checkpoint cp-2026-10-17.json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cps, keys, err := trust.load()
			if err != nil {
				return err
			}
			entries, closeFn, err := src.open(cmd.Context())
			if err != nil {
				return err
			}
			defer closeFn()
			rep, err := audit.Verify(entries, audit.VerifyOptions{Checkpoints: cps, Keys: keys, AllowUnanchored: allowUnanchored})
			if err != nil {
				if errors.Is(err, audit.ErrUnanchored) {
					return fmt.Errorf("%w; pass --checkpoint and --pubkey, or --allow-unanchored to check internal consistency only", err)
				}
				return err
			}
			printReport(cmd.OutOrStdout(), rep)
			return nil
		},
	}
	src.register(cmd)
	trust.register(cmd)
	cmd.Flags().BoolVar(&allowUnanchored, "allow-unanchored", false, "accept a ledger with no trusted checkpoint (internal consistency only)")
	return cmd
}

func printReport(w io.Writer, rep audit.Report) {
	fmt.Fprintf(w, "OK: %d entries verified\n", rep.Head.Sequence)
	fmt.Fprintf(w, "head: seq=%d hash=%s\n", rep.Head.Sequence, rep.Head.Hash)
	if rep.CheckpointsVerified == 0 {
		fmt.Fprintln(w, "WARNING: no trusted checkpoint; this shows internal consistency only, not absence of tampering")
		return
	}
	fmt.Fprintf(w, "anchored through seq=%d by %d checkpoint(s)\n", rep.AnchoredThrough, rep.CheckpointsVerified)
	if n := rep.Unanchored(); n > 0 {
		fmt.Fprintf(w, "note: %d entries after the latest checkpoint are not yet anchored\n", n)
	}
}

func newAuditExportCmd() *cobra.Command {
	var db, output string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the ledger as JSON Lines",
		Long: `Export the ledger as JSON Lines for archival or independent verification.
An export has no integrity of its own; verify it against a trusted checkpoint.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := store.OpenReadOnly(cmd.Context(), db)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			var n uint64
			if output == "" || output == "-" {
				n, err = audit.WriteJSONL(cmd.OutOrStdout(), st.AuditEntries(cmd.Context()))
			} else {
				n, err = exportToFile(output, st.AuditEntries(cmd.Context()))
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "exported %d entries\n", n)
			return nil
		},
	}
	cmd.Flags().StringVar(&db, "db", "", "path to an attestd SQLite database (opened read-only)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file (default stdout); refuses to overwrite")
	_ = cmd.MarkFlagRequired("db")
	return cmd
}

func newAuditCheckpointCmd() *cobra.Command {
	var (
		src     ledgerSource
		trust   trustOptions
		keyPath string
		output  string
	)
	cmd := &cobra.Command{
		Use:   "checkpoint",
		Short: "Verify the ledger and sign its current head",
		Long: `Verify the ledger and write a signed checkpoint of its head.

Run this with a key that is NOT stored on the control plane, and keep the
resulting checkpoint files outside the control plane (for example in
write-once storage or a separate repository). Supply earlier checkpoints with
--checkpoint so the new one only extends history that was already trusted.`,
		Example: `  attestctl audit checkpoint --db attest.db --key auditor.key \
      --checkpoint cp-previous.json -o cp-$(date +%F).json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			key, err := audit.LoadPrivateKey(keyPath)
			if err != nil {
				return err
			}
			cps, keys, err := trust.load(audit.NewKeyRing(key.Public().(ed25519.PublicKey)))
			if err != nil {
				return err
			}
			entries, closeFn, err := src.open(cmd.Context())
			if err != nil {
				return err
			}
			defer closeFn()
			rep, err := audit.Verify(entries, audit.VerifyOptions{Checkpoints: cps, Keys: keys, AllowUnanchored: true})
			if err != nil {
				return err
			}
			if len(cps) == 0 {
				fmt.Fprintln(cmd.ErrOrStderr(), "WARNING: no prior checkpoint supplied; this checkpoint trusts the ledger as it exists now")
			}
			cp, err := audit.SignCheckpoint(rep.Head, time.Now(), key)
			if err != nil {
				return err
			}
			if err := writeCheckpoint(output, cp); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "checkpoint: seq=%d hash=%s key=%s -> %s\n", cp.Sequence, cp.Hash, cp.KeyID, output)
			return nil
		},
	}
	src.register(cmd)
	trust.register(cmd)
	cmd.Flags().StringVar(&keyPath, "key", "", "checkpoint signing key, PEM PKCS#8 Ed25519 (mode 0600)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "checkpoint output file; refuses to overwrite")
	_ = cmd.MarkFlagRequired("key")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

func newAuditKeygenCmd() *cobra.Command {
	var priv, pub string
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an Ed25519 checkpoint signing key pair",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			k, err := audit.GenerateKeyFiles(priv, pub)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "key id: %s\nprivate: %s (0600)\npublic:  %s\n", audit.KeyID(k), priv, pub)
			return nil
		},
	}
	cmd.Flags().StringVar(&priv, "key", "", "private key output path")
	cmd.Flags().StringVar(&pub, "pub", "", "public key output path")
	_ = cmd.MarkFlagRequired("key")
	_ = cmd.MarkFlagRequired("pub")
	return cmd
}

func readCheckpoint(path string) (audit.SignedCheckpoint, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return audit.SignedCheckpoint{}, err
	}
	var cp audit.SignedCheckpoint
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cp); err != nil {
		return audit.SignedCheckpoint{}, fmt.Errorf("checkpoint %s: %w", path, err)
	}
	return cp, nil
}

func writeCheckpoint(path string, cp audit.SignedCheckpoint) error {
	b, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return err
	}
	// Checkpoints are signed public data; world-readable is intended.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) // #nosec G302
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func exportToFile(path string, entries iter.Seq2[audit.Entry, error]) (uint64, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, err
	}
	n, err := audit.WriteJSONL(f, entries)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return n, err
}
