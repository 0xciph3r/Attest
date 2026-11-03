package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/0xciph3r/attest/internal/policy"
)

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Validate measurement and workload policies",
	}
	cmd.AddCommand(newPolicyValidateCmd())
	return cmd
}

func newPolicyValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate FILE",
		Short: "Check a policy offline",
		Long: `Parse a measurement or workload policy (chosen by its "schema" field) with
the same strict rules the control plane applies, and print its digest and
contents. Nothing is contacted or changed.

Exit status: 0 valid, 1 invalid, 2 the file could not be read.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			doc, err := io.ReadAll(io.LimitReader(f, policy.MaxPolicySize+1))
			if err != nil {
				return err
			}
			var head struct {
				Schema string `json:"schema"`
			}
			if err := json.Unmarshal(doc, &head); err != nil {
				return fmt.Errorf("%w: %w", policy.ErrInvalid, err)
			}
			switch head.Schema {
			case policy.SchemaMeasurementV1:
				return printMeasurement(cmd.OutOrStdout(), doc)
			case policy.SchemaWorkloadV1:
				return printWorkload(cmd.OutOrStdout(), doc)
			}
			return fmt.Errorf("%w: unknown schema %q", policy.ErrInvalid, head.Schema)
		},
	}
}

func printWorkload(w io.Writer, doc []byte) error {
	p, err := policy.ParseWorkload(doc)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "OK: %s\n", p.Schema)
	fmt.Fprintf(w, "digest: %s\n", hex.EncodeToString(p.Digest()))
	fmt.Fprintf(w, "workloads: %d\n", len(p.Workloads))
	for _, wl := range p.Workloads {
		fmt.Fprintf(w, "  - %s: %s uid %d on %v, ttl %s\n", wl.Name, wl.SystemdUnit, *wl.UID, wl.Nodes, wl.Lifetime())
	}
	if len(p.Workloads) == 0 {
		fmt.Fprintln(w, "WARNING: no workloads; this policy identifies nothing")
	}
	return nil
}

func printMeasurement(w io.Writer, doc []byte) error {
	m, err := policy.ParseMeasurement(doc)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "OK: %s\n", m.Schema)
	fmt.Fprintf(w, "digest: %s\n", hex.EncodeToString(m.Digest()))
	fmt.Fprintf(w, "pcrs: %v\n", m.PCRs)
	fmt.Fprintf(w, "references: %d\n", len(m.References))
	for _, r := range m.References {
		var free []uint32
		for _, p := range m.PCRs {
			if _, ok := r.PCRs[strconv.Itoa(int(p))]; !ok {
				free = append(free, p)
			}
		}
		if len(free) == 0 {
			fmt.Fprintf(w, "  - %s\n", r.Name)
		} else {
			fmt.Fprintf(w, "  - %s (WARNING: PCRs %v are quoted and replayed but accept any value)\n", r.Name, free)
		}
	}
	if len(m.References) == 0 {
		fmt.Fprintln(w, "WARNING: no references; this policy admits no machine")
	}
	if m.AllowDevelopmentRoots {
		fmt.Fprintln(w, "WARNING: allow_development_roots is set; never use this policy in production")
	}
	return nil
}
