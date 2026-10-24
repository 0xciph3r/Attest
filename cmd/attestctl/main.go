// Command attestctl is the Attest operator CLI.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/0xciph3r/attest/internal/audit"
	"github.com/0xciph3r/attest/internal/policy"
)

// Exit codes. Verification failures are distinguished from operational errors
// so that scripts and CI can tell "the evidence is bad" from "the check could
// not run".
const (
	exitOK                 = 0
	exitVerificationFailed = 1
	exitError              = 2
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	root := newRootCmd()
	root.SetArgs(args)
	err := root.Execute()
	if err == nil {
		return exitOK
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	if isVerificationFailure(err) {
		return exitVerificationFailed
	}
	return exitError
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "attestctl",
		Short:         "Operate and audit an Attest control plane",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newAuditCmd(), newPolicyCmd())
	return root
}

func isVerificationFailure(err error) bool {
	var ve *audit.VerifyError
	return errors.As(err, &ve) ||
		errors.Is(err, audit.ErrCheckpointSignature) ||
		errors.Is(err, audit.ErrUnknownKey) ||
		errors.Is(err, audit.ErrUnanchored) ||
		errors.Is(err, policy.ErrInvalid)
}
