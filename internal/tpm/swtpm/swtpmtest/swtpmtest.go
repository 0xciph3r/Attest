// Package swtpmtest connects tests to the development swtpm started by
// `make swtpm-up`.
package swtpmtest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0xciph3r/attest/internal/tpm/swtpm"
)

// TPM is a reset swtpm connection plus the development EK root directory.
type TPM struct {
	*swtpm.Conn
	// Dir holds ek-root.pem and ek-intermediate.pem.
	Dir string
}

// Open connects to the swtpm configured through ATTEST_SWTPM_ADDR,
// ATTEST_SWTPM_CTRL and ATTEST_SWTPM_DIR and resets it. It fails (rather
// than skips) when the environment is missing: the swtpm build tag is an
// explicit request to run these tests.
func Open(t testing.TB) *TPM {
	t.Helper()
	addr, ctrl, dir := os.Getenv("ATTEST_SWTPM_ADDR"), os.Getenv("ATTEST_SWTPM_CTRL"), os.Getenv("ATTEST_SWTPM_DIR")
	if addr == "" || ctrl == "" || dir == "" {
		t.Fatal("ATTEST_SWTPM_ADDR, ATTEST_SWTPM_CTRL and ATTEST_SWTPM_DIR must be set; run `make swtpm-up test-tpm`")
	}
	c, err := swtpm.Dial(addr, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.Reset(); err != nil {
		t.Fatal(err)
	}
	return &TPM{Conn: c, Dir: dir}
}

// ReadFile reads a file from the swtpm output directory.
func (t *TPM) ReadFile(tb testing.TB, name string) []byte {
	tb.Helper()
	b, err := os.ReadFile(filepath.Join(t.Dir, name))
	if err != nil {
		tb.Fatal(err)
	}
	return b
}
