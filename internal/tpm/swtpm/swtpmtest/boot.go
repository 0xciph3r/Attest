package swtpmtest

import (
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/0xciph3r/attest/internal/eventlog"
)

// Boot extends the events of a simulated measured boot into the TPM's
// SHA-256 PCRs, as firmware would, so that b.Bytes() is a truthful event log
// for the resulting PCR values. Call it right after Open (which resets PCRs).
func (t *TPM) Boot(tb testing.TB, b *eventlog.Builder) {
	tb.Helper()
	for _, ev := range b.Events() {
		t.Extend(tb, ev.PCR, ev.Digest)
	}
}

// Extend extends one SHA-256 digest into pcr.
func (t *TPM) Extend(tb testing.TB, pcr uint32, digest []byte) {
	tb.Helper()
	_, err := tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(pcr), Auth: tpm2.PasswordAuth(nil)},
		Digests: tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{
			{HashAlg: tpm2.TPMAlgSHA256, Digest: digest},
		}},
	}.Execute(t)
	if err != nil {
		tb.Fatalf("extending PCR %d: %v", pcr, err)
	}
}
