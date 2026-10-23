//go:build swtpm

package swtpm_test

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/0xciph3r/attest/internal/tpm/swtpm/swtpmtest"
)

func pcr(t *testing.T, tpm *swtpmtest.TPM, idx uint) []byte {
	t.Helper()
	rsp, err := tpm2.PCRRead{PCRSelectionIn: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{
		{Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(idx)},
	}}}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}
	return rsp.PCRValues.Digests[0].Buffer
}

func TestResetZeroesPCRs(t *testing.T) {
	tpm := swtpmtest.Open(t)
	if _, err := (tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(7), Auth: tpm2.PasswordAuth(nil)},
		Digests:   tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMAlgSHA256, Digest: make([]byte, 32)}}},
	}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(pcr(t, tpm, 7), make([]byte, 32)) {
		t.Fatal("PCR 7 not extended")
	}
	if err := tpm.Reset(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pcr(t, tpm, 7), make([]byte, 32)) {
		t.Fatal("PCR 7 not reset")
	}
}
