package verifier

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"maps"
	"math/big"
	"slices"

	"github.com/google/go-tpm/tpm2"

	"github.com/0xciph3r/attest/internal/tpm"
)

// Size limits for untrusted quote inputs.
const (
	MaxAttestSize    = 2048
	MaxSignatureSize = 512
)

// Evidence is what a node submits in answer to a challenge.
type Evidence struct {
	Attest    []byte            // TPMS_ATTEST
	Signature []byte            // TPMT_SIGNATURE
	PCRs      map[uint32][]byte // claimed SHA-256 PCR values
	EventLog  []byte            // TCG crypto-agile event log
}

// QuoteInfo is the authenticated content of a verified quote.
type QuoteInfo struct {
	PCRs            map[uint32][]byte
	ResetCount      uint32
	RestartCount    uint32
	Clock           uint64
	FirmwareVersion uint64
}

// VerifyQuote authenticates a quote. In order, it requires that the
// signature is an ECDSA-SHA256 signature by ak over the exact attest bytes,
// that the attest structure is a TPM-generated quote whose qualifying data
// equals nonce, that it covers exactly the required SHA-256 PCRs, and that
// the claimed PCR values hash to the signed digest. Nothing from the attest
// structure is trusted before the signature check.
func VerifyQuote(ak *AK, nonce []byte, required []uint32, ev *Evidence) (*QuoteInfo, error) {
	if len(ev.Attest) == 0 || len(ev.Attest) > MaxAttestSize ||
		len(ev.Signature) == 0 || len(ev.Signature) > MaxSignatureSize {
		return nil, fail(ReasonMalformed, "quote or signature size out of range")
	}
	if err := verifySignature(ak, ev.Attest, ev.Signature); err != nil {
		return nil, err
	}
	attest, err := decode[tpm2.TPMSAttest](ev.Attest)
	if err != nil {
		return nil, wrap(ReasonMalformed, err)
	}
	if attest.Magic != tpm2.TPMGeneratedValue || attest.Type != tpm2.TPMSTAttestQuote {
		return nil, fail(ReasonNotQuote, "signed structure is not a TPM quote")
	}
	if len(nonce) == 0 || subtle.ConstantTimeCompare(attest.ExtraData.Buffer, nonce) != 1 {
		return nil, fail(ReasonNonceMismatch, "quote is not bound to the challenge")
	}
	info, err := attest.Attested.Quote()
	if err != nil {
		return nil, wrap(ReasonMalformed, err)
	}
	sel, err := tpm.PCRSelection(required)
	if err != nil {
		return nil, wrap(ReasonPCRSelection, err)
	}
	if !bytes.Equal(tpm2.Marshal(info.PCRSelect), tpm2.Marshal(sel)) {
		return nil, fail(ReasonPCRSelection, "quote covers a different PCR selection")
	}
	if !slices.Equal(slices.Sorted(maps.Keys(ev.PCRs)), slices.Sorted(slices.Values(required))) {
		return nil, fail(ReasonPCRSelection, "claimed PCR values do not match the required selection")
	}
	for p, v := range ev.PCRs {
		if len(v) != sha256.Size {
			return nil, fail(ReasonMalformed, "PCR %d value has %d bytes", p, len(v))
		}
	}
	if !bytes.Equal(info.PCRDigest.Buffer, tpm.PCRDigest(ev.PCRs)) {
		return nil, fail(ReasonPCRDigest, "claimed PCR values do not match the signed digest")
	}
	pcrs := make(map[uint32][]byte, len(ev.PCRs))
	for p, v := range ev.PCRs {
		pcrs[p] = bytes.Clone(v)
	}
	return &QuoteInfo{
		PCRs:            pcrs,
		ResetCount:      attest.ClockInfo.ResetCount,
		RestartCount:    attest.ClockInfo.RestartCount,
		Clock:           attest.ClockInfo.Clock,
		FirmwareVersion: attest.FirmwareVersion,
	}, nil
}

func verifySignature(ak *AK, attest, sigBytes []byte) error {
	sig, err := decode[tpm2.TPMTSignature](sigBytes)
	if err != nil {
		return wrap(ReasonMalformed, err)
	}
	if sig.SigAlg != tpm2.TPMAlgECDSA {
		return fail(ReasonBadSignature, "signature algorithm is not ECDSA")
	}
	ec, err := sig.Signature.ECDSA()
	if err != nil {
		return wrap(ReasonMalformed, err)
	}
	if ec.Hash != tpm2.TPMAlgSHA256 || len(ec.SignatureR.Buffer) > 32 || len(ec.SignatureS.Buffer) > 32 {
		return fail(ReasonBadSignature, "signature is not ECDSA-SHA256 over P-256")
	}
	digest := sha256.Sum256(attest)
	r := new(big.Int).SetBytes(ec.SignatureR.Buffer)
	s := new(big.Int).SetBytes(ec.SignatureS.Buffer)
	if !ecdsa.Verify(ak.Key, digest[:], r, s) {
		return fail(ReasonBadSignature, "signature does not verify under the enrolled AK")
	}
	return nil
}
