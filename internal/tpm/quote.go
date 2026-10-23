package tpm

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// MaxPCR is the highest PC Client PCR index.
const MaxPCR = 23

// Quote is a TPM2_Quote result in TPM wire format plus the SHA-256 PCR
// values it covers. The verifier must not trust PCRs until it has checked
// them against the signed digest in Attest.
type Quote struct {
	Attest    []byte            // TPMS_ATTEST
	Signature []byte            // TPMT_SIGNATURE
	PCRs      map[uint32][]byte // SHA-256 bank
}

// NormalizePCRs returns pcrs sorted, rejecting duplicates and indices
// above MaxPCR.
func NormalizePCRs(pcrs []uint32) ([]uint32, error) {
	out := slices.Sorted(slices.Values(pcrs))
	for i, p := range out {
		if p > MaxPCR {
			return nil, fmt.Errorf("tpm: PCR %d out of range", p)
		}
		if i > 0 && out[i-1] == p {
			return nil, fmt.Errorf("tpm: duplicate PCR %d", p)
		}
	}
	return out, nil
}

// PCRSelection builds a SHA-256 bank selection for the given PCRs.
func PCRSelection(pcrs []uint32) (tpm2.TPMLPCRSelection, error) {
	idx := make([]uint, 0, len(pcrs))
	for _, p := range pcrs {
		if p > MaxPCR {
			return tpm2.TPMLPCRSelection{}, fmt.Errorf("tpm: PCR %d out of range", p)
		}
		idx = append(idx, uint(p))
	}
	return tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{
		{Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(idx...)},
	}}, nil
}

// PCRDigest is the TPM's pcrDigest for SHA-256 quotes: the hash of the
// selected PCR values concatenated in ascending index order.
func PCRDigest(pcrs map[uint32][]byte) []byte {
	keys := slices.Sorted(func(yield func(uint32) bool) {
		for k := range pcrs {
			if !yield(k) {
				return
			}
		}
	})
	h := sha256.New()
	for _, k := range keys {
		h.Write(pcrs[k])
	}
	return h.Sum(nil)
}

// ReadPCRs reads SHA-256 PCR values. TPM2_PCR_Read returns at most eight
// digests per call, so the read is chunked.
func ReadPCRs(t transport.TPM, pcrs []uint32) (map[uint32][]byte, error) {
	pcrs, err := NormalizePCRs(pcrs)
	if err != nil {
		return nil, err
	}
	out := make(map[uint32][]byte, len(pcrs))
	for chunk := range slices.Chunk(pcrs, 8) {
		sel, err := PCRSelection(chunk)
		if err != nil {
			return nil, err
		}
		rsp, err := tpm2.PCRRead{PCRSelectionIn: sel}.Execute(t)
		if err != nil {
			return nil, fmt.Errorf("tpm: PCR read: %w", err)
		}
		if len(rsp.PCRSelectionOut.PCRSelections) != 1 ||
			!bytes.Equal(rsp.PCRSelectionOut.PCRSelections[0].PCRSelect, sel.PCRSelections[0].PCRSelect) ||
			len(rsp.PCRValues.Digests) != len(chunk) {
			return nil, errors.New("tpm: PCR read returned a different selection")
		}
		for i, p := range chunk {
			out[p] = rsp.PCRValues.Digests[i].Buffer
		}
	}
	return out, nil
}

// maxQuoteAttempts bounds retries when PCRs change between quoting and
// reading them.
const maxQuoteAttempts = 3

// MakeQuote signs the SHA-256 values of pcrs with ak, binding nonce as
// qualifying data. The PCR values are read after the quote and checked
// against its digest so a concurrent extend causes a retry, not a
// mismatched evidence bundle.
func MakeQuote(t transport.TPM, ak *Key, nonce []byte, pcrs []uint32) (*Quote, error) {
	if len(pcrs) == 0 {
		return nil, errors.New("tpm: empty PCR selection")
	}
	pcrs, err := NormalizePCRs(pcrs)
	if err != nil {
		return nil, err
	}
	sel, err := PCRSelection(pcrs)
	if err != nil {
		return nil, err
	}
	for range maxQuoteAttempts {
		rsp, err := tpm2.Quote{
			SignHandle:     tpm2.AuthHandle{Handle: ak.Handle, Name: ak.Name, Auth: tpm2.PasswordAuth(nil)},
			QualifyingData: tpm2.TPM2BData{Buffer: nonce},
			InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
			PCRSelect:      sel,
		}.Execute(t)
		if err != nil {
			return nil, fmt.Errorf("tpm: quote: %w", err)
		}
		attest, err := rsp.Quoted.Contents()
		if err != nil {
			return nil, err
		}
		info, err := attest.Attested.Quote()
		if err != nil {
			return nil, err
		}
		values, err := ReadPCRs(t, pcrs)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(info.PCRDigest.Buffer, PCRDigest(values)) {
			return &Quote{
				Attest:    rsp.Quoted.Bytes(),
				Signature: tpm2.Marshal(rsp.Signature),
				PCRs:      values,
			}, nil
		}
	}
	return nil, errors.New("tpm: PCRs kept changing while quoting")
}
