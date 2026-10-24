// Package verifiertest provides software stand-ins for TPM attestation
// evidence. It lets tests craft quotes, including ones a real TPM would never
// produce, without a TPM.
package verifiertest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/0xciph3r/attest/internal/eventlog"
	"github.com/0xciph3r/attest/internal/policy"
	"github.com/0xciph3r/attest/internal/tpm"
)

// BootPCRs are the PCRs eventlog.SimulatedBoot measures.
var BootPCRs = []uint32{0, 1, 2, 3, 4, 5, 6, 7}

// AK is a software attestation key with the exact public template of a
// TPM-resident Attest AK.
type AK struct {
	Key    *ecdsa.PrivateKey
	Public tpm2.TPMTPublic
	Name   []byte
}

// NewAK generates a software AK.
func NewAK(t testing.TB) *AK {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := tpm.AKTemplate
	e, err := key.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	raw := e.Bytes()
	pub.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: raw[1:33]},
		Y: tpm2.TPM2BECCParameter{Buffer: raw[33:]},
	})
	name, err := tpm2.ObjectName(&pub)
	if err != nil {
		t.Fatal(err)
	}
	return &AK{Key: key, Public: pub, Name: name.Buffer}
}

// PublicBytes returns the marshaled TPMT_PUBLIC.
func (a *AK) PublicBytes() []byte { return tpm2.Marshal(a.Public) }

// Attest returns the TPMS_ATTEST a TPM would produce quoting pcrs.
func (a *AK) Attest(nonce []byte, pcrs map[uint32][]byte) tpm2.TPMSAttest {
	keys := make([]uint32, 0, len(pcrs))
	for k := range pcrs {
		keys = append(keys, k)
	}
	sel, _ := tpm.PCRSelection(keys)
	return tpm2.TPMSAttest{
		Magic:           tpm2.TPMGeneratedValue,
		Type:            tpm2.TPMSTAttestQuote,
		QualifiedSigner: tpm2.TPM2BName{Buffer: a.Name},
		ExtraData:       tpm2.TPM2BData{Buffer: nonce},
		ClockInfo:       tpm2.TPMSClockInfo{Clock: 1000, ResetCount: 2, RestartCount: 3, Safe: true},
		FirmwareVersion: 42,
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: sel,
			PCRDigest: tpm2.TPM2BDigest{Buffer: tpm.PCRDigest(pcrs)},
		}),
	}
}

// Sign returns a marshaled ECDSA-SHA256 TPMT_SIGNATURE over msg.
func (a *AK) Sign(t testing.TB, msg []byte) []byte {
	t.Helper()
	d := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, a.Key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return tpm2.Marshal(tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgECDSA,
		Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
			Hash:       tpm2.TPMAlgSHA256,
			SignatureR: tpm2.TPM2BECCParameter{Buffer: r.FillBytes(make([]byte, 32))},
			SignatureS: tpm2.TPM2BECCParameter{Buffer: s.FillBytes(make([]byte, 32))},
		}),
	})
}

// Quote returns a signed quote over pcrs.
func (a *AK) Quote(t testing.TB, nonce []byte, pcrs map[uint32][]byte) (attest, sig []byte) {
	t.Helper()
	attest = tpm2.Marshal(a.Attest(nonce, pcrs))
	return attest, a.Sign(t, attest)
}

// PolicyJSON returns a measurement policy over BootPCRs admitting each boot.
func PolicyJSON(t testing.TB, allowDevelopmentRoots bool, boots ...*eventlog.Builder) []byte {
	t.Helper()
	m := policy.Measurement{
		Schema:                policy.SchemaMeasurementV1,
		PCRs:                  BootPCRs,
		References:            []policy.Reference{},
		AllowDevelopmentRoots: allowDevelopmentRoots,
	}
	for i, b := range boots {
		ref := policy.Reference{Name: "boot" + strconv.Itoa(i), PCRs: map[string]string{}}
		for p, v := range b.PCRs(BootPCRs...) {
			ref.PCRs[strconv.Itoa(int(p))] = hex.EncodeToString(v)
		}
		m.References = append(m.References, ref)
	}
	doc, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}
