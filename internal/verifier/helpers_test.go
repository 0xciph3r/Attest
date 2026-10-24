package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/0xciph3r/attest/internal/eventlog"
	"github.com/0xciph3r/attest/internal/policy"
	"github.com/0xciph3r/attest/internal/tpm"
)

// softAK is a software stand-in for a TPM-resident AK. It lets unit tests
// craft quotes, including ones a real TPM would never produce.
type softAK struct {
	key *ecdsa.PrivateKey
	pub tpm2.TPMTPublic
	ak  *AK
}

func akPublic(key *ecdsa.PublicKey) tpm2.TPMTPublic {
	pub := tpm.AKTemplate
	e, _ := key.ECDH()
	raw := e.Bytes()
	pub.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: raw[1:33]},
		Y: tpm2.TPM2BECCParameter{Buffer: raw[33:]},
	})
	return pub
}

func newSoftAK(t *testing.T) *softAK {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := akPublic(&key.PublicKey)
	ak, err := ParseAK(tpm2.Marshal(pub))
	if err != nil {
		t.Fatal(err)
	}
	return &softAK{key: key, pub: pub, ak: ak}
}

func (s *softAK) attest(nonce []byte, pcrs map[uint32][]byte) tpm2.TPMSAttest {
	keys := make([]uint32, 0, len(pcrs))
	for k := range pcrs {
		keys = append(keys, k)
	}
	sel, _ := tpm.PCRSelection(keys)
	return tpm2.TPMSAttest{
		Magic:           tpm2.TPMGeneratedValue,
		Type:            tpm2.TPMSTAttestQuote,
		QualifiedSigner: tpm2.TPM2BName{Buffer: s.ak.Name},
		ExtraData:       tpm2.TPM2BData{Buffer: nonce},
		ClockInfo:       tpm2.TPMSClockInfo{Clock: 1000, ResetCount: 2, RestartCount: 3, Safe: true},
		FirmwareVersion: 42,
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: sel,
			PCRDigest: tpm2.TPM2BDigest{Buffer: tpm.PCRDigest(pcrs)},
		}),
	}
}

func (s *softAK) sign(t *testing.T, msg []byte) []byte {
	t.Helper()
	d := sha256.Sum256(msg)
	r, ss, err := ecdsa.Sign(rand.Reader, s.key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return tpm2.Marshal(tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgECDSA,
		Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
			Hash:       tpm2.TPMAlgSHA256,
			SignatureR: tpm2.TPM2BECCParameter{Buffer: r.FillBytes(make([]byte, 32))},
			SignatureS: tpm2.TPM2BECCParameter{Buffer: ss.FillBytes(make([]byte, 32))},
		}),
	})
}

var bootPCRs = []uint32{0, 1, 2, 3, 4, 5, 6, 7}

// fixture is a valid evidence bundle for a simulated boot.
type fixture struct {
	ak     *softAK
	nonce  []byte
	boot   *eventlog.Builder
	policy *policy.Measurement
	ev     *Evidence
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{ak: newSoftAK(t), nonce: make([]byte, 32), boot: eventlog.SimulatedBoot("v1")}
	_, _ = rand.Read(f.nonce)
	f.policy = policyFor(t, f.boot)
	pcrs := f.boot.PCRs(bootPCRs...)
	attest := tpm2.Marshal(f.ak.attest(f.nonce, pcrs))
	f.ev = &Evidence{Attest: attest, Signature: f.ak.sign(t, attest), PCRs: pcrs, EventLog: f.boot.Bytes()}
	return f
}

func policyFor(t *testing.T, boots ...*eventlog.Builder) *policy.Measurement {
	t.Helper()
	doc := `{"schema":"` + policy.SchemaMeasurementV1 + `","pcrs":[0,1,2,3,4,5,6,7],"references":[`
	for i, b := range boots {
		if i > 0 {
			doc += ","
		}
		doc += `{"name":"boot` + string(rune('0'+i)) + `","pcrs":{`
		for j, p := range bootPCRs {
			if j > 0 {
				doc += ","
			}
			doc += `"` + string(rune('0'+p)) + `":"` + hexs(b.PCRs(p)[p]) + `"`
		}
		doc += `}}`
	}
	doc += `]}`
	m, err := policy.ParseMeasurement([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func hexs(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}
