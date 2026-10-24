package verifier

import (
	"bytes"
	"crypto/rand"
	"maps"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/0xciph3r/attest/internal/eventlog"
)

func TestVerifyEvidenceAccepts(t *testing.T) {
	f := newFixture(t)
	res, err := VerifyEvidence(f.ak.ak, f.nonce, f.policy, f.ev)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reference != "boot0" || res.Events != len(f.boot.Events()) {
		t.Fatalf("unexpected result %+v", res)
	}
	if res.Quote.ResetCount != 2 || res.Quote.RestartCount != 3 || res.Quote.FirmwareVersion != 42 {
		t.Fatalf("clock info not propagated: %+v", res.Quote)
	}
}

func TestVerifyEvidenceRejects(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, f *fixture)
		want   Reason
	}{
		{"signature by another key", func(t *testing.T, f *fixture) {
			f.ev.Signature = newSoftAK(t).sign(t, f.ev.Attest)
		}, ReasonBadSignature},
		{"attest modified after signing", func(_ *testing.T, f *fixture) {
			f.ev.Attest = bytes.Clone(f.ev.Attest)
			f.ev.Attest[len(f.ev.Attest)-1] ^= 1
		}, ReasonBadSignature},
		{"signature from another quote", func(t *testing.T, f *fixture) {
			other := tpm2.Marshal(f.ak.attest([]byte("other nonce"), f.ev.PCRs))
			f.ev.Signature = f.ak.sign(t, other)
		}, ReasonBadSignature},
		{"non-ECDSA signature", func(_ *testing.T, f *fixture) {
			f.ev.Signature = tpm2.Marshal(tpm2.TPMTSignature{
				SigAlg: tpm2.TPMAlgRSASSA,
				Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgRSASSA, &tpm2.TPMSSignatureRSA{
					Hash: tpm2.TPMAlgSHA256, Sig: tpm2.TPM2BPublicKeyRSA{Buffer: make([]byte, 256)},
				}),
			})
		}, ReasonBadSignature},
		{"SHA-1 signature", func(_ *testing.T, f *fixture) {
			sig, _ := tpm2.Unmarshal[tpm2.TPMTSignature](f.ev.Signature)
			ec, _ := sig.Signature.ECDSA()
			ec.Hash = tpm2.TPMAlgSHA1
			f.ev.Signature = tpm2.Marshal(tpm2.TPMTSignature{SigAlg: tpm2.TPMAlgECDSA, Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, ec)})
		}, ReasonBadSignature},
		{"garbage signature", func(_ *testing.T, f *fixture) {
			f.ev.Signature = []byte{0, 0x18, 1}
		}, ReasonMalformed},
		{"signature with trailing bytes", func(_ *testing.T, f *fixture) {
			f.ev.Signature = append(bytes.Clone(f.ev.Signature), 0)
		}, ReasonMalformed},
		{"signed attest with trailing bytes", func(t *testing.T, f *fixture) {
			f.ev.Attest = append(bytes.Clone(f.ev.Attest), 0)
			f.ev.Signature = f.ak.sign(t, f.ev.Attest)
		}, ReasonMalformed},
		{"signed non-TPM-generated data", func(t *testing.T, f *fixture) {
			f.ev.Attest = []byte("arbitrary data signed by a non-restricted key")
			f.ev.Signature = f.ak.sign(t, f.ev.Attest)
		}, ReasonMalformed},
		{"signed attestation that is not a quote", func(t *testing.T, f *fixture) {
			a := f.ak.attest(f.nonce, f.ev.PCRs)
			a.Type = tpm2.TPMSTAttestTime
			a.Attested = tpm2.NewTPMUAttest(tpm2.TPMSTAttestTime, &tpm2.TPMSTimeAttestInfo{})
			f.ev.Attest = tpm2.Marshal(a)
			f.ev.Signature = f.ak.sign(t, f.ev.Attest)
		}, ReasonNotQuote},
		{"quote for another challenge (replay)", func(t *testing.T, f *fixture) {
			f.nonce = make([]byte, 32)
			_, _ = rand.Read(f.nonce)
		}, ReasonNonceMismatch},
		{"empty expected nonce", func(_ *testing.T, f *fixture) {
			f.nonce = nil
		}, ReasonNonceMismatch},
		{"quote over fewer PCRs", func(t *testing.T, f *fixture) {
			pcrs := maps.Clone(f.ev.PCRs)
			delete(pcrs, 7)
			f.ev.Attest = tpm2.Marshal(f.ak.attest(f.nonce, pcrs))
			f.ev.Signature = f.ak.sign(t, f.ev.Attest)
			f.ev.PCRs = pcrs
		}, ReasonPCRSelection},
		{"claimed PCR omitted", func(_ *testing.T, f *fixture) {
			delete(f.ev.PCRs, 7)
		}, ReasonPCRSelection},
		{"claimed PCR value altered", func(_ *testing.T, f *fixture) {
			f.ev.PCRs[7] = make([]byte, 32)
		}, ReasonPCRDigest},
		{"claimed PCR value wrong size", func(_ *testing.T, f *fixture) {
			f.ev.PCRs[7] = make([]byte, 20)
		}, ReasonMalformed},
		{"oversized attest", func(_ *testing.T, f *fixture) {
			f.ev.Attest = make([]byte, MaxAttestSize+1)
		}, ReasonMalformed},
		{"empty event log", func(_ *testing.T, f *fixture) {
			f.ev.EventLog = nil
		}, ReasonEventLogInvalid},
		{"truncated event log", func(_ *testing.T, f *fixture) {
			f.ev.EventLog = f.ev.EventLog[:len(f.ev.EventLog)-1]
		}, ReasonEventLogInvalid},
		{"event log from another boot", func(_ *testing.T, f *fixture) {
			f.ev.EventLog = eventlog.SimulatedBoot("v2").Bytes()
		}, ReasonEventLogReplay},
		{"measurements not in policy", func(t *testing.T, f *fixture) {
			f.policy = policyFor(t, eventlog.SimulatedBoot("v2"))
		}, ReasonMeasurement},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			tt.mutate(t, f)
			_, err := VerifyEvidence(f.ak.ak, f.nonce, f.policy, f.ev)
			if got := ReasonOf(err); got != tt.want {
				t.Fatalf("got reason %q (%v), want %q", got, err, tt.want)
			}
		})
	}
}

func TestVerifyEvidenceRequiresPolicy(t *testing.T) {
	f := newFixture(t)
	if _, err := VerifyEvidence(f.ak.ak, f.nonce, nil, f.ev); err == nil {
		t.Fatal("nil policy accepted")
	}
}

func TestPolicyWithAlternativeReference(t *testing.T) {
	f := newFixture(t)
	f.policy = policyFor(t, eventlog.SimulatedBoot("v2"), f.boot)
	res, err := VerifyEvidence(f.ak.ak, f.nonce, f.policy, f.ev)
	if err != nil || res.Reference != "boot1" {
		t.Fatalf("got %+v, %v", res, err)
	}
}

func TestParseAKRejects(t *testing.T) {
	good := newSoftAK(t).pub
	mods := map[string]func(p *tpm2.TPMTPublic){
		"decrypt allowed":   func(p *tpm2.TPMTPublic) { p.ObjectAttributes.Decrypt = true },
		"not restricted":    func(p *tpm2.TPMTPublic) { p.ObjectAttributes.Restricted = false },
		"not fixedTPM":      func(p *tpm2.TPMTPublic) { p.ObjectAttributes.FixedTPM = false },
		"not TPM generated": func(p *tpm2.TPMTPublic) { p.ObjectAttributes.SensitiveDataOrigin = false },
		"SHA-1 name":        func(p *tpm2.TPMTPublic) { p.NameAlg = tpm2.TPMAlgSHA1 },
		"auth policy":       func(p *tpm2.TPMTPublic) { p.AuthPolicy = tpm2.TPM2BDigest{Buffer: make([]byte, 32)} },
		"point not on curve": func(p *tpm2.TPMTPublic) {
			p.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: bytes.Repeat([]byte{1}, 32)},
				Y: tpm2.TPM2BECCParameter{Buffer: bytes.Repeat([]byte{2}, 32)},
			})
		},
		"SHA-1 scheme": func(p *tpm2.TPMTPublic) {
			parms, _ := p.Parameters.ECCDetail()
			c := *parms
			c.Scheme.Details = tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA1})
			p.Parameters = tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &c)
		},
		"RSA key": func(p *tpm2.TPMTPublic) { *p = tpm2.RSASRKTemplate },
	}
	for name, mod := range mods {
		t.Run(name, func(t *testing.T) {
			p := good
			mod(&p)
			if _, err := ParseAK(tpm2.Marshal(p)); ReasonOf(err) != ReasonAKInvalid {
				t.Fatalf("got %v", err)
			}
		})
	}
	t.Run("EK template", func(t *testing.T) {
		if _, err := ParseAK(tpm2.Marshal(tpm2.ECCEKTemplate)); ReasonOf(err) != ReasonAKInvalid {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("trailing bytes", func(t *testing.T) {
		if _, err := ParseAK(append(tpm2.Marshal(good), 0)); ReasonOf(err) != ReasonAKInvalid {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("name matches go-tpm", func(t *testing.T) {
		ak, err := ParseAK(tpm2.Marshal(good))
		if err != nil {
			t.Fatal(err)
		}
		want, _ := tpm2.ObjectName(&good)
		if !bytes.Equal(ak.Name, want.Buffer) || ak.Name[0] != 0 || ak.Name[1] != 0x0b {
			t.Fatal("unexpected AK name")
		}
	})
}
