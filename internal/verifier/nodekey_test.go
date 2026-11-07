package verifier

import (
	"bytes"
	"crypto/elliptic"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/0xciph3r/attest/internal/eventlog"
	"github.com/0xciph3r/attest/internal/tpm"
	"github.com/0xciph3r/attest/internal/verifier/verifiertest"
)

// boundFixture is a valid evidence bundle that also binds a node key.
type boundFixture struct {
	*fixture
	key *verifiertest.NodeKey
}

func newBoundFixture(t *testing.T) *boundFixture {
	t.Helper()
	f := &boundFixture{fixture: newFixture(t), key: verifiertest.NewNodeKey(t)}
	b := f.ak.BoundEvidence(t, f.nonce, f.key, f.ev.PCRs)
	f.ev.Attest, f.ev.Signature = b.Attest, b.Signature
	f.ev.NodeKey = &KeyEvidence{Public: b.Public, Certify: b.Certify, CertifySignature: b.CertifySignature}
	return f
}

func (f *boundFixture) binding() []byte { return tpm.KeyBindingData(f.nonce, f.key.Name) }

// certify replaces the certification with a, signed by the fixture's AK.
func (f *boundFixture) certify(t *testing.T, a tpm2.TPMSAttest) {
	f.ev.NodeKey.Certify = tpm2.Marshal(a)
	f.ev.NodeKey.CertifySignature = f.ak.sign(t, f.ev.NodeKey.Certify)
}

func TestVerifyEvidenceBindsNodeKey(t *testing.T) {
	f := newBoundFixture(t)
	res, err := VerifyEvidence(f.ak.ak, f.nonce, f.policy, f.ev)
	if err != nil {
		t.Fatal(err)
	}
	if res.NodeKey == nil || !bytes.Equal(res.NodeKey.Name, f.key.Name) || !res.NodeKey.Key.Equal(&f.key.Key.PublicKey) {
		t.Fatalf("node key %+v", res.NodeKey)
	}
	want, err := ParseNodeKey(f.key.PublicBytes())
	if err != nil || !bytes.Equal(res.NodeKey.SPKIHash, want.SPKIHash) || len(want.SPKIHash) != 32 {
		t.Fatalf("SPKI hash %x, %v", res.NodeKey.SPKIHash, err)
	}
	// Without key evidence the result carries no key.
	plain := newFixture(t)
	if res, err := VerifyEvidence(plain.ak.ak, plain.nonce, plain.policy, plain.ev); err != nil || res.NodeKey != nil {
		t.Fatalf("plain: %+v, %v", res, err)
	}
}

func TestVerifyEvidenceRejectsKeyBinding(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, f *boundFixture)
		want   Reason
	}{
		{"quote over the bare nonce", func(t *testing.T, f *boundFixture) {
			f.ev.Attest, f.ev.Signature = f.ak.Quote(t, f.nonce, f.ev.PCRs)
		}, ReasonNonceMismatch},
		{"quote bound to another key", func(t *testing.T, f *boundFixture) {
			other := verifiertest.NewNodeKey(t)
			f.ev.Attest, f.ev.Signature = f.ak.Quote(t, tpm.KeyBindingData(f.nonce, other.Name), f.ev.PCRs)
		}, ReasonNonceMismatch},
		{"key substituted after binding", func(t *testing.T, f *boundFixture) {
			f.ev.NodeKey.Public = verifiertest.NewNodeKey(t).PublicBytes()
		}, ReasonNonceMismatch},
		{"key requested without a nonce", func(_ *testing.T, f *boundFixture) { f.nonce = nil }, ReasonNonceMismatch},
		{"certification over the bare nonce", func(t *testing.T, f *boundFixture) {
			f.certify(t, f.ak.CertifyAttest(f.key.Name, f.nonce))
		}, ReasonKeyBinding},
		{"certification for another challenge", func(t *testing.T, f *boundFixture) {
			f.certify(t, f.ak.CertifyAttest(f.key.Name, tpm.KeyBindingData([]byte("other nonce"), f.key.Name)))
		}, ReasonKeyBinding},
		{"certification without extra data", func(t *testing.T, f *boundFixture) {
			f.certify(t, f.ak.CertifyAttest(f.key.Name, nil))
		}, ReasonKeyBinding},
		{"certification of another key", func(t *testing.T, f *boundFixture) {
			f.certify(t, f.ak.CertifyAttest(verifiertest.NewNodeKey(t).Name, f.binding()))
		}, ReasonKeyBinding},
		{"certification of the AK", func(t *testing.T, f *boundFixture) {
			f.certify(t, f.ak.CertifyAttest(f.ak.Name, f.binding()))
		}, ReasonKeyBinding},
		{"certification from an earlier boot", func(t *testing.T, f *boundFixture) {
			a := f.ak.CertifyAttest(f.key.Name, f.binding())
			a.ClockInfo.ResetCount--
			f.certify(t, a)
		}, ReasonKeyBinding},
		{"certification before a restart", func(t *testing.T, f *boundFixture) {
			a := f.ak.CertifyAttest(f.key.Name, f.binding())
			a.ClockInfo.RestartCount++
			f.certify(t, a)
		}, ReasonKeyBinding},
		{"certification signed by another AK", func(t *testing.T, f *boundFixture) {
			f.ev.NodeKey.CertifySignature = verifiertest.NewAK(t).Sign(t, f.ev.NodeKey.Certify)
		}, ReasonBadSignature},
		{"certification signed by the node key", func(t *testing.T, f *boundFixture) {
			other := &verifiertest.AK{Key: f.key.Key}
			f.ev.NodeKey.CertifySignature = other.Sign(t, f.ev.NodeKey.Certify)
		}, ReasonBadSignature},
		{"certification signature over other bytes", func(t *testing.T, f *boundFixture) {
			f.ev.NodeKey.CertifySignature = f.ev.Signature
		}, ReasonBadSignature},
		{"quote submitted as the certification", func(_ *testing.T, f *boundFixture) {
			f.ev.NodeKey.Certify, f.ev.NodeKey.CertifySignature = f.ev.Attest, f.ev.Signature
		}, ReasonNotCertify},
		{"certification submitted as the quote", func(_ *testing.T, f *boundFixture) {
			f.ev.Attest, f.ev.Signature = f.ev.NodeKey.Certify, f.ev.NodeKey.CertifySignature
		}, ReasonNotQuote},
		{"certification without the TPM magic", func(t *testing.T, f *boundFixture) {
			a := f.ak.CertifyAttest(f.key.Name, f.binding())
			a.Magic++
			f.certify(t, a)
		}, ReasonNotCertify},
		{"certification with trailing bytes", func(t *testing.T, f *boundFixture) {
			f.ev.NodeKey.Certify = append(f.ev.NodeKey.Certify, 0)
			f.ev.NodeKey.CertifySignature = f.ak.sign(t, f.ev.NodeKey.Certify)
		}, ReasonMalformed},
		{"truncated certification", func(t *testing.T, f *boundFixture) {
			f.ev.NodeKey.Certify = f.ev.NodeKey.Certify[:20]
			f.ev.NodeKey.CertifySignature = f.ak.sign(t, f.ev.NodeKey.Certify)
		}, ReasonMalformed},
		{"empty certification", func(_ *testing.T, f *boundFixture) { f.ev.NodeKey.Certify = nil }, ReasonMalformed},
		{"empty certification signature", func(_ *testing.T, f *boundFixture) { f.ev.NodeKey.CertifySignature = nil }, ReasonMalformed},
		{"oversized certification", func(_ *testing.T, f *boundFixture) {
			f.ev.NodeKey.Certify = make([]byte, MaxAttestSize+1)
		}, ReasonMalformed},
		{"oversized certification signature", func(_ *testing.T, f *boundFixture) {
			f.ev.NodeKey.CertifySignature = make([]byte, MaxSignatureSize+1)
		}, ReasonMalformed},
		{"no key public area", func(_ *testing.T, f *boundFixture) { f.ev.NodeKey.Public = nil }, ReasonKeyInvalid},
		{"AK presented as the node key", func(t *testing.T, f *boundFixture) {
			f.ev.NodeKey.Public = f.ak.PublicBytes()
		}, ReasonKeyInvalid},
		// Measurements are still enforced when a key is bound.
		{"boot not in policy", func(t *testing.T, f *boundFixture) {
			f.policy = policyFor(t, eventlog.SimulatedBoot("v2"))
		}, ReasonMeasurement},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newBoundFixture(t)
			tc.mutate(t, f)
			res, err := VerifyEvidence(f.ak.ak, f.nonce, f.policy, f.ev)
			if ReasonOf(err) != tc.want {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
			if res != nil {
				t.Fatal("result returned with error")
			}
		})
	}
}

func TestVerifyEvidenceNil(t *testing.T) {
	f := newFixture(t)
	if _, err := VerifyEvidence(f.ak.ak, f.nonce, f.policy, nil); ReasonOf(err) != ReasonMalformed {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyCertifyRequiresInputs(t *testing.T) {
	f := newBoundFixture(t)
	key, err := ParseNodeKey(f.ev.NodeKey.Public)
	if err != nil {
		t.Fatal(err)
	}
	q := &QuoteInfo{ResetCount: 2, RestartCount: 3}
	if err := VerifyCertify(f.ak.ak, key, f.binding(), q, f.ev.NodeKey); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"no AK":       VerifyCertify(nil, key, f.binding(), q, f.ev.NodeKey),
		"AK no key":   VerifyCertify(&AK{}, key, f.binding(), q, f.ev.NodeKey),
		"no node key": VerifyCertify(f.ak.ak, nil, f.binding(), q, f.ev.NodeKey),
		"no quote":    VerifyCertify(f.ak.ak, key, f.binding(), nil, f.ev.NodeKey),
	} {
		if err == nil || ReasonOf(err) != "" {
			t.Errorf("%s: got %v, want an operational error", name, err)
		}
	}
	if err := VerifyCertify(f.ak.ak, key, f.binding(), q, nil); ReasonOf(err) != ReasonMalformed {
		t.Errorf("nil evidence: got %v", err)
	}
	if err := VerifyCertify(f.ak.ak, key, nil, q, f.ev.NodeKey); ReasonOf(err) != ReasonKeyBinding {
		t.Errorf("empty qualifying data: got %v", err)
	}
}

func TestParseNodeKeyRejects(t *testing.T) {
	good := verifiertest.NewNodeKey(t).Public
	eccParms := func(p *tpm2.TPMTPublic, mod func(*tpm2.TPMSECCParms)) {
		parms, _ := p.Parameters.ECCDetail()
		c := *parms
		mod(&c)
		p.Parameters = tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &c)
	}
	point := func(x, y []byte) tpm2.TPMUPublicID {
		return tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: x}, Y: tpm2.TPM2BECCParameter{Buffer: y},
		})
	}
	prime := elliptic.P256().Params().P.FillBytes(make([]byte, 32))
	mods := map[string]func(p *tpm2.TPMTPublic){
		// A restricted key is an AK: the node key must not be able to
		// produce TPM attestation structures, nor the AK sign TLS.
		"restricted":             func(p *tpm2.TPMTPublic) { p.ObjectAttributes.Restricted = true },
		"decrypt":                func(p *tpm2.TPMTPublic) { p.ObjectAttributes.Decrypt = true },
		"not fixedTPM":           func(p *tpm2.TPMTPublic) { p.ObjectAttributes.FixedTPM = false },
		"not fixedParent":        func(p *tpm2.TPMTPublic) { p.ObjectAttributes.FixedParent = false },
		"imported":               func(p *tpm2.TPMTPublic) { p.ObjectAttributes.SensitiveDataOrigin = false },
		"not signing":            func(p *tpm2.TPMTPublic) { p.ObjectAttributes.SignEncrypt = false },
		"no userWithAuth":        func(p *tpm2.TPMTPublic) { p.ObjectAttributes.UserWithAuth = false },
		"adminWithPolicy":        func(p *tpm2.TPMTPublic) { p.ObjectAttributes.AdminWithPolicy = true },
		"dictionary attack lock": func(p *tpm2.TPMTPublic) { p.ObjectAttributes.NoDA = false },
		"auth policy":            func(p *tpm2.TPMTPublic) { p.AuthPolicy = tpm2.TPM2BDigest{Buffer: make([]byte, 32)} },
		"SHA-384 name":           func(p *tpm2.TPMTPublic) { p.NameAlg = tpm2.TPMAlgSHA384 },
		"P-384 curve": func(p *tpm2.TPMTPublic) {
			eccParms(p, func(c *tpm2.TPMSECCParms) { c.CurveID = tpm2.TPMECCNistP384 })
		},
		"no signing scheme": func(p *tpm2.TPMTPublic) {
			eccParms(p, func(c *tpm2.TPMSECCParms) { c.Scheme = tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull} })
		},
		"SHA-384 scheme": func(p *tpm2.TPMTPublic) {
			eccParms(p, func(c *tpm2.TPMSECCParms) {
				c.Scheme.Details = tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA384})
			})
		},
		"symmetric set": func(p *tpm2.TPMTPublic) {
			eccParms(p, func(c *tpm2.TPMSECCParms) { c.Symmetric.Algorithm = tpm2.TPMAlgAES })
		},
		"template point":   func(p *tpm2.TPMTPublic) { p.Unique = point(make([]byte, 32), make([]byte, 32)) },
		"off-curve point":  func(p *tpm2.TPMTPublic) { p.Unique = point(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)) },
		"X equal to prime": func(p *tpm2.TPMTPublic) { p.Unique = point(prime, make([]byte, 32)) },
		"short Y":          func(p *tpm2.TPMTPublic) { p.Unique = point(make([]byte, 32), make([]byte, 31)) },
		"RSA key": func(p *tpm2.TPMTPublic) {
			*p = tpm2.TPMTPublic{Type: tpm2.TPMAlgRSA, NameAlg: tpm2.TPMAlgSHA256, ObjectAttributes: tpm.NodeKeyAttributes,
				Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{KeyBits: 2048}),
				Unique:     tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: make([]byte, 256)})}
		},
	}
	for name, mod := range mods {
		t.Run(name, func(t *testing.T) {
			p := good
			mod(&p)
			if _, err := ParseNodeKey(tpm2.Marshal(p)); ReasonOf(err) != ReasonKeyInvalid {
				t.Fatalf("got %v", err)
			}
		})
	}
	for name, b := range map[string][]byte{
		"empty":           nil,
		"truncated":       tpm2.Marshal(good)[:20],
		"trailing byte":   append(tpm2.Marshal(good), 0),
		"oversized":       make([]byte, maxPublicSize+1),
		"garbage":         bytes.Repeat([]byte{0xff}, 64),
		"AK public area":  newSoftAK(t).PublicBytes(),
		"EK-like garbage": {0, 0x23, 0, 0x0b},
	} {
		if _, err := ParseNodeKey(b); ReasonOf(err) != ReasonKeyInvalid {
			t.Errorf("%s: got %v", name, err)
		}
	}
}
