package verifier

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"

	"github.com/0xciph3r/attest/internal/policy"
	"github.com/0xciph3r/attest/internal/tpm/swtpm/swtpmtest"
)

func TestParseAKRejectsMore(t *testing.T) {
	good := newSoftAK(t).pub
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
	p := elliptic.P256().Params().P.FillBytes(make([]byte, 32))
	mods := map[string]func(p *tpm2.TPMTPublic){
		"not fixedParent":      func(p *tpm2.TPMTPublic) { p.ObjectAttributes.FixedParent = false },
		"not signing":          func(p *tpm2.TPMTPublic) { p.ObjectAttributes.SignEncrypt = false },
		"stClear":              func(p *tpm2.TPMTPublic) { p.ObjectAttributes.STClear = true },
		"adminWithPolicy":      func(p *tpm2.TPMTPublic) { p.ObjectAttributes.AdminWithPolicy = true },
		"encryptedDuplication": func(p *tpm2.TPMTPublic) { p.ObjectAttributes.EncryptedDuplication = true },
		"no userWithAuth":      func(p *tpm2.TPMTPublic) { p.ObjectAttributes.UserWithAuth = false },
		"SHA-384 name":         func(p *tpm2.TPMTPublic) { p.NameAlg = tpm2.TPMAlgSHA384 },
		"P-384 curve":          func(p *tpm2.TPMTPublic) { eccParms(p, func(c *tpm2.TPMSECCParms) { c.CurveID = tpm2.TPMECCNistP384 }) },
		"symmetric set": func(p *tpm2.TPMTPublic) {
			eccParms(p, func(c *tpm2.TPMSECCParms) { c.Symmetric.Algorithm = tpm2.TPMAlgAES })
		},
		"KDF set": func(p *tpm2.TPMTPublic) {
			eccParms(p, func(c *tpm2.TPMSECCParms) { c.KDF.Scheme = tpm2.TPMAlgKDF1SP80056A })
		},
		"no signing scheme": func(p *tpm2.TPMTPublic) {
			eccParms(p, func(c *tpm2.TPMSECCParms) { c.Scheme.Scheme = tpm2.TPMAlgNull })
		},
		"ECDAA scheme": func(p *tpm2.TPMTPublic) {
			eccParms(p, func(c *tpm2.TPMSECCParms) {
				c.Scheme = tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgECDAA, Details: tpm2.NewTPMUAsymScheme(
					tpm2.TPMAlgECDAA, &tpm2.TPMSSchemeECDAA{HashAlg: tpm2.TPMAlgSHA256})}
			})
		},
		"short X":          func(p *tpm2.TPMTPublic) { p.Unique = point(make([]byte, 31), make([]byte, 32)) },
		"empty point":      func(p *tpm2.TPMTPublic) { p.Unique = point(nil, nil) },
		"zero point":       func(p *tpm2.TPMTPublic) { p.Unique = point(make([]byte, 32), make([]byte, 32)) },
		"X equal to prime": func(pub *tpm2.TPMTPublic) { pub.Unique = point(p, make([]byte, 32)) },
		"keyedHash type":   func(p *tpm2.TPMTPublic) { *p = tpm2.TPMTPublic{Type: tpm2.TPMAlgKeyedHash, NameAlg: tpm2.TPMAlgSHA256} },
	}
	for name, mod := range mods {
		t.Run(name, func(t *testing.T) {
			p := good
			mod(&p)
			b := tpm2.Marshal(p)
			if _, err := ParseAK(b); ReasonOf(err) != ReasonAKInvalid {
				t.Fatalf("got %v", err)
			}
		})
	}
	for name, b := range map[string][]byte{
		"empty":     nil,
		"truncated": tpm2.Marshal(good)[:20],
		"oversized": make([]byte, maxPublicSize+1),
	} {
		if _, err := ParseAK(b); ReasonOf(err) != ReasonAKInvalid {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestVerifyEKCertRejectsMore(t *testing.T) {
	ca, other := swtpmtest.NewCA(t, "ca"), swtpmtest.NewCA(t, "other")
	p256 := eccKey(t, elliptic.P256()).Public()
	roots := EKRoots{Production: pool(ca)}
	rsa4096, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	tests := []struct {
		name  string
		der   []byte
		roots EKRoots
		now   time.Time
		want  Reason
	}{
		{"not yet valid", ca.IssueEKCert(t, p256), roots, time.Now().Add(-48 * time.Hour), ReasonEKUntrusted},
		{"trusted only as development, no dev pool", other.IssueEKCert(t, p256), EKRoots{Development: pool(ca)}, time.Now(), ReasonEKUntrusted},
		{"RSA-4096 EK", ca.IssueEKCert(t, rsa4096.Public()), roots, time.Now(), ReasonEKCertInvalid},
		{"Ed25519 EK", ca.IssueEKCert(t, edPub), roots, time.Now(), ReasonEKCertInvalid},
		{"P-224 EK", ca.IssueEKCert(t, eccKey(t, elliptic.P224()).Public()), roots, time.Now(), ReasonEKCertInvalid},
		{"PEM instead of DER", []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), roots, time.Now(), ReasonEKCertInvalid},
		{"DER of another type", []byte{0x02, 0x01, 0x05}, roots, time.Now(), ReasonEKCertInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyEKCert(tt.der, tt.roots, tt.now)
			if got := ReasonOf(err); got != tt.want {
				t.Fatalf("got %q (%v), want %q", got, err, tt.want)
			}
		})
	}
}

func TestAdmitRoot(t *testing.T) {
	allow := &policy.Measurement{AllowDevelopmentRoots: true}
	deny := &policy.Measurement{}
	for name, tc := range map[string]struct {
		dev  bool
		m    *policy.Measurement
		want Reason
	}{
		"production, nil policy":  {false, nil, ""},
		"production, denying":     {false, deny, ""},
		"development, nil policy": {true, nil, ReasonDevelopmentRoot},
		"development, denying":    {true, deny, ReasonDevelopmentRoot},
		"development, allowing":   {true, allow, ""},
	} {
		if got := ReasonOf(AdmitRoot(tc.dev, tc.m)); got != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}
}
