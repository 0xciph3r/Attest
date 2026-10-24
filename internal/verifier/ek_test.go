package verifier

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"

	"github.com/0xciph3r/attest/internal/tpm"
	"github.com/0xciph3r/attest/internal/tpm/swtpm/swtpmtest"
)

func pool(cas ...*swtpmtest.CA) *x509.CertPool {
	p := x509.NewCertPool()
	for _, ca := range cas {
		p.AddCert(ca.Cert)
	}
	return p
}

func eccKey(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestVerifyEKCert(t *testing.T) {
	prod, dev := swtpmtest.NewCA(t, "prod"), swtpmtest.NewCA(t, "dev")
	key := eccKey(t, elliptic.P256())
	der := dev.IssueEKCert(t, key.Public())
	if raw, _ := x509.ParseCertificate(der); len(raw.UnhandledCriticalExtensions) != 1 {
		t.Fatal("fixture does not exercise the critical directoryName SAN")
	}

	ek, err := VerifyEKCert(der, EKRoots{Production: pool(prod), Development: pool(dev)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ek.Type != tpm.EKECCP256 || !ek.Development {
		t.Fatalf("got type %s development=%v", ek.Type, ek.Development)
	}
	got, err := tpm2.Pub(ek.Public)
	if err != nil || !key.PublicKey.Equal(got) {
		t.Fatal("derived EK public does not match the certificate")
	}
	// Credentials can be encrypted to the derived public area.
	kem, err := tpm2.ImportEncapsulationKey(&ek.Public)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := tpm2.CreateCredential(rand.Reader, kem, make([]byte, 34), make([]byte, 32)); err != nil {
		t.Fatal(err)
	}

	ek, err = VerifyEKCert(der, EKRoots{Production: pool(dev), Development: pool(dev)}, time.Now())
	if err != nil || ek.Development {
		t.Fatalf("production root not preferred: %v", err)
	}
}

func TestVerifyEKCertRSA(t *testing.T) {
	ca := swtpmtest.NewCA(t, "ca")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ek, err := VerifyEKCert(ca.IssueEKCert(t, key.Public()), EKRoots{Production: pool(ca)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := tpm2.Pub(ek.Public)
	if ek.Type != tpm.EKRSA2048 || ek.Development || !key.PublicKey.Equal(got) {
		t.Fatal("unexpected RSA EK")
	}
}

func TestEKCertPadding(t *testing.T) {
	ca := swtpmtest.NewCA(t, "ca")
	der := ca.IssueEKCert(t, eccKey(t, elliptic.P256()).Public())
	roots := EKRoots{Production: pool(ca)}
	for name, b := range map[string][]byte{
		"zero padding": append(bytes.Clone(der), 0, 0, 0),
		"ff padding":   append(bytes.Clone(der), 0xff, 0xff),
	} {
		if _, err := VerifyEKCert(b, roots, time.Now()); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, b := range map[string][]byte{
		"trailing data": append(bytes.Clone(der), 1, 2),
		"mixed padding": append(bytes.Clone(der), 0, 0xff),
		"empty":         nil,
		"truncated":     der[:len(der)-1],
		"oversized":     make([]byte, MaxEKCertSize+1),
	} {
		if _, err := VerifyEKCert(b, roots, time.Now()); ReasonOf(err) != ReasonEKCertInvalid {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestVerifyEKCertRejects(t *testing.T) {
	ca, other := swtpmtest.NewCA(t, "ca"), swtpmtest.NewCA(t, "other")
	p256 := eccKey(t, elliptic.P256()).Public()
	roots := EKRoots{Production: pool(ca)}
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		der   []byte
		roots EKRoots
		now   time.Time
		want  Reason
	}{
		{"untrusted issuer", other.IssueEKCert(t, p256), roots, time.Now(), ReasonEKUntrusted},
		{"no roots configured", ca.IssueEKCert(t, p256), EKRoots{}, time.Now(), ReasonEKUntrusted},
		{"expired", ca.IssueEKCert(t, p256), roots, time.Now().Add(48 * time.Hour), ReasonEKUntrusted},
		{"unknown critical extension", ca.IssueEKCert(t, p256, func(c *x509.Certificate) {
			c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{
				Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0},
			})
		}), roots, time.Now(), ReasonEKUntrusted},
		{"P-384 EK", ca.IssueEKCert(t, eccKey(t, elliptic.P384()).Public()), roots, time.Now(), ReasonEKCertInvalid},
		{"RSA-1024 EK", ca.IssueEKCert(t, crypto.PublicKey(&rsa1024.PublicKey)), roots, time.Now(), ReasonEKCertInvalid},
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
