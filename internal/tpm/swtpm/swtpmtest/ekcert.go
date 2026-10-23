package swtpmtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
)

// CA is a throwaway certificate authority for provisioning EK certificates
// that swtpm_setup does not create (the TCG L-2 ECC P-256 EK).
type CA struct {
	Cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// NewCA creates a self-signed test CA.
func NewCA(t testing.TB, name string) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{Cert: cert, key: key}
}

var (
	oidSAN             = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidTCGKpEKCert     = asn1.ObjectIdentifier{2, 23, 133, 8, 1}
	oidTPMManufacturer = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
)

// IssueEKCert issues a TCG-style EK certificate for pub: empty subject and
// a critical subjectAltName that holds only a directoryName, exactly the
// shape that Go's x509 verifier treats as an unhandled critical extension.
func (ca *CA) IssueEKCert(t testing.TB, pub crypto.PublicKey) []byte {
	t.Helper()
	name, err := asn1.Marshal(pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{
		{Type: oidTPMManufacturer, Value: "id:41545354"},
	}}.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	gn, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: name})
	if err != nil {
		t.Fatal(err)
	}
	san, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: gn})
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyAgreement,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidTCGKpEKCert},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{{Id: oidSAN, Critical: true, Value: san}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// WriteNV (re)defines an owner-writable, auth-readable NV index holding data.
func (t *TPM) WriteNV(tb testing.TB, idx tpm2.TPMHandle, data []byte) {
	tb.Helper()
	owner := tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)}
	if pub, err := (tpm2.NVReadPublic{NVIndex: idx}).Execute(t); err == nil {
		if _, err := (tpm2.NVUndefineSpace{AuthHandle: owner, NVIndex: tpm2.NamedHandle{Handle: idx, Name: pub.NVName}}).Execute(t); err != nil {
			tb.Fatal(err)
		}
	}
	def := tpm2.TPMSNVPublic{
		NVIndex: idx,
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			OwnerWrite: true, OwnerRead: true, AuthRead: true, NoDA: true,
			NT: tpm2.TPMNTOrdinary,
		},
		DataSize: uint16(len(data)), //nolint:gosec // test data is small
	}
	if _, err := (tpm2.NVDefineSpace{AuthHandle: owner, PublicInfo: tpm2.New2B(def)}).Execute(t); err != nil {
		tb.Fatal(err)
	}
	pub, err := tpm2.NVReadPublic{NVIndex: idx}.Execute(t)
	if err != nil {
		tb.Fatal(err)
	}
	for off := 0; off < len(data); off += 512 {
		end := min(off+512, len(data))
		if _, err := (tpm2.NVWrite{
			AuthHandle: owner,
			NVIndex:    tpm2.NamedHandle{Handle: idx, Name: pub.NVName},
			Data:       tpm2.TPM2BMaxNVBuffer{Buffer: data[off:end]},
			Offset:     uint16(off), //nolint:gosec // test data is small
		}).Execute(t); err != nil {
			tb.Fatal(err)
		}
	}
}
