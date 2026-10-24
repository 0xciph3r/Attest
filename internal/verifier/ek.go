package verifier

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"slices"
	"time"

	"github.com/google/go-tpm/tpm2"

	"github.com/0xciph3r/attest/internal/tpm"
)

// MaxEKCertSize bounds a DER EK certificate.
const MaxEKCertSize = 4096

var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// EKRoots are the trust anchors for EK certificates. Development roots
// (for example swtpm's local CA) are kept separate so that policy can
// refuse them.
type EKRoots struct {
	Production    *x509.CertPool
	Development   *x509.CertPool
	Intermediates *x509.CertPool
}

// EK is a validated endorsement key.
type EK struct {
	Type EKType
	Cert *x509.Certificate
	// Public is the TPMT_PUBLIC that the TCG default template produces for
	// the certified key. It is derived from the certificate, never taken
	// from the node, and is the key credentials are encrypted to.
	Public tpm2.TPMTPublic
	// Development is true when the certificate chains only to a
	// development root.
	Development bool
}

// EKType re-exports the supported EK templates.
type EKType = tpm.EKType

// ParseEKCert decodes an EK certificate as stored in TPM NV memory. Some
// TPMs pad the NV index after the DER certificate; trailing bytes are
// accepted only if they are all 0x00 or all 0xff.
func ParseEKCert(b []byte) (*x509.Certificate, error) {
	if len(b) == 0 || len(b) > MaxEKCertSize {
		return nil, fail(ReasonEKCertInvalid, "certificate size %d out of range", len(b))
	}
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(b, &raw)
	if err != nil || raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence {
		return nil, fail(ReasonEKCertInvalid, "not a DER certificate")
	}
	if len(rest) > 0 && !isPadding(rest) {
		return nil, fail(ReasonEKCertInvalid, "trailing data after certificate")
	}
	cert, err := x509.ParseCertificate(raw.FullBytes)
	if err != nil {
		return nil, wrap(ReasonEKCertInvalid, err)
	}
	// TCG EK certificates carry a critical subjectAltName holding only a
	// directoryName (TPM manufacturer, model, version). Go's verifier
	// leaves such a SAN unhandled; it is understood here, so mark it
	// handled. Any other unhandled critical extension still fails Verify.
	if len(cert.DNSNames)+len(cert.EmailAddresses)+len(cert.IPAddresses)+len(cert.URIs) == 0 {
		cert.UnhandledCriticalExtensions = slices.DeleteFunc(cert.UnhandledCriticalExtensions,
			func(o asn1.ObjectIdentifier) bool { return o.Equal(oidSubjectAltName) })
	}
	return cert, nil
}

func isPadding(b []byte) bool {
	return bytes.Count(b, []byte{0}) == len(b) || bytes.Count(b, []byte{0xff}) == len(b)
}

// VerifyEKCert validates an EK certificate chain and derives the EK.
func VerifyEKCert(b []byte, roots EKRoots, now time.Time) (*EK, error) {
	cert, err := ParseEKCert(b)
	if err != nil {
		return nil, err
	}
	dev, err := verifyChain(cert, roots, now)
	if err != nil {
		return nil, err
	}
	typ, pub, err := ekPublic(cert)
	if err != nil {
		return nil, err
	}
	return &EK{Type: typ, Cert: cert, Public: pub, Development: dev}, nil
}

func verifyChain(cert *x509.Certificate, roots EKRoots, now time.Time) (development bool, err error) {
	opts := x509.VerifyOptions{
		Intermediates: roots.Intermediates,
		CurrentTime:   now,
		// The EK certificate EKU (tcg-kp-EKCertificate) is not one Go
		// knows; key usage is constrained by the TPM, not the certificate.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	var errs []error
	if roots.Production != nil {
		opts.Roots = roots.Production
		if _, err := cert.Verify(opts); err == nil {
			return false, nil
		} else {
			errs = append(errs, err)
		}
	}
	if roots.Development != nil {
		opts.Roots = roots.Development
		if _, err := cert.Verify(opts); err == nil {
			return true, nil
		} else {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		errs = append(errs, errors.New("no EK roots configured"))
	}
	return false, wrap(ReasonEKUntrusted, errors.Join(errs...))
}

func ekPublic(cert *x509.Certificate) (EKType, tpm2.TPMTPublic, error) {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() != 2048 || k.E != 65537 {
			return "", tpm2.TPMTPublic{}, fail(ReasonEKCertInvalid, "unsupported RSA EK (want 2048-bit, e=65537)")
		}
		pub, _, _ := tpm.EKTemplate(tpm.EKRSA2048)
		pub.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: k.N.FillBytes(make([]byte, 256))})
		return tpm.EKRSA2048, pub, nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return "", tpm2.TPMTPublic{}, fail(ReasonEKCertInvalid, "unsupported ECC EK curve %s (only P-256)", k.Curve.Params().Name)
		}
		e, err := k.ECDH()
		if err != nil {
			return "", tpm2.TPMTPublic{}, wrap(ReasonEKCertInvalid, err)
		}
		raw := e.Bytes() // 0x04 || X || Y
		pub, _, _ := tpm.EKTemplate(tpm.EKECCP256)
		pub.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: raw[1:33]},
			Y: tpm2.TPM2BECCParameter{Buffer: raw[33:]},
		})
		return tpm.EKECCP256, pub, nil
	default:
		return "", tpm2.TPMTPublic{}, fail(ReasonEKCertInvalid, "unsupported EK key type %T", k)
	}
}
