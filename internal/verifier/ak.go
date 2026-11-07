package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"

	"github.com/google/go-tpm/tpm2"

	"github.com/0xciph3r/attest/internal/tpm"
)

// maxPublicSize bounds an encoded TPMT_PUBLIC.
const maxPublicSize = 1024

// AK is a validated attestation key.
type AK struct {
	Public tpm2.TPMTPublic
	Key    *ecdsa.PublicKey
	// Name is the TPM name (nameAlg || H(TPMT_PUBLIC)) that credential
	// activation binds to.
	Name []byte
}

// ParseAK decodes a TPMT_PUBLIC and requires it to be an Attest AK: a
// restricted, fixedTPM, non-decrypting ECDSA P-256/SHA-256 signing key with
// exactly the attributes of tpm.AKTemplate. A restricted signing key only
// signs TPM-generated structures, which is what makes its quotes evidence.
func ParseAK(b []byte) (*AK, error) {
	pub, key, name, err := parseSigningKey(b, tpm.AKTemplate.ObjectAttributes, ReasonAKInvalid, "AK")
	if err != nil {
		return nil, err
	}
	return &AK{Public: *pub, Key: key, Name: name}, nil
}

// parseSigningKey decodes a TPMT_PUBLIC and requires an ECDSA P-256 key
// with SHA-256 name and signing scheme, no auth policy and exactly attrs.
// Failures carry reason r.
func parseSigningKey(b []byte, attrs tpm2.TPMAObject, r Reason, what string) (*tpm2.TPMTPublic, *ecdsa.PublicKey, []byte, error) {
	if len(b) > maxPublicSize {
		return nil, nil, nil, fail(r, "public area too large")
	}
	pub, err := decode[tpm2.TPMTPublic](b)
	if err != nil {
		return nil, nil, nil, wrap(r, err)
	}
	if pub.Type != tpm2.TPMAlgECC || pub.NameAlg != tpm2.TPMAlgSHA256 {
		return nil, nil, nil, fail(r, "%s must be ECC with SHA-256 name algorithm", what)
	}
	if pub.ObjectAttributes != attrs {
		return nil, nil, nil, fail(r, "%s attributes differ from the required template", what)
	}
	if len(pub.AuthPolicy.Buffer) != 0 {
		return nil, nil, nil, fail(r, "%s must not have an auth policy", what)
	}
	parms, err := pub.Parameters.ECCDetail()
	if err != nil {
		return nil, nil, nil, wrap(r, err)
	}
	if parms.CurveID != tpm2.TPMECCNistP256 || parms.Symmetric.Algorithm != tpm2.TPMAlgNull ||
		parms.KDF.Scheme != tpm2.TPMAlgNull || parms.Scheme.Scheme != tpm2.TPMAlgECDSA {
		return nil, nil, nil, fail(r, "%s must be an ECDSA P-256 key", what)
	}
	scheme, err := parms.Scheme.Details.ECDSA()
	if err != nil || scheme.HashAlg != tpm2.TPMAlgSHA256 {
		return nil, nil, nil, fail(r, "%s signing scheme must be ECDSA-SHA256", what)
	}
	point, err := pub.Unique.ECC()
	if err != nil {
		return nil, nil, nil, wrap(r, err)
	}
	if len(point.X.Buffer) != 32 || len(point.Y.Buffer) != 32 {
		return nil, nil, nil, fail(r, "%s public point has wrong size", what)
	}
	key, err := tpm2.ECDSAPub(parms, point)
	if err != nil || key.Curve != elliptic.P256() {
		return nil, nil, nil, fail(r, "%s public point is invalid", what)
	}
	// ECDSAPub does not check the point is on the curve.
	if _, err := key.ECDH(); err != nil {
		return nil, nil, nil, wrap(r, err)
	}
	name, err := tpm2.ObjectName(pub)
	if err != nil {
		return nil, nil, nil, wrap(r, err)
	}
	return pub, key, name.Buffer, nil
}
