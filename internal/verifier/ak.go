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
	if len(b) > maxPublicSize {
		return nil, fail(ReasonAKInvalid, "public area too large")
	}
	pub, err := decode[tpm2.TPMTPublic](b)
	if err != nil {
		return nil, wrap(ReasonAKInvalid, err)
	}
	want := tpm.AKTemplate
	if pub.Type != tpm2.TPMAlgECC || pub.NameAlg != tpm2.TPMAlgSHA256 {
		return nil, fail(ReasonAKInvalid, "AK must be ECC with SHA-256 name algorithm")
	}
	if pub.ObjectAttributes != want.ObjectAttributes {
		return nil, fail(ReasonAKInvalid, "AK attributes differ from the required template")
	}
	if len(pub.AuthPolicy.Buffer) != 0 {
		return nil, fail(ReasonAKInvalid, "AK must not have an auth policy")
	}
	parms, err := pub.Parameters.ECCDetail()
	if err != nil {
		return nil, wrap(ReasonAKInvalid, err)
	}
	if parms.CurveID != tpm2.TPMECCNistP256 || parms.Symmetric.Algorithm != tpm2.TPMAlgNull ||
		parms.KDF.Scheme != tpm2.TPMAlgNull || parms.Scheme.Scheme != tpm2.TPMAlgECDSA {
		return nil, fail(ReasonAKInvalid, "AK must be an ECDSA P-256 key")
	}
	scheme, err := parms.Scheme.Details.ECDSA()
	if err != nil || scheme.HashAlg != tpm2.TPMAlgSHA256 {
		return nil, fail(ReasonAKInvalid, "AK signing scheme must be ECDSA-SHA256")
	}
	point, err := pub.Unique.ECC()
	if err != nil {
		return nil, wrap(ReasonAKInvalid, err)
	}
	if len(point.X.Buffer) != 32 || len(point.Y.Buffer) != 32 {
		return nil, fail(ReasonAKInvalid, "AK public point has wrong size")
	}
	key, err := tpm2.ECDSAPub(parms, point)
	if err != nil || key.Curve != elliptic.P256() {
		return nil, fail(ReasonAKInvalid, "AK public point is invalid")
	}
	// ECDSAPub does not check the point is on the curve.
	if _, err := key.ECDH(); err != nil {
		return nil, wrap(ReasonAKInvalid, err)
	}
	name, err := tpm2.ObjectName(pub)
	if err != nil {
		return nil, wrap(ReasonAKInvalid, err)
	}
	return &AK{Public: *pub, Key: key, Name: name.Buffer}, nil
}
