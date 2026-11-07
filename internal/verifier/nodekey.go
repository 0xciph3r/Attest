package verifier

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"errors"

	"github.com/google/go-tpm/tpm2"

	"github.com/0xciph3r/attest/internal/tpm"
)

// KeyEvidence asks for a key to be bound to an attestation: the key's
// public area and the AK's certification of it.
type KeyEvidence struct {
	Public           []byte // TPMT_PUBLIC
	Certify          []byte // TPMS_ATTEST of type TPM_ST_ATTEST_CERTIFY
	CertifySignature []byte // TPMT_SIGNATURE by the AK
}

// NodeKey is a validated node identity key.
type NodeKey struct {
	Public tpm2.TPMTPublic
	Key    *ecdsa.PublicKey
	// Name is the key's TPM name, which the certification attests.
	Name []byte
	// SPKIHash is the SHA-256 of the key's DER SubjectPublicKeyInfo, the
	// form in which it appears in issued certificates.
	SPKIHash []byte
}

// ParseNodeKey decodes a TPMT_PUBLIC and requires the exact properties of
// tpm.NodeKeyTemplate: a fixedTPM, TPM-generated, unrestricted ECDSA
// P-256/SHA-256 signing key that cannot decrypt.
func ParseNodeKey(b []byte) (*NodeKey, error) {
	pub, key, name, err := parseSigningKey(b, tpm.NodeKeyAttributes, ReasonKeyInvalid, "node key")
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, wrap(ReasonKeyInvalid, err)
	}
	h := sha256.Sum256(der)
	return &NodeKey{Public: *pub, Key: key, Name: name, SPKIHash: h[:]}, nil
}

// VerifyCertify authenticates the AK's certification of key. It requires an
// ECDSA-SHA256 signature by ak over the exact attest bytes, a TPM-generated
// certification whose extra data equals qualifying and whose certified name
// is key's name, made in the same boot cycle (reset and restart counts) as
// the quote q. Since the AK is restricted and fixedTPM, this proves the key
// was loaded in the AK's TPM, and its fixedTPM attribute (checked by
// ParseNodeKey and covered by the name) proves it cannot leave it.
func VerifyCertify(ak *AK, key *NodeKey, qualifying []byte, q *QuoteInfo, ev *KeyEvidence) error {
	if ak == nil || ak.Key == nil {
		return errors.New("verifier: no attestation key")
	}
	if key == nil || q == nil {
		return errors.New("verifier: no node key or quote")
	}
	if ev == nil || len(ev.Certify) == 0 || len(ev.Certify) > MaxAttestSize ||
		len(ev.CertifySignature) == 0 || len(ev.CertifySignature) > MaxSignatureSize {
		return fail(ReasonMalformed, "certification or signature size out of range")
	}
	if err := verifySignature(ak, ev.Certify, ev.CertifySignature); err != nil {
		return err
	}
	attest, err := decode[tpm2.TPMSAttest](ev.Certify)
	if err != nil {
		return wrap(ReasonMalformed, err)
	}
	if attest.Magic != tpm2.TPMGeneratedValue || attest.Type != tpm2.TPMSTAttestCertify {
		return fail(ReasonNotCertify, "signed structure is not a TPM key certification")
	}
	if len(qualifying) == 0 || subtle.ConstantTimeCompare(attest.ExtraData.Buffer, qualifying) != 1 {
		return fail(ReasonKeyBinding, "certification is not bound to the challenge and key")
	}
	info, err := attest.Attested.Certify()
	if err != nil {
		return wrap(ReasonMalformed, err)
	}
	if !bytes.Equal(info.Name.Buffer, key.Name) {
		return fail(ReasonKeyBinding, "certification is for a different key")
	}
	if attest.ClockInfo.ResetCount != q.ResetCount || attest.ClockInfo.RestartCount != q.RestartCount {
		return fail(ReasonKeyBinding, "certification and quote are from different boot cycles")
	}
	return nil
}
