package tpm

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// NodeKeyUniqueSize is the size of the value that selects a node key.
const NodeKeyUniqueSize = 32

// NodeKeyAttributes are the required attributes of a node identity key: a
// non-duplicable, TPM-generated, unrestricted signing key. Unlike the AK it
// signs arbitrary digests (TLS handshakes), so it is never trusted to sign
// TPM attestation structures and is only trusted because the AK certifies it.
var NodeKeyAttributes = tpm2.TPMAObject{
	FixedTPM:            true,
	FixedParent:         true,
	SensitiveDataOrigin: true,
	UserWithAuth:        true,
	NoDA:                true,
	SignEncrypt:         true,
}

// NodeKeyTemplate returns the template of the node identity key selected by
// unique. Like the AK it is a primary key in the owner hierarchy, so the
// agent re-derives it from unique and no key blob exists outside the TPM;
// rotating the key means choosing a new unique value.
func NodeKeyTemplate(unique []byte) (tpm2.TPMTPublic, error) {
	if len(unique) != NodeKeyUniqueSize {
		return tpm2.TPMTPublic{}, fmt.Errorf("tpm: node key unique value must be %d bytes", NodeKeyUniqueSize)
	}
	return tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgECC,
		NameAlg:          tpm2.TPMAlgSHA256,
		ObjectAttributes: NodeKeyAttributes,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA,
					&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
			CurveID: tpm2.TPMECCNistP256,
			KDF:     tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: append([]byte(nil), unique...)},
			Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		}),
	}, nil
}

// LoadNodeKey derives the node identity key selected by unique. The caller
// must Flush it.
func LoadNodeKey(t transport.TPM, unique []byte) (*Key, error) {
	tmpl, err := NodeKeyTemplate(unique)
	if err != nil {
		return nil, err
	}
	k, err := createPrimary(t, tpm2.TPMRHOwner, tmpl)
	if err != nil {
		return nil, fmt.Errorf("tpm: create node key: %w", err)
	}
	return k, nil
}

// KeyBindingDomain separates key-binding qualifying data from every other
// use of an attestation nonce.
const KeyBindingDomain = "attest.dev/key-binding/v1"

// KeyBindingData is the qualifying data a node puts in both the quote and
// the certification of the key it wants an identity for:
// SHA-256(domain || u64(len) || nonce || u64(len) || keyName). It binds the boot state
// evidence, the challenge and the key into one statement by the AK.
func KeyBindingData(nonce, keyName []byte) []byte {
	h := sha256.New()
	h.Write([]byte(KeyBindingDomain))
	for _, f := range [][]byte{nonce, keyName} {
		_ = binary.Write(h, binary.BigEndian, uint64(len(f)))
		h.Write(f)
	}
	return h.Sum(nil)
}

// Certification is an AK-signed TPM2_Certify of a key.
type Certification struct {
	Attest    []byte // TPMS_ATTEST of type TPM_ST_ATTEST_CERTIFY
	Signature []byte // TPMT_SIGNATURE
}

// Certify has ak attest that key is loaded in the same TPM, with
// qualifying as extra data.
func Certify(t transport.TPM, ak, key *Key, qualifying []byte) (*Certification, error) {
	if ak == nil || key == nil {
		return nil, errors.New("tpm: certify needs an AK and a key")
	}
	rsp, err := tpm2.Certify{
		ObjectHandle:   tpm2.AuthHandle{Handle: key.Handle, Name: key.Name, Auth: tpm2.PasswordAuth(nil)},
		SignHandle:     tpm2.AuthHandle{Handle: ak.Handle, Name: ak.Name, Auth: tpm2.PasswordAuth(nil)},
		QualifyingData: tpm2.TPM2BData{Buffer: qualifying},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpm: certify: %w", err)
	}
	return &Certification{Attest: rsp.CertifyInfo.Bytes(), Signature: tpm2.Marshal(rsp.Signature)}, nil
}
