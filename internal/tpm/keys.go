// Package tpm implements the node agent's TPM operations (EK, AK, quotes,
// credential activation, event log) and the TPM object definitions shared
// with the control plane's verifier.
//
// All functions take a transport.TPM so that the same code drives a
// hardware TPM (/dev/tpmrm0) and the development swtpm.
package tpm

import (
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// EKType identifies a supported endorsement key template.
type EKType string

// Supported EK templates (TCG EK Credential Profile, low range).
const (
	EKRSA2048 EKType = "rsa2048" // template L-1, cert NV index 0x01c00002
	EKECCP256 EKType = "eccp256" // template L-2, cert NV index 0x01c0000a
)

// EK certificate NV indices from the TCG EK Credential Profile.
const (
	EKCertNVRSA2048 tpm2.TPMHandle = 0x01c00002
	EKCertNVECCP256 tpm2.TPMHandle = 0x01c0000a
)

// ErrUnsupportedEK is returned for EK types outside the supported set.
var ErrUnsupportedEK = errors.New("tpm: unsupported EK type")

// EKTemplate returns the TCG default template and certificate NV index.
func EKTemplate(t EKType) (tpm2.TPMTPublic, tpm2.TPMHandle, error) {
	switch t {
	case EKRSA2048:
		return tpm2.RSAEKTemplate, EKCertNVRSA2048, nil
	case EKECCP256:
		return tpm2.ECCEKTemplate, EKCertNVECCP256, nil
	default:
		return tpm2.TPMTPublic{}, 0, fmt.Errorf("%w: %q", ErrUnsupportedEK, t)
	}
}

// AKTemplate is the attestation key template: a restricted ECDSA P-256
// signing key with SHA-256 name algorithm, created as a primary key in the
// owner hierarchy so that it can be re-derived without storing a key blob.
// The verifier requires these exact properties (see verifier.CheckAKPublic).
var AKTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgECC,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		NoDA:                true,
		Restricted:          true,
		SignEncrypt:         true,
	},
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
		X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
	}),
}

// Key is a loaded transient key.
type Key struct {
	Handle tpm2.TPMHandle
	Name   tpm2.TPM2BName
	Public tpm2.TPMTPublic
}

// PublicBytes returns the TPMT_PUBLIC wire encoding of the key.
func (k *Key) PublicBytes() []byte { return tpm2.Marshal(k.Public) }

// Flush unloads the key from the TPM.
func (k *Key) Flush(t transport.TPM) error {
	_, err := tpm2.FlushContext{FlushHandle: k.Handle}.Execute(t)
	return err
}

func createPrimary(t transport.TPM, hierarchy tpm2.TPMHandle, tmpl tpm2.TPMTPublic) (*Key, error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{Handle: hierarchy, Auth: tpm2.PasswordAuth(nil)},
		InPublic:      tpm2.New2B(tmpl),
	}.Execute(t)
	if err != nil {
		return nil, err
	}
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		_, _ = tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(t)
		return nil, err
	}
	return &Key{Handle: rsp.ObjectHandle, Name: rsp.Name, Public: *pub}, nil
}

// LoadEK derives the endorsement key for the given template. The caller
// must Flush it.
func LoadEK(t transport.TPM, typ EKType) (*Key, error) {
	tmpl, _, err := EKTemplate(typ)
	if err != nil {
		return nil, err
	}
	k, err := createPrimary(t, tpm2.TPMRHEndorsement, tmpl)
	if err != nil {
		return nil, fmt.Errorf("tpm: create EK: %w", err)
	}
	return k, nil
}

// LoadAK derives the attestation key. The caller must Flush it.
func LoadAK(t transport.TPM) (*Key, error) {
	k, err := createPrimary(t, tpm2.TPMRHOwner, AKTemplate)
	if err != nil {
		return nil, fmt.Errorf("tpm: create AK: %w", err)
	}
	return k, nil
}

// maxEKCertSize bounds the EK certificate read from NV.
const maxEKCertSize = 4096

// nvChunk is conservatively below every TPM's MAX_NV_BUFFER_SIZE.
const nvChunk = 512

// ReadEKCert reads the DER EK certificate provisioned for the EK type.
func ReadEKCert(t transport.TPM, typ EKType) ([]byte, error) {
	_, idx, err := EKTemplate(typ)
	if err != nil {
		return nil, err
	}
	pub, err := tpm2.NVReadPublic{NVIndex: idx}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpm: EK certificate NV index %#x: %w", uint32(idx), err)
	}
	nv, err := pub.NVPublic.Contents()
	if err != nil {
		return nil, err
	}
	size := int(nv.DataSize)
	if size == 0 || size > maxEKCertSize {
		return nil, fmt.Errorf("tpm: EK certificate size %d out of range", size)
	}
	h := tpm2.AuthHandle{Handle: idx, Name: pub.NVName, Auth: tpm2.PasswordAuth(nil)}
	out := make([]byte, 0, size)
	for len(out) < size {
		n := min(nvChunk, size-len(out))
		rsp, err := tpm2.NVRead{
			AuthHandle: h,
			NVIndex:    tpm2.NamedHandle{Handle: idx, Name: pub.NVName},
			Size:       uint16(n),        //nolint:gosec // n <= nvChunk
			Offset:     uint16(len(out)), //nolint:gosec // len(out) < maxEKCertSize
		}.Execute(t)
		if err != nil {
			return nil, fmt.Errorf("tpm: read EK certificate: %w", err)
		}
		out = append(out, rsp.Data.Buffer...)
	}
	return out[:size], nil
}
