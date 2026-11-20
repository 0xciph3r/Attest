package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Locked serializes commands to t. A TPM executes one command at a time and
// the transports are not safe for concurrent use; the agent shares one TPM
// between attestation, renewal and TLS handshakes.
func Locked(t transport.TPM) transport.TPM { return &locked{t: t} }

type locked struct {
	mu sync.Mutex
	t  transport.TPM
}

func (l *locked) Send(cmd []byte) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.t.Send(cmd)
}

// Signer is a crypto.Signer backed by a loaded node key. It signs only
// SHA-256 digests, the key's sole scheme, and checks every signature the
// TPM returns against the public key before releasing it.
type Signer struct {
	t   transport.TPM
	key *Key
	pub *ecdsa.PublicKey
}

// ErrSignerHash is returned for digests other than SHA-256.
var ErrSignerHash = errors.New("tpm: node key signs only SHA-256 digests")

// NewSigner returns a Signer for key, which must have the node key's
// attributes and be an ECDSA P-256 key. t should be Locked if shared.
func NewSigner(t transport.TPM, key *Key) (*Signer, error) {
	if key == nil {
		return nil, errors.New("tpm: signer needs a key")
	}
	if key.Public.ObjectAttributes != NodeKeyAttributes || key.Public.Type != tpm2.TPMAlgECC {
		return nil, errors.New("tpm: signer key is not a node key")
	}
	parms, err := key.Public.Parameters.ECCDetail()
	if err != nil {
		return nil, fmt.Errorf("tpm: signer key: %w", err)
	}
	point, err := key.Public.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("tpm: signer key: %w", err)
	}
	if parms.CurveID != tpm2.TPMECCNistP256 {
		return nil, errors.New("tpm: signer key must be P-256")
	}
	pub, err := tpm2.ECDSAPub(parms, point)
	if err != nil {
		return nil, fmt.Errorf("tpm: signer key: %w", err)
	}
	// ECDSAPub does not check the point is on the curve.
	if _, err := pub.ECDH(); err != nil {
		return nil, fmt.Errorf("tpm: signer key: %w", err)
	}
	return &Signer{t: t, key: key, pub: pub}, nil
}

// Public implements crypto.Signer.
func (s *Signer) Public() crypto.PublicKey { return s.pub }

// Sign implements crypto.Signer, returning an ASN.1 ECDSA signature.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != sha256.Size {
		return nil, ErrSignerHash
	}
	rsp, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{Handle: s.key.Handle, Name: s.key.Name, Auth: tpm2.PasswordAuth(nil)},
		Digest:    tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull},
	}.Execute(s.t)
	if err != nil {
		return nil, fmt.Errorf("tpm: sign: %w", err)
	}
	// ECDSA() fails for any other signature algorithm.
	sig, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("tpm: sign: %w", err)
	}
	if sig.Hash != tpm2.TPMAlgSHA256 {
		return nil, errors.New("tpm: sign: TPM used the wrong hash")
	}
	r := new(big.Int).SetBytes(sig.SignatureR.Buffer)
	sv := new(big.Int).SetBytes(sig.SignatureS.Buffer)
	if !ecdsa.Verify(s.pub, digest, r, sv) {
		return nil, errors.New("tpm: sign: TPM returned a signature that does not verify")
	}
	return asn1.Marshal(struct{ R, S *big.Int }{r, sv})
}
