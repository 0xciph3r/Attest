package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// checkpointDomain separates checkpoint signatures from any other use of the
// same key.
const checkpointDomain = "attest/audit/checkpoint/v1"

// Checkpoint asserts that a ledger had a given head at a point in time.
//
// A checkpoint is only as trustworthy as the custody of its signing key and of
// the checkpoint file itself. Attest's recommended deployment keeps the signing
// key away from the control plane and stores signed checkpoints outside the
// control plane's database (see docs/security-properties.md).
type Checkpoint struct {
	Sequence uint64    `json:"sequence"`
	Hash     Hash      `json:"hash"`
	Time     time.Time `json:"time"`
	KeyID    string    `json:"key_id"`
}

// SignedCheckpoint is a Checkpoint with an Ed25519 signature over its
// canonical encoding.
type SignedCheckpoint struct {
	Checkpoint
	Signature []byte `json:"signature"`
}

// KeyRing maps key IDs to trusted checkpoint verification keys.
type KeyRing map[string]ed25519.PublicKey

// NewKeyRing builds a KeyRing, deriving each key's ID from the key itself.
func NewKeyRing(keys ...ed25519.PublicKey) KeyRing {
	r := make(KeyRing, len(keys))
	for _, k := range keys {
		r[KeyID(k)] = k
	}
	return r
}

// KeyID returns a stable identifier for an Ed25519 public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(sum[:8])
}

var (
	// ErrCheckpointSignature indicates a checkpoint whose signature does not
	// verify under its declared key.
	ErrCheckpointSignature = errors.New("audit: invalid checkpoint signature")
	// ErrUnknownKey indicates a checkpoint signed by a key that is not trusted.
	ErrUnknownKey = errors.New("audit: checkpoint signed by untrusted key")
)

func (c *Checkpoint) signedBytes() []byte {
	var buf bytes.Buffer
	putField(&buf, []byte(checkpointDomain))
	putUint64(&buf, c.Sequence)
	buf.Write(c.Hash[:])
	putUint64(&buf, uint64(c.Time.UTC().UnixNano()))
	putField(&buf, []byte(c.KeyID))
	return buf.Bytes()
}

// SignCheckpoint signs head with key. Checkpoints of an empty ledger are
// rejected because they anchor nothing.
func SignCheckpoint(head Head, at time.Time, key ed25519.PrivateKey) (SignedCheckpoint, error) {
	if head.Sequence == 0 {
		return SignedCheckpoint{}, errors.New("audit: cannot checkpoint an empty ledger")
	}
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return SignedCheckpoint{}, errors.New("audit: signing key is not Ed25519")
	}
	c := Checkpoint{
		Sequence: head.Sequence,
		Hash:     head.Hash,
		Time:     at.UTC(),
		KeyID:    KeyID(pub),
	}
	return SignedCheckpoint{Checkpoint: c, Signature: ed25519.Sign(key, c.signedBytes())}, nil
}

// Verify checks the checkpoint's signature against the trusted keys.
func (s *SignedCheckpoint) Verify(keys KeyRing) error {
	pub, ok := keys[s.KeyID]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownKey, s.KeyID)
	}
	if s.Sequence == 0 {
		return fmt.Errorf("%w: sequence 0", ErrCheckpointSignature)
	}
	if !ed25519.Verify(pub, s.signedBytes(), s.Signature) {
		return fmt.Errorf("%w: checkpoint at sequence %d", ErrCheckpointSignature, s.Sequence)
	}
	return nil
}
