// Package audit implements Attest's tamper-evident, append-only audit ledger.
//
// The ledger is a hash chain: each entry commits to the hash of its predecessor,
// so alteration, reordering and truncation (relative to a trusted checkpoint)
// are detectable. The chain alone is not immutable storage — a party with direct
// write access to the database can rewrite history. The trust anchor is a signed
// Checkpoint whose signing key is held outside the database (see key.go and
// docs/security-properties.md).
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// HashSize is the length in bytes of a chain hash (SHA-256).
const HashSize = sha256.Size

// Hash is a 32-byte SHA-256 digest used for the audit hash chain.
type Hash [HashSize]byte

// GenesisHash is the predecessor hash of the first entry in a ledger. It is the
// all-zero hash and is never a valid entry hash in practice.
var GenesisHash Hash

// Entry is a single append-only audit record describing one security-relevant
// action. Sequence numbers are 1-based and strictly contiguous; gaps or repeats
// indicate tampering.
type Entry struct {
	// Sequence is the 1-based position of this entry in the ledger.
	Sequence uint64
	// Time is when the entry was recorded (stored to nanosecond precision).
	Time time.Time
	// Actor is the authenticated principal that caused the action.
	Actor string
	// Action is a stable identifier for the operation (e.g. "node.enroll").
	Action string
	// Object is the resource the action targeted (e.g. "node/abc123").
	Object string
	// Metadata is opaque, caller-supplied context. It MUST NOT contain plaintext
	// secrets. It may be nil.
	Metadata []byte
	// PrevHash is the hash of the preceding entry, or GenesisHash for the first.
	PrevHash Hash
	// Hash is this entry's chain hash: SHA-256(PrevHash || canonicalBody).
	Hash Hash
}

// canonicalBody returns the deterministic byte serialization of the entry's
// security-relevant fields, excluding PrevHash and Hash. Every variable-length
// field is length-prefixed so that no field boundary can be forged by shifting
// bytes between adjacent fields.
func (e *Entry) canonicalBody() []byte {
	var buf bytes.Buffer
	putUint64(&buf, e.Sequence)
	// Timestamps are normalized to UTC nanoseconds so that the digest is
	// independent of the recording process's location.
	putUint64(&buf, uint64(e.Time.UTC().UnixNano()))
	putField(&buf, []byte(e.Actor))
	putField(&buf, []byte(e.Action))
	putField(&buf, []byte(e.Object))
	putField(&buf, e.Metadata)
	return buf.Bytes()
}

// computeHash derives an entry hash from the previous hash and the canonical
// body: H = SHA-256(prev || body). Binding prev into the digest is what makes
// reordering and truncation detectable.
func computeHash(prev Hash, body []byte) Hash {
	h := sha256.New()
	h.Write(prev[:])
	h.Write(body)
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// chainHash computes the hash an entry must have given its predecessor.
func (e *Entry) chainHash(prev Hash) Hash {
	return computeHash(prev, e.canonicalBody())
}

func putUint64(buf *bytes.Buffer, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	buf.Write(b[:])
}

// putField writes an 8-byte big-endian length prefix followed by the bytes.
func putField(buf *bytes.Buffer, b []byte) {
	putUint64(buf, uint64(len(b)))
	buf.Write(b)
}
