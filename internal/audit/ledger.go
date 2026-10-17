package audit

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// MaxMetadataSize bounds the metadata attached to a single entry.
const MaxMetadataSize = 64 << 10

// Head identifies the tip of a ledger. The zero Head is the empty ledger.
type Head struct {
	Sequence uint64
	Hash     Hash
}

// Record is the caller-supplied content of a new audit entry.
type Record struct {
	Time     time.Time
	Actor    string
	Action   string
	Object   string
	Metadata []byte
}

// ErrInvalidRecord is returned when a record cannot be appended.
var ErrInvalidRecord = errors.New("audit: invalid record")

// Next builds the entry that extends the ledger at head with rec. It does not
// persist anything; the caller must store the entry atomically with reading
// head so that concurrent appends cannot fork the chain.
func Next(head Head, rec Record) (Entry, error) {
	switch {
	case rec.Time.IsZero():
		return Entry{}, fmt.Errorf("%w: time is required", ErrInvalidRecord)
	case rec.Actor == "":
		return Entry{}, fmt.Errorf("%w: actor is required", ErrInvalidRecord)
	case rec.Action == "":
		return Entry{}, fmt.Errorf("%w: action is required", ErrInvalidRecord)
	case rec.Object == "":
		return Entry{}, fmt.Errorf("%w: object is required", ErrInvalidRecord)
	case len(rec.Metadata) > MaxMetadataSize:
		return Entry{}, fmt.Errorf("%w: metadata exceeds %d bytes", ErrInvalidRecord, MaxMetadataSize)
	}
	if head.Sequence == 0 && head.Hash != GenesisHash {
		return Entry{}, fmt.Errorf("%w: empty ledger head must carry the genesis hash", ErrInvalidRecord)
	}
	e := Entry{
		Sequence: head.Sequence + 1,
		// UTC() strips the monotonic reading and the location, so the entry
		// compares equal to its persisted form.
		Time:     rec.Time.UTC(),
		Actor:    rec.Actor,
		Action:   rec.Action,
		Object:   rec.Object,
		Metadata: rec.Metadata,
		PrevHash: head.Hash,
	}
	e.Hash = e.chainHash(head.Hash)
	return e, nil
}

// String returns the lowercase hex encoding of h.
func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// MarshalText encodes h as lowercase hex.
func (h Hash) MarshalText() ([]byte, error) { return []byte(h.String()), nil }

// UnmarshalText decodes a hex-encoded hash of exactly HashSize bytes.
func (h *Hash) UnmarshalText(b []byte) error {
	parsed, err := ParseHash(string(b))
	if err != nil {
		return err
	}
	*h = parsed
	return nil
}

// ParseHash decodes a hex-encoded hash of exactly HashSize bytes.
func ParseHash(s string) (Hash, error) {
	var h Hash
	if len(s) != 2*HashSize {
		return h, fmt.Errorf("audit: hash must be %d hex characters, got %d", 2*HashSize, len(s))
	}
	if _, err := hex.Decode(h[:], []byte(s)); err != nil {
		return h, fmt.Errorf("audit: invalid hash: %w", err)
	}
	return h, nil
}

// HashFromBytes copies a raw HashSize-byte digest into a Hash.
func HashFromBytes(b []byte) (Hash, error) {
	var h Hash
	if len(b) != HashSize {
		return h, fmt.Errorf("audit: hash must be %d bytes, got %d", HashSize, len(b))
	}
	copy(h[:], b)
	return h, nil
}
