package audit

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"
)

// MaxMetadataSize bounds the metadata attached to a single entry.
const MaxMetadataSize = 64 << 10

// MaxFieldSize bounds an entry's actor, action and object.
const MaxFieldSize = 1024

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
	if err := rec.validate(); err != nil {
		return Entry{}, err
	}
	if head.Sequence == math.MaxUint64 {
		return Entry{}, fmt.Errorf("%w: ledger sequence exhausted", ErrInvalidRecord)
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

func (rec *Record) validate() error {
	switch {
	case rec.Time.IsZero():
		return fmt.Errorf("%w: time is required", ErrInvalidRecord)
	case !encodableTime(rec.Time):
		return fmt.Errorf("%w: time %s is outside the encodable range", ErrInvalidRecord, rec.Time)
	}
	for _, f := range []struct{ name, v string }{{"actor", rec.Actor}, {"action", rec.Action}, {"object", rec.Object}} {
		switch {
		case f.v == "":
			return fmt.Errorf("%w: %s is required", ErrInvalidRecord, f.name)
		case len(f.v) > MaxFieldSize:
			return fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalidRecord, f.name, MaxFieldSize)
		// JSON export would replace invalid bytes with U+FFFD, changing
		// the entry so that an honest ledger's export fails verification.
		case !utf8.ValidString(f.v):
			return fmt.Errorf("%w: %s is not valid UTF-8", ErrInvalidRecord, f.name)
		}
	}
	switch {
	case len(rec.Metadata) > MaxMetadataSize:
		return fmt.Errorf("%w: metadata exceeds %d bytes", ErrInvalidRecord, MaxMetadataSize)
	}
	return nil
}

// encodableTime reports whether t survives the int64 Unix-nanosecond
// encoding used in hashes and signatures (years 1678 to 2262). Outside that
// range UnixNano wraps, so two different times would share one encoding and
// a timestamp could be altered without changing the hash.
func encodableTime(t time.Time) bool {
	return time.Unix(0, t.UnixNano()).Equal(t)
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

// ParseHash decodes a hash written as exactly 2*HashSize lowercase hex
// digits, the only form Attest produces, so each hash has one spelling.
func ParseHash(s string) (Hash, error) {
	var h Hash
	if len(s) != 2*HashSize {
		return h, fmt.Errorf("audit: hash must be %d hex characters, got %d", 2*HashSize, len(s))
	}
	if strings.ToLower(s) != s {
		return h, errors.New("audit: invalid hash: hex must be lowercase")
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
