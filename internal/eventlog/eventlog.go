// Package eventlog parses and replays TCG PC Client crypto-agile
// measured-boot event logs (TCG PC Client Platform Firmware Profile,
// section 10) for the SHA-256 PCR bank.
//
// The parser is deliberately strict and fails closed: unknown digest
// algorithms in an event, truncated or trailing data, oversized fields and
// replay mismatches are errors, and no firmware workarounds are applied.
// Every requested PCR must replay exactly, including PCRs that have no
// events (they must hold their reset value).
//
// The event log is untrusted input. It only becomes meaningful once the
// PCR values it is replayed against have been authenticated by a verified
// TPM quote.
package eventlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

// Event types referenced by this package.
const (
	EvNoAction uint32 = 0x00000003
)

const (
	algSHA1   uint16 = 0x0004
	algSHA256 uint16 = 0x000b

	maxPCR = 23

	// MaxLogSize bounds the input accepted by Parse.
	MaxLogSize = 4 << 20
	// MaxEvents bounds the number of events in a log.
	MaxEvents = 16384
	// MaxEventDataSize bounds a single event's data.
	MaxEventDataSize = 1 << 20

	maxAlgorithms = 8
)

var specIDSignature = []byte("Spec ID Event03\x00")

var startupLocalitySignature = []byte("StartupLocality\x00")

// Errors returned by Parse and Replay.
var (
	ErrEmpty     = errors.New("eventlog: empty log")
	ErrTooLarge  = errors.New("eventlog: log too large")
	ErrMalformed = errors.New("eventlog: malformed log")
	ErrNoSHA256  = errors.New("eventlog: log has no SHA-256 digests")
	ErrReplay    = errors.New("eventlog: replay does not match PCR value")
)

// Event is one measurement from the log.
type Event struct {
	Seq    int
	PCR    uint32
	Type   uint32
	Digest []byte // SHA-256
	Data   []byte
}

// Log is a parsed, not yet replayed, event log.
type Log struct {
	Events []Event
	// locality is the PCR 0 startup locality from a StartupLocality event.
	locality byte
}

type reader struct {
	b   []byte
	off int
}

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || n > len(r.b)-r.off {
		return nil, fmt.Errorf("%w: truncated at offset %d", ErrMalformed, r.off)
	}
	out := r.b[r.off : r.off+n]
	r.off += n
	return out, nil
}

func (r *reader) u8() (uint8, error) {
	b, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *reader) u16() (uint16, error) {
	b, err := r.take(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func (r *reader) u32() (uint32, error) {
	b, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (r *reader) sized(limit int) ([]byte, error) {
	n, err := r.u32()
	if err != nil {
		return nil, err
	}
	if n > uint32(limit) { //nolint:gosec // limit is a small positive constant
		return nil, fmt.Errorf("%w: field of %d bytes exceeds %d", ErrMalformed, n, limit)
	}
	return r.take(int(n))
}

// Parse decodes a crypto-agile event log.
func Parse(raw []byte) (*Log, error) {
	if len(raw) == 0 {
		return nil, ErrEmpty
	}
	if len(raw) > MaxLogSize {
		return nil, ErrTooLarge
	}
	r := &reader{b: raw}
	digestSizes, err := parseHeader(r)
	if err != nil {
		return nil, err
	}
	log := &Log{}
	sawLocality := false
	for seq := 1; r.off < len(r.b); seq++ {
		if seq > MaxEvents {
			return nil, fmt.Errorf("%w: more than %d events", ErrTooLarge, MaxEvents)
		}
		ev, err := parseEvent(r, seq, digestSizes)
		if err != nil {
			return nil, err
		}
		if ev.Type == EvNoAction {
			if ev.PCR == 0 && len(ev.Data) == len(startupLocalitySignature)+1 &&
				bytes.HasPrefix(ev.Data, startupLocalitySignature) {
				if sawLocality || len(log.Events) > 0 {
					return nil, fmt.Errorf("%w: misplaced StartupLocality event", ErrMalformed)
				}
				sawLocality = true
				log.locality = ev.Data[len(ev.Data)-1]
			}
			continue
		}
		log.Events = append(log.Events, ev)
	}
	return log, nil
}

func parseHeader(r *reader) (map[uint16]int, error) {
	pcr, err := r.u32()
	if err != nil {
		return nil, err
	}
	typ, err := r.u32()
	if err != nil {
		return nil, err
	}
	sha1Digest, err := r.take(20)
	if err != nil {
		return nil, err
	}
	data, err := r.sized(MaxEventDataSize)
	if err != nil {
		return nil, err
	}
	if pcr != 0 || typ != EvNoAction || !bytes.Equal(sha1Digest, make([]byte, 20)) ||
		!bytes.HasPrefix(data, specIDSignature) {
		return nil, fmt.Errorf("%w: missing Spec ID Event03 header (only crypto-agile logs are supported)", ErrMalformed)
	}
	s := &reader{b: data, off: len(specIDSignature)}
	// platformClass(4) specVersionMinor(1) specVersionMajor(1) specErrata(1) uintnSize(1)
	if _, err := s.take(8); err != nil {
		return nil, err
	}
	n, err := s.u32()
	if err != nil {
		return nil, err
	}
	if n == 0 || n > maxAlgorithms {
		return nil, fmt.Errorf("%w: %d digest algorithms", ErrMalformed, n)
	}
	sizes := make(map[uint16]int, n)
	for range n {
		alg, err := s.u16()
		if err != nil {
			return nil, err
		}
		size, err := s.u16()
		if err != nil {
			return nil, err
		}
		if _, dup := sizes[alg]; dup || size == 0 || size > 64 {
			return nil, fmt.Errorf("%w: bad algorithm entry %#x/%d", ErrMalformed, alg, size)
		}
		sizes[alg] = int(size)
	}
	if sizes[algSHA256] != sha256.Size {
		return nil, ErrNoSHA256
	}
	if sz, ok := sizes[algSHA1]; ok && sz != 20 {
		return nil, fmt.Errorf("%w: bad SHA-1 digest size", ErrMalformed)
	}
	vendorLen, err := s.u8()
	if err != nil {
		return nil, err
	}
	if _, err := s.take(int(vendorLen)); err != nil {
		return nil, err
	}
	if s.off != len(s.b) {
		return nil, fmt.Errorf("%w: trailing bytes in Spec ID event", ErrMalformed)
	}
	return sizes, nil
}

func parseEvent(r *reader, seq int, sizes map[uint16]int) (Event, error) {
	pcr, err := r.u32()
	if err != nil {
		return Event{}, err
	}
	if pcr > maxPCR {
		return Event{}, fmt.Errorf("%w: event %d has PCR %d", ErrMalformed, seq, pcr)
	}
	typ, err := r.u32()
	if err != nil {
		return Event{}, err
	}
	count, err := r.u32()
	if err != nil {
		return Event{}, err
	}
	if count != uint32(len(sizes)) { //nolint:gosec // len(sizes) <= maxAlgorithms
		return Event{}, fmt.Errorf("%w: event %d has %d digests, header declares %d", ErrMalformed, seq, count, len(sizes))
	}
	seen := make(map[uint16]bool, count)
	var digest []byte
	for range count {
		alg, err := r.u16()
		if err != nil {
			return Event{}, err
		}
		size, ok := sizes[alg]
		if !ok || seen[alg] {
			return Event{}, fmt.Errorf("%w: event %d has unexpected digest algorithm %#x", ErrMalformed, seq, alg)
		}
		seen[alg] = true
		d, err := r.take(size)
		if err != nil {
			return Event{}, err
		}
		if alg == algSHA256 {
			digest = d
		}
	}
	data, err := r.sized(MaxEventDataSize)
	if err != nil {
		return Event{}, err
	}
	return Event{Seq: seq, PCR: pcr, Type: typ, Digest: digest, Data: data}, nil
}

// ReplayError reports the PCRs whose replayed value differs from the
// authenticated value.
type ReplayError struct {
	PCRs []uint32
}

func (e *ReplayError) Error() string {
	return fmt.Sprintf("%v: PCRs %v", ErrReplay, e.PCRs)
}

// Unwrap allows errors.Is(err, ErrReplay).
func (e *ReplayError) Unwrap() error { return ErrReplay }

// initial returns the reset value of a PCR in the SHA-256 bank.
func (l *Log) initial(pcr uint32) []byte {
	v := make([]byte, sha256.Size)
	if pcr == 0 {
		v[sha256.Size-1] = l.locality
	}
	return v
}

// Replay recomputes every PCR in pcrs from the log and compares it with
// the authenticated value. It returns the events for those PCRs, in log
// order.
func (l *Log) Replay(pcrs map[uint32][]byte) ([]Event, error) {
	if len(pcrs) == 0 {
		return nil, fmt.Errorf("%w: no PCRs to replay", ErrMalformed)
	}
	acc := make(map[uint32][]byte, len(pcrs))
	for p := range pcrs {
		acc[p] = l.initial(p)
	}
	var out []Event
	for _, ev := range l.Events {
		cur, ok := acc[ev.PCR]
		if !ok {
			continue
		}
		h := sha256.New()
		h.Write(cur)
		h.Write(ev.Digest)
		acc[ev.PCR] = h.Sum(nil)
		out = append(out, ev)
	}
	var bad []uint32
	for p, want := range pcrs {
		if !bytes.Equal(acc[p], want) {
			bad = append(bad, p)
		}
	}
	if len(bad) > 0 {
		slices.Sort(bad)
		return nil, &ReplayError{PCRs: bad}
	}
	return out, nil
}

// ParseAndReplay parses raw and replays it against pcrs.
func ParseAndReplay(raw []byte, pcrs map[uint32][]byte) ([]Event, error) {
	l, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	return l.Replay(pcrs)
}
