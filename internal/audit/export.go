package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"time"

	"github.com/0xciph3r/attest/internal/strictjson"
)

// jsonEntry is the JSON Lines export representation of an Entry. Metadata is
// base64-encoded by encoding/json. Hashes are hex.
type jsonEntry struct {
	Sequence uint64    `json:"seq"`
	Time     time.Time `json:"time"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	Object   string    `json:"object"`
	Metadata []byte    `json:"metadata,omitempty"`
	PrevHash Hash      `json:"prev_hash"`
	Hash     Hash      `json:"hash"`
}

// WriteJSONL writes entries as JSON Lines and returns the number written. An
// export carries no integrity of its own; verify it against a trusted
// checkpoint.
func WriteJSONL(w io.Writer, entries iter.Seq2[Entry, error]) (uint64, error) {
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	var n uint64
	for e, err := range entries {
		if err != nil {
			return n, err
		}
		if err := enc.Encode(jsonEntry{
			Sequence: e.Sequence,
			Time:     e.Time.UTC(),
			Actor:    e.Actor,
			Action:   e.Action,
			Object:   e.Object,
			Metadata: e.Metadata,
			PrevHash: e.PrevHash,
			Hash:     e.Hash,
		}); err != nil {
			return n, err
		}
		n++
	}
	return n, bw.Flush()
}

// maxLineSize bounds one export line: three fields of MaxFieldSize bytes,
// each of which JSON may escape to six bytes per byte, base64 metadata, and
// the fixed fields.
const maxLineSize = 3*6*MaxFieldSize + (MaxMetadataSize+2)/3*4 + 1024

// ReadJSONL streams entries from a JSON Lines export, one object per line
// exactly as WriteJSONL writes them. A line that is blank, too long, carries
// duplicate, case-variant or unknown keys, or holds more than one value is
// rejected so that a malformed or foreign file is not silently accepted.
func ReadJSONL(r io.Reader) iter.Seq2[Entry, error] {
	return func(yield func(Entry, error) bool) {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64<<10), maxLineSize)
		sc.Split(scanLines)
		for line := 1; sc.Scan(); line++ {
			var je jsonEntry
			if err := strictjson.Decode(sc.Bytes(), &je); err != nil {
				yield(Entry{}, fmt.Errorf("audit: export line %d: %w", line, err))
				return
			}
			e := Entry{
				Sequence: je.Sequence,
				Time:     je.Time.UTC(),
				Actor:    je.Actor,
				Action:   je.Action,
				Object:   je.Object,
				Metadata: je.Metadata,
				PrevHash: je.PrevHash,
				Hash:     je.Hash,
			}
			if !yield(e, nil) {
				return
			}
		}
		if err := sc.Err(); err != nil {
			yield(Entry{}, fmt.Errorf("audit: reading export: %w", err))
		}
	}
}

var errUnterminated = errors.New("last line is not newline-terminated (truncated export?)")

// scanLines splits on '\n'. Unlike bufio.ScanLines it rejects an
// unterminated final line, which is what a truncated export looks like.
func scanLines(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF && len(data) > 0 {
		return 0, nil, errUnterminated
	}
	return 0, nil, nil
}

// Slice adapts an in-memory slice to the iterator form accepted by Verify.
func Slice(entries []Entry) iter.Seq2[Entry, error] {
	return func(yield func(Entry, error) bool) {
		for _, e := range entries {
			if !yield(e, nil) {
				return
			}
		}
	}
}
