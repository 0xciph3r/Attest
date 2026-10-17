package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"time"
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

// ReadJSONL streams entries from a JSON Lines export. Unknown fields are
// rejected so that a malformed or foreign file is not silently accepted.
func ReadJSONL(r io.Reader) iter.Seq2[Entry, error] {
	return func(yield func(Entry, error) bool) {
		dec := json.NewDecoder(bufio.NewReader(r))
		dec.DisallowUnknownFields()
		for line := 1; ; line++ {
			var je jsonEntry
			err := dec.Decode(&je)
			if errors.Is(err, io.EOF) {
				return
			}
			if err != nil {
				yield(Entry{}, fmt.Errorf("audit: export record %d: %w", line, err))
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
	}
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
