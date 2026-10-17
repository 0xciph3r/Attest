package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 17, 12, 0, 0, 123456789, time.UTC)

func buildChain(t *testing.T, n int) []Entry {
	t.Helper()
	var (
		head    Head
		entries []Entry
	)
	for i := range n {
		e, err := Next(head, Record{
			Time:     t0.Add(time.Duration(i) * time.Second),
			Actor:    "operator:alice",
			Action:   "node.enroll",
			Object:   "node/n" + string(rune('a'+i)),
			Metadata: []byte(`{"i":` + string(rune('0'+i%10)) + `}`),
		})
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		entries = append(entries, e)
		head = Head{Sequence: e.Sequence, Hash: e.Hash}
	}
	return entries
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func checkpointAt(t *testing.T, entries []Entry, seq uint64, key ed25519.PrivateKey) SignedCheckpoint {
	t.Helper()
	e := entries[seq-1]
	cp, err := SignCheckpoint(Head{Sequence: e.Sequence, Hash: e.Hash}, t0, key)
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

func opts(key ed25519.PrivateKey, cps ...SignedCheckpoint) VerifyOptions {
	return VerifyOptions{Checkpoints: cps, Keys: NewKeyRing(key.Public().(ed25519.PublicKey))}
}

func TestVerifyAcceptsValidChain(t *testing.T) {
	entries := buildChain(t, 10)
	key := newKey(t)
	rep, err := Verify(Slice(entries), opts(key, checkpointAt(t, entries, 4, key), checkpointAt(t, entries, 8, key)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Head.Sequence != 10 || rep.CheckpointsVerified != 2 || rep.AnchoredThrough != 8 || rep.Unanchored() != 2 {
		t.Fatalf("unexpected report %+v", rep)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	key := newKey(t)
	tests := []struct {
		name   string
		mutate func([]Entry) []Entry
		want   error
	}{
		{"altered actor", func(e []Entry) []Entry { e[2].Actor = "operator:mallory"; return e }, ErrEntryHash},
		{"altered action", func(e []Entry) []Entry { e[2].Action = "secret.get"; return e }, ErrEntryHash},
		{"altered object", func(e []Entry) []Entry { e[2].Object = "node/evil"; return e }, ErrEntryHash},
		{"altered metadata", func(e []Entry) []Entry { e[2].Metadata = []byte(`{}`); return e }, ErrEntryHash},
		{"altered time", func(e []Entry) []Entry { e[2].Time = e[2].Time.Add(time.Nanosecond); return e }, ErrEntryHash},
		{"swapped entries", func(e []Entry) []Entry { e[3], e[4] = e[4], e[3]; return e }, ErrSequence},
		{"deleted middle entry", func(e []Entry) []Entry { return append(e[:3:3], e[4:]...) }, ErrSequence},
		{"duplicated entry", func(e []Entry) []Entry { return append(e[:4:4], e[3:]...) }, ErrSequence},
		{"renumbered after deletion", func(e []Entry) []Entry {
			e = append(e[:3:3], e[4:]...)
			for i := 3; i < len(e); i++ {
				e[i].Sequence--
			}
			return e
		}, ErrPrevHash},
		{
			// An attacker with write access rewrites an entry and recomputes
			// every subsequent hash. The chain is internally consistent; only
			// the trusted checkpoint reveals the rewrite.
			"rewritten and rehashed suffix", func(e []Entry) []Entry {
				e[1].Actor = "operator:mallory"
				prev := e[0].Hash
				for i := 1; i < len(e); i++ {
					e[i].PrevHash = prev
					e[i].Hash = e[i].chainHash(prev)
					prev = e[i].Hash
				}
				return e
			}, ErrCheckpointMismatch,
		},
		{"truncated before checkpoint", func(e []Entry) []Entry { return e[:5] }, ErrTruncated},
		{"emptied ledger", func(e []Entry) []Entry { return nil }, ErrTruncated},
		{"missing genesis entry", func(e []Entry) []Entry { return e[1:] }, ErrSequence},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entries := buildChain(t, 10)
			cp := checkpointAt(t, entries, 7, key)
			_, err := Verify(Slice(tc.mutate(entries)), opts(key, cp))
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			var ve *VerifyError
			if !errors.As(err, &ve) {
				t.Fatalf("error %T is not a *VerifyError", err)
			}
		})
	}
}

func TestCanonicalFieldBoundaries(t *testing.T) {
	a := Entry{Sequence: 1, Time: t0, Actor: "ab", Action: "c", Object: "o"}
	b := Entry{Sequence: 1, Time: t0, Actor: "a", Action: "bc", Object: "o"}
	if a.chainHash(GenesisHash) == b.chainHash(GenesisHash) {
		t.Fatal("shifting bytes between fields must change the hash")
	}
}

func TestVerifyCheckpointTrust(t *testing.T) {
	entries := buildChain(t, 5)
	key, other := newKey(t), newKey(t)

	t.Run("unanchored rejected by default", func(t *testing.T) {
		if _, err := Verify(Slice(entries), opts(key)); !errors.Is(err, ErrUnanchored) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("unanchored allowed explicitly", func(t *testing.T) {
		o := opts(key)
		o.AllowUnanchored = true
		rep, err := Verify(Slice(entries), o)
		if err != nil || rep.Unanchored() != 5 {
			t.Fatalf("rep=%+v err=%v", rep, err)
		}
	})
	t.Run("untrusted key", func(t *testing.T) {
		if _, err := Verify(Slice(entries), opts(key, checkpointAt(t, entries, 3, other))); !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("forged key id", func(t *testing.T) {
		cp := checkpointAt(t, entries, 3, other)
		cp.KeyID = KeyID(key.Public().(ed25519.PublicKey))
		if _, err := Verify(Slice(entries), opts(key, cp)); !errors.Is(err, ErrCheckpointSignature) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("altered checkpoint", func(t *testing.T) {
		for name, mutate := range map[string]func(*SignedCheckpoint){
			"sequence": func(c *SignedCheckpoint) { c.Sequence = 2 },
			"hash":     func(c *SignedCheckpoint) { c.Hash = entries[1].Hash },
			"time":     func(c *SignedCheckpoint) { c.Time = c.Time.Add(time.Second) },
		} {
			cp := checkpointAt(t, entries, 3, key)
			mutate(&cp)
			if _, err := Verify(Slice(entries), opts(key, cp)); !errors.Is(err, ErrCheckpointSignature) {
				t.Errorf("%s: got %v", name, err)
			}
		}
	})
	t.Run("conflicting checkpoints", func(t *testing.T) {
		forkedEntries := buildChain(t, 5)
		forkedEntries[2].Actor = "x"
		forkedEntries[2].Hash = forkedEntries[2].chainHash(forkedEntries[1].Hash)
		_, err := Verify(Slice(entries), opts(key, checkpointAt(t, entries, 3, key), checkpointAt(t, forkedEntries, 3, key)))
		if !errors.Is(err, ErrConflictingCheckpoint) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("empty ledger cannot be checkpointed", func(t *testing.T) {
		if _, err := SignCheckpoint(Head{}, t0, key); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestVerifyPropagatesSourceErrors(t *testing.T) {
	boom := errors.New("disk read failed")
	src := func(yield func(Entry, error) bool) { yield(Entry{}, boom) }
	o := VerifyOptions{AllowUnanchored: true}
	if _, err := Verify(src, o); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
}

func TestNextValidation(t *testing.T) {
	valid := Record{Time: t0, Actor: "a", Action: "b", Object: "c"}
	for name, mutate := range map[string]func(*Record){
		"zero time":      func(r *Record) { r.Time = time.Time{} },
		"empty actor":    func(r *Record) { r.Actor = "" },
		"empty action":   func(r *Record) { r.Action = "" },
		"empty object":   func(r *Record) { r.Object = "" },
		"large metadata": func(r *Record) { r.Metadata = make([]byte, MaxMetadataSize+1) },
	} {
		r := valid
		mutate(&r)
		if _, err := Next(Head{}, r); !errors.Is(err, ErrInvalidRecord) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if _, err := Next(Head{Hash: Hash{1}}, valid); !errors.Is(err, ErrInvalidRecord) {
		t.Errorf("non-genesis empty head: got %v", err)
	}
}

func TestJSONLRoundTrip(t *testing.T) {
	entries := buildChain(t, 6)
	entries[0].Metadata = nil
	entries[0].Hash = entries[0].chainHash(GenesisHash)
	prev := entries[0].Hash
	for i := 1; i < len(entries); i++ {
		entries[i].PrevHash = prev
		entries[i].Hash = entries[i].chainHash(prev)
		prev = entries[i].Hash
	}

	var buf bytes.Buffer
	n, err := WriteJSONL(&buf, Slice(entries))
	if err != nil || n != 6 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	key := newKey(t)
	if _, err := Verify(ReadJSONL(&buf), opts(key, checkpointAt(t, entries, 6, key))); err != nil {
		t.Fatalf("round trip: %v", err)
	}

	if _, err := Verify(ReadJSONL(bytes.NewBufferString(`{"seq":1,"bogus":true}`)), VerifyOptions{AllowUnanchored: true}); err == nil {
		t.Fatal("unknown fields must be rejected")
	}
}

func TestKeyFiles(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "audit.key"), filepath.Join(dir, "audit.pub")
	gotPub, err := GenerateKeyFiles(priv, pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateKeyFiles(priv, pub); err == nil {
		t.Fatal("must not overwrite existing key")
	}
	k, err := LoadPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	p, err := LoadPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Equal(gotPub) || !p.Equal(k.Public()) {
		t.Fatal("loaded keys do not match")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(priv, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPrivateKey(priv); err == nil {
			t.Fatal("world-readable private key must be rejected")
		}
	}
}
