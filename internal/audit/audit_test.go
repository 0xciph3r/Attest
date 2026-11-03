package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
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
		{"altered prev hash only", func(e []Entry) []Entry { e[2].PrevHash[0] ^= 1; return e }, ErrPrevHash},
		{"altered hash only", func(e []Entry) []Entry { e[2].Hash[31] ^= 1; return e }, ErrEntryHash},
		{"zero sequence", func(e []Entry) []Entry { e[0].Sequence = 0; return e }, ErrSequence},
		{"altered after checkpoint", func(e []Entry) []Entry { e[8].Object = "node/evil"; return e }, ErrEntryHash},
		{"appended copy of head", func(e []Entry) []Entry { return append(e, e[9]) }, ErrSequence},
		{"appended entry not chained", func(e []Entry) []Entry {
			x := e[9]
			x.Sequence = 11
			x.PrevHash = e[8].Hash
			x.Hash = x.chainHash(x.PrevHash)
			return append(e, x)
		}, ErrPrevHash},
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
		"long actor":     func(r *Record) { r.Actor = strings.Repeat("a", MaxFieldSize+1) },
		"long object":    func(r *Record) { r.Object = strings.Repeat("o", MaxFieldSize+1) },
		"invalid utf-8":  func(r *Record) { r.Actor = "operator:\xff" },
		"after 2262":     func(r *Record) { r.Time = time.Date(2263, 1, 1, 0, 0, 0, 0, time.UTC) },
		"before 1678":    func(r *Record) { r.Time = time.Date(1677, 1, 1, 0, 0, 0, 0, time.UTC) },
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
	if _, err := Next(Head{Sequence: math.MaxUint64, Hash: Hash{1}}, valid); !errors.Is(err, ErrInvalidRecord) {
		t.Errorf("exhausted sequence: got %v", err)
	}
	edge := valid
	edge.Actor = strings.Repeat("a", MaxFieldSize)
	edge.Metadata = make([]byte, MaxMetadataSize)
	if _, err := Next(Head{}, edge); err != nil {
		t.Errorf("maximum sizes: %v", err)
	}
}

// aliasTime returns a time 2^64 nanoseconds after t: a different instant
// with the same wrapped UnixNano encoding.
func aliasTime(t time.Time) time.Time {
	const s, ns = 18446744073, 709551616 // 2^64 ns
	return time.Unix(t.Unix()+s, int64(t.Nanosecond())+ns).UTC()
}

func TestVerifyRejectsMalformedEntries(t *testing.T) {
	key := newKey(t)
	for name, mutate := range map[string]func(*Entry){
		// The hash would not change, so without a range check this edit
		// would pass even a checkpointed verification.
		"time aliased past 2262": func(e *Entry) { e.Time = aliasTime(e.Time) },
		"zero time":              func(e *Entry) { e.Time = time.Time{} },
		"empty actor":            func(e *Entry) { e.Actor = "" },
		"invalid utf-8":          func(e *Entry) { e.Object = "node/\xc3" },
		"oversized metadata":     func(e *Entry) { e.Metadata = make([]byte, MaxMetadataSize+1) },
	} {
		t.Run(name, func(t *testing.T) {
			entries := buildChain(t, 3)
			cp := checkpointAt(t, entries, 3, key)
			before := entries[1].Hash
			mutate(&entries[1])
			// Rehash the suffix as a database writer would.
			prev := entries[0].Hash
			for i := 1; i < len(entries); i++ {
				entries[i].PrevHash = prev
				entries[i].Hash = entries[i].chainHash(prev)
				prev = entries[i].Hash
			}
			if name == "time aliased past 2262" && entries[1].Hash != before {
				t.Fatal("alias did not collide; test is not exercising the wrap")
			}
			_, err := Verify(Slice(entries), opts(key, cp))
			if !errors.Is(err, ErrMalformedEntry) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestCheckpointKeyMisuse(t *testing.T) {
	entries := buildChain(t, 2)
	key := newKey(t)
	head := Head{Sequence: 2, Hash: entries[1].Hash}

	mismatched := append(ed25519.PrivateKey(nil), key...)
	copy(mismatched[32:], newKey(t)[32:])
	for name, k := range map[string]ed25519.PrivateKey{
		"nil":               nil,
		"seed only":         key.Seed(),
		"truncated":         key[:63],
		"mismatched halves": mismatched,
	} {
		if _, err := SignCheckpoint(head, t0, k); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
	if _, err := SignCheckpoint(head, time.Date(2263, 1, 1, 0, 0, 0, 0, time.UTC), key); err == nil {
		t.Error("signed an unencodable time")
	}

	cp := checkpointAt(t, entries, 2, key)
	for name, ring := range map[string]KeyRing{
		"short key": {cp.KeyID: key.Public().(ed25519.PublicKey)[:31]},
		"nil key":   {cp.KeyID: nil},
		"empty":     {},
		"nil ring":  nil,
	} {
		if err := cp.Verify(ring); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	for name, mutate := range map[string]func(*SignedCheckpoint){
		"no signature":    func(c *SignedCheckpoint) { c.Signature = nil },
		"short signature": func(c *SignedCheckpoint) { c.Signature = c.Signature[:63] },
		"long signature":  func(c *SignedCheckpoint) { c.Signature = append(c.Signature, 0) },
		"zero sequence":   func(c *SignedCheckpoint) { c.Sequence = 0 },
		"time aliased":    func(c *SignedCheckpoint) { c.Time = aliasTime(c.Time) },
		"key id case":     func(c *SignedCheckpoint) { c.KeyID = strings.ToUpper(c.KeyID) },
		"flipped sig bit": func(c *SignedCheckpoint) { c.Signature[0] ^= 1 },
	} {
		c := checkpointAt(t, entries, 2, key)
		c.Signature = append([]byte(nil), c.Signature...)
		mutate(&c)
		if err := c.Verify(NewKeyRing(key.Public().(ed25519.PublicKey))); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

func TestParseHash(t *testing.T) {
	good := strings.Repeat("ab", HashSize)
	if _, err := ParseHash(good); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]string{
		"uppercase":  strings.ToUpper(good),
		"mixed case": "A" + good[1:],
		"short":      good[:63],
		"long":       good + "0",
		"odd digit":  good[:63] + "g",
		"whitespace": " " + good[1:],
		"0x prefix":  "0x" + good[2:],
		"empty":      "",
	} {
		if _, err := ParseHash(s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := HashFromBytes(make([]byte, 31)); err == nil {
		t.Error("31-byte hash accepted")
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

	if _, err := Verify(ReadJSONL(bytes.NewBufferString(`{"seq":1,"bogus":true}`+"\n")), VerifyOptions{AllowUnanchored: true}); err == nil {
		t.Fatal("unknown fields must be rejected")
	}
}

func TestReadJSONLRejects(t *testing.T) {
	entries := buildChain(t, 3)
	var buf bytes.Buffer
	if _, err := WriteJSONL(&buf, Slice(entries)); err != nil {
		t.Fatal(err)
	}
	export := buf.String()
	lines := strings.SplitAfter(export, "\n")
	first := strings.TrimSuffix(lines[0], "\n")
	unanchored := VerifyOptions{AllowUnanchored: true}

	for name, doc := range map[string]string{
		"unterminated last line": strings.TrimSuffix(export, "\n"),
		"truncated mid-line":     export[:len(export)-20],
		"blank line":             lines[0] + "\n" + lines[1] + lines[2],
		"leading blank line":     "\n" + export,
		"two values on a line":   first + first + "\n",
		"value split over lines": strings.Replace(lines[0], `,"actor"`, "\n,\"actor\"", 1),
		"duplicate key":          strings.Replace(lines[0], `{"seq":1,`, `{"seq":1,"seq":1,`, 1),
		"case-variant key":       strings.Replace(lines[0], `"actor":`, `"Actor":`, 1),
		"unknown key":            strings.Replace(lines[0], `{"seq":1,`, `{"seq":1,"note":"x",`, 1),
		"uppercase hash":         strings.Replace(lines[0], entries[0].Hash.String(), strings.ToUpper(entries[0].Hash.String()), 1),
		"short hash":             strings.Replace(lines[0], entries[0].Hash.String(), entries[0].Hash.String()[:62], 1),
		"negative seq":           strings.Replace(lines[0], `{"seq":1,`, `{"seq":-1,`, 1),
		"string seq":             strings.Replace(lines[0], `{"seq":1,`, `{"seq":"1",`, 1),
		"seq overflow":           strings.Replace(lines[0], `{"seq":1,`, `{"seq":18446744073709551616,`, 1),
		"bad base64 metadata":    strings.Replace(lines[0], `"metadata":"`, `"metadata":"!`, 1),
		"bad time":               strings.Replace(lines[0], `"time":"2026`, `"time":"26`, 1),
		"array line":             "[" + first + "]\n",
		"null line":              "null\n",
		"oversized line":         `{"seq":1,"actor":"` + strings.Repeat("a", maxLineSize) + `"}` + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(ReadJSONL(strings.NewReader(doc)), unanchored); err == nil {
				t.Fatal("accepted")
			}
		})
	}

	// The largest entry Next accepts must survive export and import.
	big, err := Next(Head{}, Record{
		Time:     t0,
		Actor:    strings.Repeat("\x01", MaxFieldSize), // escaped to \u0001 in JSON
		Action:   strings.Repeat("<", MaxFieldSize),
		Object:   strings.Repeat("\u2028", MaxFieldSize/3),
		Metadata: bytes.Repeat([]byte{0xff}, MaxMetadataSize),
	})
	if err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if _, err := WriteJSONL(&buf, Slice([]Entry{big})); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ReadJSONL(&buf), unanchored); err != nil {
		t.Fatalf("maximum entry: %v", err)
	}
}

func TestReadJSONLPropagatesReadErrors(t *testing.T) {
	boom := errors.New("disk read failed")
	r := io.MultiReader(strings.NewReader(`{"seq":1`), iotest.ErrReader(boom))
	if _, err := Verify(ReadJSONL(r), VerifyOptions{AllowUnanchored: true}); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
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
	if _, err := GenerateKeyFiles(filepath.Join(dir, "same"), filepath.Join(dir, "same")); err == nil {
		t.Fatal("private and public key at the same path")
	}
	if _, err := os.Stat(filepath.Join(dir, "same")); !os.IsNotExist(err) {
		t.Fatal("failed generation left a private key behind")
	}
	if _, err := GenerateKeyFiles(filepath.Join(dir, "missing", "k"), filepath.Join(dir, "p")); err == nil {
		t.Fatal("missing directory")
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

func TestLoadKeyRejects(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath := filepath.Join(dir, "k"), filepath.Join(dir, "k.pub")
	if _, err := GenerateKeyFiles(privPath, pubPath); err != nil {
		t.Fatal(err)
	}
	priv, _ := os.ReadFile(privPath)
	pub, _ := os.ReadFile(pubPath)
	write := func(data []byte) string {
		p := filepath.Join(dir, "case")
		_ = os.Remove(p)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

	rsa := []byte("-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALRiMLAh9iimur8VA7qVvdqxevEuUkW4K+2KdMXmnQbG9Aa7k7eBjK1S+0LYmVjPKlJGNXHDGuy5Fw/d7rjVJ0BLB+ubPK8iA/Tw3hLQgXMRRGRXXCn8ikfuQfjUS1uZSatdLB81mydBETlJhI6GH4twrbDJCR2Bwy/XWXgqgGRcCAwEAAQ==\n-----END PUBLIC KEY-----\n")
	for name, c := range map[string]struct {
		data []byte
		load func(string) error
	}{
		"public as private":     {pub, loadPriv},
		"private as public":     {priv, loadPub},
		"empty":                 {nil, loadPub},
		"not pem":               {[]byte("hello"), loadPub},
		"trailing garbage":      {cat(pub, []byte("garbage")), loadPub},
		"leading garbage":       {cat([]byte("garbage\n"), pub), loadPub},
		"two keys":              {cat(pub, pub), loadPub},
		"malformed block first": {cat([]byte("-----BEGIN PUBLIC KEY-----\n!!\n-----END PUBLIC KEY-----\n"), pub), loadPub},
		"headers":               {bytes.Replace(pub, []byte("KEY-----\n"), []byte("KEY-----\nProc-Type: 4,ENCRYPTED\n\n"), 1), loadPub},
		"rsa key":               {rsa, loadPub},
		"corrupt der":           {bytes.Replace(pub, []byte("MCowBQYDK2Vw"), []byte("MCowBQYDK2Vx"), 1), loadPub},
		"oversized":             {cat(pub, bytes.Repeat([]byte(" "), maxKeyFileSize)), loadPub},
	} {
		if err := c.load(write(c.data)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	if err := loadPub(write(cat([]byte("\n"), pub, []byte("\n\n")))); err != nil {
		t.Errorf("surrounding whitespace: %v", err)
	}
	if err := loadPub(dir); err == nil {
		t.Error("directory loaded")
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(dir, "link")
		if err := os.Symlink(privPath, link); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(privPath, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := loadPriv(link); err == nil {
			t.Error("group-readable key loaded through a symlink")
		}
		if err := os.Chmod(privPath, 0o400); err != nil {
			t.Fatal(err)
		}
		if err := loadPriv(link); err != nil {
			t.Errorf("0400 key: %v", err)
		}
	}
}

func loadPriv(p string) error { _, err := LoadPrivateKey(p); return err }
func loadPub(p string) error  { _, err := LoadPublicKey(p); return err }
