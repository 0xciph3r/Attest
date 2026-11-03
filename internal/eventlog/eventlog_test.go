package eventlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
)

var bootPCRs = []uint32{0, 1, 2, 3, 4, 5, 6, 7}

func TestReplaySimulatedBoot(t *testing.T) {
	b := SimulatedBoot("v1")
	events, err := ParseAndReplay(b.Bytes(), b.PCRs(bootPCRs...))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != len(b.Events()) {
		t.Fatalf("got %d events, want %d", len(events), len(b.Events()))
	}
	for i, ev := range events {
		if !bytes.Equal(ev.Digest, b.Events()[i].Digest) || ev.PCR != b.Events()[i].PCR {
			t.Fatalf("event %d differs", i)
		}
	}
}

func TestReplaySubset(t *testing.T) {
	b := SimulatedBoot("v1")
	events, err := ParseAndReplay(b.Bytes(), b.PCRs(7))
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		if ev.PCR != 7 {
			t.Fatalf("event for PCR %d returned", ev.PCR)
		}
	}
}

func TestReplayRejects(t *testing.T) {
	good := SimulatedBoot("v1")
	other := SimulatedBoot("v2")
	pcrs := good.PCRs(bootPCRs...)

	tamperedDigest := good.Bytes()
	i := bytes.Index(tamperedDigest, good.Events()[0].Digest)
	tamperedDigest[i] ^= 1

	tests := []struct {
		name string
		log  []byte
		pcrs map[uint32][]byte
		want error
	}{
		{"empty log", nil, pcrs, ErrEmpty},
		{"oversized log", make([]byte, MaxLogSize+1), pcrs, ErrTooLarge},
		{"log from another boot", other.Bytes(), pcrs, ErrReplay},
		{"tampered event digest", tamperedDigest, pcrs, ErrReplay},
		{"truncated log", good.Bytes()[:len(good.Bytes())-3], pcrs, ErrMalformed},
		{"trailing garbage", append(good.Bytes(), 0xde, 0xad), pcrs, ErrMalformed},
		{"header only, PCRs extended", NewBuilder().Bytes(), pcrs, ErrReplay},
		{"missing events for extended PCR", func() []byte {
			b := NewBuilder()
			b.Measure(0, EvPostCode, []byte("only pcr0"))
			return b.Bytes()
		}(), pcrs, ErrReplay},
		{"no PCRs requested", good.Bytes(), map[uint32][]byte{}, ErrMalformed},
		{"not crypto-agile", func() []byte {
			l := good.Bytes()
			copy(l[32:], "Spec ID Event02\x00")
			return l
		}(), pcrs, ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAndReplay(tt.log, tt.pcrs)
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
}

func TestReplayErrorListsPCRs(t *testing.T) {
	b := SimulatedBoot("v1")
	pcrs := b.PCRs(bootPCRs...)
	pcrs[7] = make([]byte, 32)
	pcrs[3] = bytes.Repeat([]byte{1}, 32)
	_, err := ParseAndReplay(b.Bytes(), pcrs)
	var re *ReplayError
	if !errors.As(err, &re) || len(re.PCRs) != 2 || re.PCRs[0] != 3 || re.PCRs[1] != 7 {
		t.Fatalf("got %v", err)
	}
}

func TestNoActionEventsDoNotExtend(t *testing.T) {
	b := NewBuilder()
	b.Append(0, EvNoAction, make([]byte, 32), []byte("vendor data"))
	b.Measure(0, EvPostCode, []byte("x"))
	if _, err := ParseAndReplay(b.Bytes(), b.PCRs(0)); err != nil {
		t.Fatal(err)
	}
}

func TestStartupLocality(t *testing.T) {
	b := NewBuilder()
	b.Append(0, EvNoAction, make([]byte, 32), append([]byte("StartupLocality\x00"), 3))
	d := sha256.Sum256([]byte("fw"))
	b.Append(0, EvPostCode, d[:], []byte("fw"))

	init := make([]byte, 32)
	init[31] = 3
	h := sha256.New()
	h.Write(init)
	h.Write(d[:])
	if _, err := ParseAndReplay(b.Bytes(), map[uint32][]byte{0: h.Sum(nil)}); err != nil {
		t.Fatal(err)
	}
	// The builder ignores locality, so its own PCR 0 must not replay.
	if _, err := ParseAndReplay(b.Bytes(), b.PCRs(0)); !errors.Is(err, ErrReplay) {
		t.Fatalf("got %v", err)
	}
}

// rawLog assembles a log with a custom algorithm table.
func rawLog(algs [][2]uint16, events ...[]byte) []byte {
	return rawLogSpec([4]byte{0, 2, 0, 2}, algs, nil, events...)
}

// rawLogSpec assembles a log with custom Spec ID version fields (minor,
// major, errata, uintnSize), algorithm table and vendor info.
func rawLogSpec(version [4]byte, algs [][2]uint16, vendor []byte, events ...[]byte) []byte {
	spec := new(bytes.Buffer)
	spec.Write(specIDSignature)
	spec.Write(make([]byte, 4))
	spec.Write(version[:])
	_ = binary.Write(spec, binary.LittleEndian, uint32(len(algs)))
	for _, a := range algs {
		_ = binary.Write(spec, binary.LittleEndian, a)
	}
	spec.WriteByte(byte(len(vendor)))
	spec.Write(vendor)
	return headerWith(spec.Bytes(), events...)
}

// headerWith wraps raw Spec ID event data in a header event.
func headerWith(spec []byte, events ...[]byte) []byte {
	out := new(bytes.Buffer)
	_ = binary.Write(out, binary.LittleEndian, [2]uint32{0, EvNoAction})
	out.Write(make([]byte, 20))
	_ = binary.Write(out, binary.LittleEndian, uint32(len(spec)))
	out.Write(spec)
	for _, e := range events {
		out.Write(e)
	}
	return out.Bytes()
}

func event(pcr uint32, digests map[uint16][]byte, order []uint16, data []byte) []byte {
	out := new(bytes.Buffer)
	_ = binary.Write(out, binary.LittleEndian, [3]uint32{pcr, EvPostCode, uint32(len(order))})
	for _, alg := range order {
		_ = binary.Write(out, binary.LittleEndian, alg)
		out.Write(digests[alg])
	}
	_ = binary.Write(out, binary.LittleEndian, uint32(len(data)))
	out.Write(data)
	return out.Bytes()
}

func TestMultiAlgorithmLog(t *testing.T) {
	s1 := make([]byte, 20)
	s256 := sha256.Sum256([]byte("x"))
	digests := map[uint16][]byte{algSHA1: s1, algSHA256: s256[:]}
	algs := [][2]uint16{{algSHA1, 20}, {algSHA256, 32}}
	want := sha256.Sum256(append(make([]byte, 32), s256[:]...))
	pcrs := map[uint32][]byte{0: want[:]}

	if _, err := ParseAndReplay(rawLog(algs, event(0, digests, []uint16{algSHA1, algSHA256}, []byte("x"))), pcrs); err != nil {
		t.Fatal(err)
	}
	for name, log := range map[string][]byte{
		"no sha256 bank":       rawLog([][2]uint16{{algSHA1, 20}}),
		"missing digest":       rawLog(algs, event(0, digests, []uint16{algSHA1}, nil)),
		"duplicate digest":     rawLog(algs, event(0, digests, []uint16{algSHA256, algSHA256}, nil)),
		"undeclared algorithm": rawLog([][2]uint16{{algSHA256, 32}}, event(0, digests, []uint16{algSHA1}, nil)),
		"bad pcr index":        rawLog([][2]uint16{{algSHA256, 32}}, event(24, digests, []uint16{algSHA256}, nil)),
	} {
		if _, err := ParseAndReplay(log, pcrs); err == nil || errors.Is(err, ErrReplay) {
			t.Errorf("%s: got %v, want parse error", name, err)
		}
	}
}

func TestOversizedEventData(t *testing.T) {
	b := NewBuilder().Bytes()
	ev := new(bytes.Buffer)
	_ = binary.Write(ev, binary.LittleEndian, [3]uint32{0, EvPostCode, 1})
	_ = binary.Write(ev, binary.LittleEndian, algSHA256)
	ev.Write(make([]byte, 32))
	_ = binary.Write(ev, binary.LittleEndian, uint32(MaxEventDataSize+1))
	if _, err := Parse(append(b, ev.Bytes()...)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v", err)
	}
}

func TestTruncatedAtEveryOffset(t *testing.T) {
	b := SimulatedBoot("v1")
	full, pcrs := b.Bytes(), b.PCRs(bootPCRs...)
	for n := range len(full) {
		if _, err := ParseAndReplay(full[:n], pcrs); err == nil {
			t.Fatalf("log truncated to %d of %d bytes accepted", n, len(full))
		}
	}
}

func TestCorruptedBytesNeverPanic(t *testing.T) {
	b := SimulatedBoot("v1")
	full, pcrs := b.Bytes(), b.PCRs(bootPCRs...)
	for i := range full {
		for _, v := range []byte{0x00, 0xff, full[i] ^ 0x01} {
			l := bytes.Clone(full)
			l[i] = v
			// Event data is not hashed, so some edits are harmless; any
			// edit that is accepted must still replay to the same PCRs.
			_, _ = ParseAndReplay(l, pcrs)
		}
	}
}

func TestHeaderRejects(t *testing.T) {
	sha256Only := [][2]uint16{{algSHA256, 32}}
	pcrs := map[uint32][]byte{0: make([]byte, 32)}
	nineAlgs := make([][2]uint16, 9)
	for i := range nineAlgs {
		nineAlgs[i] = [2]uint16{uint16(0x100 + i), 32}
	}
	nineAlgs[0] = [2]uint16{algSHA256, 32}
	countOverflow := rawLog(sha256Only)
	// Patch the algorithm count to 0xffffffff.
	i := bytes.Index(countOverflow, specIDSignature) + len(specIDSignature) + 8
	binary.LittleEndian.PutUint32(countOverflow[i:], 0xffffffff)

	for name, log := range map[string][]byte{
		"spec version 1.0":       rawLogSpec([4]byte{0, 1, 0, 2}, sha256Only, nil),
		"spec version 2.1":       rawLogSpec([4]byte{1, 2, 0, 2}, sha256Only, nil),
		"uintnSize 0":            rawLogSpec([4]byte{0, 2, 0, 0}, sha256Only, nil),
		"uintnSize 3":            rawLogSpec([4]byte{0, 2, 0, 3}, sha256Only, nil),
		"no algorithms":          rawLog(nil),
		"nine algorithms":        rawLog(nineAlgs),
		"algorithm count max":    countOverflow,
		"duplicate sha256":       rawLog([][2]uint16{{algSHA256, 32}, {algSHA256, 32}}),
		"sha256 wrong size":      rawLog([][2]uint16{{algSHA256, 20}}),
		"sha1 wrong size":        rawLog([][2]uint16{{algSHA1, 32}, {algSHA256, 32}}),
		"zero-size algorithm":    rawLog([][2]uint16{{0x0012, 0}, {algSHA256, 32}}),
		"oversized algorithm":    rawLog([][2]uint16{{0x0012, 65}, {algSHA256, 32}}),
		"vendor info overruns":   headerWith(bytes.TrimSuffix(rawLogSpec([4]byte{0, 2, 0, 2}, sha256Only, []byte("abc"))[32:], []byte("c"))),
		"trailing spec bytes":    headerWith(append(rawLog(sha256Only)[32:], 0)),
		"spec id event only sig": headerWith(specIDSignature),
		"header on pcr 1": func() []byte {
			l := rawLog(sha256Only)
			l[0] = 1
			return l
		}(),
		"header nonzero sha1": func() []byte {
			l := rawLog(sha256Only)
			l[8] = 1
			return l
		}(),
		"header wrong type": func() []byte {
			l := rawLog(sha256Only)
			l[4] = 4
			return l
		}(),
	} {
		if _, err := ParseAndReplay(log, pcrs); !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrNoSHA256) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	// Both uintn sizes in the specification are accepted.
	for _, v := range [][4]byte{{0, 2, 0, 1}, {0, 2, 0, 2}, {0, 2, 105, 2}} {
		if _, err := ParseAndReplay(rawLogSpec(v, sha256Only, []byte("vendor")), pcrs); err != nil {
			t.Errorf("version %v: %v", v, err)
		}
	}
}

func TestEventRejects(t *testing.T) {
	sha256Only := [][2]uint16{{algSHA256, 32}}
	pcrs := map[uint32][]byte{0: make([]byte, 32)}
	ev := func(pcr, count, dataLen uint32, digest []byte) []byte {
		out := new(bytes.Buffer)
		_ = binary.Write(out, binary.LittleEndian, [3]uint32{pcr, EvPostCode, count})
		if digest != nil {
			_ = binary.Write(out, binary.LittleEndian, algSHA256)
			out.Write(digest)
		}
		_ = binary.Write(out, binary.LittleEndian, dataLen)
		return out.Bytes()
	}
	d := make([]byte, 32)
	for name, log := range map[string][]byte{
		"zero digests":         rawLog(sha256Only, ev(0, 0, 0, nil)),
		"digest count max":     rawLog(sha256Only, ev(0, 0xffffffff, 0, d)),
		"data length max":      rawLog(sha256Only, ev(0, 1, 0xffffffff, d)),
		"data length overruns": rawLog(sha256Only, ev(0, 1, 10, d), []byte("short")),
		"short digest":         rawLog(sha256Only, ev(0, 1, 0, d[:31])),
		"pcr max":              rawLog(sha256Only, ev(0xffffffff, 1, 0, d)),
		"pcr 24":               rawLog(sha256Only, ev(24, 1, 0, d)),
	} {
		if _, err := ParseAndReplay(log, pcrs); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: got %v", name, err)
		}
	}

	tooMany := NewBuilder()
	for range MaxEvents {
		tooMany.Append(23, EvNoAction, d, nil)
	}
	if _, err := Parse(tooMany.Bytes()); err != nil {
		t.Fatalf("%d events: %v", MaxEvents, err)
	}
	tooMany.Append(23, EvNoAction, d, nil)
	if _, err := Parse(tooMany.Bytes()); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("%d events: %v", MaxEvents+1, err)
	}
}

func TestNoActionMidLogIgnored(t *testing.T) {
	b := NewBuilder()
	b.Measure(0, EvPostCode, []byte("a"))
	// A nonzero digest on EV_NO_ACTION must still not extend.
	b.Append(0, EvNoAction, bytes.Repeat([]byte{0xaa}, 32), []byte("vendor"))
	b.Measure(0, EvPostCode, []byte("b"))
	events, err := ParseAndReplay(b.Bytes(), b.PCRs(0))
	if err != nil || len(events) != 2 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
}

func FuzzParseAndReplay(f *testing.F) {
	b := SimulatedBoot("v1")
	f.Add(b.Bytes())
	f.Add(NewBuilder().Bytes())
	f.Add(rawLog([][2]uint16{{algSHA1, 20}, {algSHA256, 32}}))
	pcrs := b.PCRs(bootPCRs...)
	f.Fuzz(func(t *testing.T, raw []byte) {
		l, err := Parse(raw)
		if err != nil {
			return
		}
		for _, ev := range l.Events {
			if ev.PCR > maxPCR || len(ev.Digest) != sha256.Size || ev.Type == EvNoAction {
				t.Fatalf("parsed invalid event %+v", ev)
			}
		}
		_, _ = l.Replay(pcrs)
	})
}
