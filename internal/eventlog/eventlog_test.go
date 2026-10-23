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
	spec := new(bytes.Buffer)
	spec.Write(specIDSignature)
	spec.Write(make([]byte, 4))
	spec.Write([]byte{0, 2, 0, 2})
	_ = binary.Write(spec, binary.LittleEndian, uint32(len(algs)))
	for _, a := range algs {
		_ = binary.Write(spec, binary.LittleEndian, a)
	}
	spec.WriteByte(0)
	out := new(bytes.Buffer)
	_ = binary.Write(out, binary.LittleEndian, [2]uint32{0, EvNoAction})
	out.Write(make([]byte, 20))
	_ = binary.Write(out, binary.LittleEndian, uint32(spec.Len()))
	out.Write(spec.Bytes())
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
