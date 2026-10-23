package eventlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

// Common event types used when synthesizing logs.
const (
	EvPostCode            uint32 = 0x00000001
	EvSeparator           uint32 = 0x00000004
	EvEFIAction           uint32 = 0x80000007
	EvEFIVariableDriverCf uint32 = 0x80000001
)

// Builder synthesizes a SHA-256 crypto-agile event log and tracks the PCR
// values a TPM would hold after the same measurements. It exists for tests
// and for driving a development software TPM through a simulated boot; it
// does not produce evidence of a real boot.
type Builder struct {
	buf    bytes.Buffer
	events []Event
	pcrs   map[uint32][]byte
}

// NewBuilder returns a builder whose log contains only the Spec ID header.
func NewBuilder() *Builder {
	b := &Builder{pcrs: make(map[uint32][]byte)}
	spec := new(bytes.Buffer)
	spec.Write(specIDSignature)
	_ = binary.Write(spec, binary.LittleEndian, uint32(0)) // platformClass: client
	spec.Write([]byte{0, 2, 0, 2})                         // minor, major, errata, uintnSize
	_ = binary.Write(spec, binary.LittleEndian, uint32(1))
	_ = binary.Write(spec, binary.LittleEndian, algSHA256)
	_ = binary.Write(spec, binary.LittleEndian, uint16(sha256.Size))
	spec.WriteByte(0) // vendorInfoSize

	_ = binary.Write(&b.buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(&b.buf, binary.LittleEndian, EvNoAction)
	b.buf.Write(make([]byte, 20))
	_ = binary.Write(&b.buf, binary.LittleEndian, uint32(spec.Len())) //nolint:gosec // small
	b.buf.Write(spec.Bytes())
	return b
}

// Measure appends an event whose digest is SHA-256(data), extends the
// tracked PCR and returns the digest.
func (b *Builder) Measure(pcr, typ uint32, data []byte) []byte {
	d := sha256.Sum256(data)
	b.Append(pcr, typ, d[:], data)
	return d[:]
}

// Append appends an event with an explicit digest. Data does not have to
// hash to digest, as with many real firmware events.
func (b *Builder) Append(pcr, typ uint32, digest, data []byte) {
	_ = binary.Write(&b.buf, binary.LittleEndian, pcr)
	_ = binary.Write(&b.buf, binary.LittleEndian, typ)
	_ = binary.Write(&b.buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(&b.buf, binary.LittleEndian, algSHA256)
	b.buf.Write(digest)
	_ = binary.Write(&b.buf, binary.LittleEndian, uint32(len(data))) //nolint:gosec // test sizes
	b.buf.Write(data)
	if typ == EvNoAction {
		return
	}
	b.events = append(b.events, Event{Seq: len(b.events) + 1, PCR: pcr, Type: typ, Digest: digest, Data: data})
	cur, ok := b.pcrs[pcr]
	if !ok {
		cur = make([]byte, sha256.Size)
	}
	h := sha256.New()
	h.Write(cur)
	h.Write(digest)
	b.pcrs[pcr] = h.Sum(nil)
}

// Bytes returns the encoded log.
func (b *Builder) Bytes() []byte { return bytes.Clone(b.buf.Bytes()) }

// Events returns the extending (non EV_NO_ACTION) events in order.
func (b *Builder) Events() []Event { return b.events }

// PCRs returns the expected SHA-256 values of the requested PCRs.
func (b *Builder) PCRs(pcrs ...uint32) map[uint32][]byte {
	out := make(map[uint32][]byte, len(pcrs))
	for _, p := range pcrs {
		if v, ok := b.pcrs[p]; ok {
			out[p] = bytes.Clone(v)
		} else {
			out[p] = make([]byte, sha256.Size)
		}
	}
	return out
}

// SimulatedBoot returns a builder with a small, plausible firmware
// measurement sequence over PCRs 0-7. The label makes distinct "firmware
// builds" produce distinct measurements.
func SimulatedBoot(label string) *Builder {
	b := NewBuilder()
	b.Measure(0, EvPostCode, []byte("attest simulated firmware "+label))
	b.Measure(1, EvEFIVariableDriverCf, []byte("attest simulated platform config"))
	b.Measure(2, EvPostCode, []byte("attest simulated option ROMs"))
	b.Measure(4, EvEFIAction, []byte("Calling EFI Application from Boot Option"))
	b.Measure(7, EvEFIVariableDriverCf, []byte("attest simulated SecureBoot=1"))
	for p := uint32(0); p <= 7; p++ {
		b.Measure(p, EvSeparator, []byte{0, 0, 0, 0})
	}
	b.Measure(4, EvPostCode, []byte("attest simulated bootloader "+label))
	b.Measure(5, EvEFIAction, []byte("Exit Boot Services Invocation"))
	return b
}
