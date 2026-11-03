package tpm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// fakeTPM answers commands from a script so that tests can model a buggy or
// malicious TPM. Each handler receives the raw command and returns response
// parameters; the fake frames them.
type fakeTPM struct {
	handlers map[tpm2.TPMCC]func(cmd []byte) (params []byte, sessions bool)
	calls    map[tpm2.TPMCC]int
}

func newFake() *fakeTPM {
	return &fakeTPM{
		handlers: map[tpm2.TPMCC]func([]byte) ([]byte, bool){},
		calls:    map[tpm2.TPMCC]int{},
	}
}

const maxFakeCalls = 1000

var errRunaway = errors.New("fake TPM: runaway command loop")

func (f *fakeTPM) Send(cmd []byte) ([]byte, error) {
	cc := tpm2.TPMCC(binary.BigEndian.Uint32(cmd[6:10]))
	f.calls[cc]++
	if f.calls[cc] > maxFakeCalls {
		return nil, errRunaway
	}
	h, ok := f.handlers[cc]
	if !ok {
		return frame(tpm2.TPMSTNoSessions, uint32(tpm2.TPMRCCommandCode), nil), nil
	}
	params, sess := h(cmd)
	if !sess {
		return frame(tpm2.TPMSTNoSessions, 0, params), nil
	}
	body := binary.BigEndian.AppendUint32(nil, uint32(len(params)))
	body = append(body, params...)
	// Password session response: empty nonce, continueSession, empty HMAC.
	body = append(body, 0, 0, 1, 0, 0)
	return frame(tpm2.TPMSTSessions, 0, body), nil
}

func frame(tag tpm2.TPMISTCommandTag, rc uint32, body []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, uint16(tag))
	out = binary.BigEndian.AppendUint32(out, uint32(10+len(body)))
	out = binary.BigEndian.AppendUint32(out, rc)
	return append(out, body...)
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// nvPublic serves NV_ReadPublic for idx with the given data size.
func (f *fakeTPM) nvPublic(idx tpm2.TPMHandle, size uint16) {
	f.handlers[tpm2.TPMCCNVReadPublic] = func([]byte) ([]byte, bool) {
		pub := tpm2.New2B(tpm2.TPMSNVPublic{NVIndex: idx, NameAlg: tpm2.TPMAlgSHA256, DataSize: size})
		return cat(tpm2.Marshal(pub), tpm2.Marshal(tpm2.TPM2BName{Buffer: []byte{0, 0x0b, 1, 2}})), false
	}
}

// nvRead serves NV_Read from data, letting tweak alter each answer.
func (f *fakeTPM) nvRead(data []byte, tweak func(off, size int, out []byte) []byte) {
	f.handlers[tpm2.TPMCCNVRead] = func(cmd []byte) ([]byte, bool) {
		// header(10) authHandle(4) nvIndex(4) authSize(4) auth area, size(2) offset(2)
		authSize := int(binary.BigEndian.Uint32(cmd[18:22]))
		p := cmd[22+authSize:]
		size, off := int(binary.BigEndian.Uint16(p)), int(binary.BigEndian.Uint16(p[2:]))
		out := data[min(off, len(data)):min(off+size, len(data))]
		if tweak != nil {
			out = tweak(off, size, out)
		}
		return tpm2.Marshal(tpm2.TPM2BMaxNVBuffer{Buffer: out}), true
	}
}

func TestReadEKCertFake(t *testing.T) {
	cert := bytes.Repeat([]byte("0123456789abcdef"), 100) // 1600 bytes, 4 chunks
	f := newFake()
	f.nvPublic(EKCertNVECCP256, uint16(len(cert)))
	f.nvRead(cert, nil)
	got, err := ReadEKCert(f, EKECCP256)
	if err != nil || !bytes.Equal(got, cert) {
		t.Fatalf("err=%v equal=%v", err, bytes.Equal(got, cert))
	}
}

func TestReadEKCertRejectsMisbehavingTPM(t *testing.T) {
	cert := bytes.Repeat([]byte{0x30}, 1600)
	for name, tc := range map[string]struct {
		size  uint16
		tweak func(off, size int, out []byte) []byte
	}{
		"empty index":     {0, nil},
		"oversized index": {maxEKCertSize + 1, nil},
		"max index":       {0xffff, nil},
		"no progress":     {1600, func(int, int, []byte) []byte { return nil }},
		"short chunk":     {1600, func(_, _ int, out []byte) []byte { return out[:len(out)-1] }},
		"long chunk":      {1600, func(_, _ int, out []byte) []byte { return append(out, 0xff) }},
		"index shorter than data size": {1600, func(off, _ int, out []byte) []byte {
			if off >= 1024 {
				return nil
			}
			return out
		}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake()
			f.nvPublic(EKCertNVECCP256, tc.size)
			f.nvRead(cert, tc.tweak)
			_, err := ReadEKCert(f, EKECCP256)
			if err == nil || errors.Is(err, errRunaway) {
				t.Fatalf("got %v", err)
			}
		})
	}
	if _, err := ReadEKCert(newFake(), EKType("rsa4096")); !errors.Is(err, ErrUnsupportedEK) {
		t.Fatalf("unsupported EK type: %v", err)
	}
	if _, err := ReadEKCert(newFake(), EKECCP256); err == nil {
		t.Fatal("missing NV index accepted")
	}
}
