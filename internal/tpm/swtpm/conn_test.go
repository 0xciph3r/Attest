package swtpm

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// pipeConn returns a Conn whose TPM side is served by fn.
func pipeConn(t *testing.T, fn func(tpm net.Conn)) *Conn {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	go func() {
		defer func() { _ = server.Close() }()
		fn(server)
	}()
	return &Conn{conn: client}
}

func rsp(tag uint16, size uint32, body []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, tag)
	out = binary.BigEndian.AppendUint32(out, size)
	out = append(out, 0, 0, 0, 0)
	return append(out, body...)
}

var cmd = rsp(0x8001, 12, []byte{0, 0})

// readCmd consumes one command from the client.
func readCmd(c net.Conn) bool {
	b := make([]byte, len(cmd))
	_, err := io.ReadFull(c, b)
	return err == nil
}

func TestSendRoundTrip(t *testing.T) {
	for _, tag := range []uint16{0x8001, 0x8002} {
		want := rsp(tag, 13, []byte{1, 2, 3})
		c := pipeConn(t, func(s net.Conn) {
			for readCmd(s) {
				_, _ = s.Write(want)
			}
		})
		for range 3 {
			got, err := c.Send(cmd)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("tag %#x: got %x, %v", tag, got, err)
			}
		}
	}
}

func TestSendRejectsBadResponses(t *testing.T) {
	for name, reply := range map[string][]byte{
		"size below header": rsp(0x8001, 9, nil),
		"size zero":         rsp(0x8001, 0, nil),
		"size too large":    rsp(0x8001, maxResponse+1, nil),
		"size max":          rsp(0x8001, 0xffffffff, nil),
		"tpm 1.2 tag":       rsp(0x00c4, 10, nil),
		"zero tag":          rsp(0x0000, 10, nil),
		"command tag":       rsp(0x8003, 10, nil),
		"short header":      {0x80, 0x01, 0, 0},
		"short body":        rsp(0x8001, 20, []byte{1, 2}),
	} {
		t.Run(name, func(t *testing.T) {
			c := pipeConn(t, func(s net.Conn) {
				if readCmd(s) {
					_, _ = s.Write(reply)
				}
			})
			if _, err := c.Send(cmd); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// After a framing error the stream position is unknown, so the leftover
// bytes must not be returned as the next command's response.
func TestSendFailsClosedAfterDesync(t *testing.T) {
	good := rsp(0x8001, 10, nil)
	c := pipeConn(t, func(s net.Conn) {
		if !readCmd(s) {
			return
		}
		// A bad tag followed by a well-formed response in the same stream.
		_, _ = s.Write(append(rsp(0x00c4, 10, nil), good...))
		for readCmd(s) {
			_, _ = s.Write(good)
		}
	})
	if _, err := c.Send(cmd); err == nil {
		t.Fatal("bad tag accepted")
	}
	if got, err := c.Send(cmd); err == nil {
		t.Fatalf("send after desync returned %x", got)
	}
}

func TestSendTimesOut(t *testing.T) {
	c := pipeConn(t, func(s net.Conn) {
		readCmd(s)
		time.Sleep(time.Second)
	})
	c.timeout = 50 * time.Millisecond
	start := time.Now()
	if _, err := c.Send(cmd); err == nil {
		t.Fatal("silent TPM accepted")
	}
	if time.Since(start) > 900*time.Millisecond {
		t.Fatal("deadline not applied")
	}
}

func TestResetWithoutControlChannel(t *testing.T) {
	if err := (&Conn{}).Reset(); err == nil {
		t.Fatal("reset without control address succeeded")
	}
}
