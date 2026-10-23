// Package swtpm is a development-only transport for the swtpm software TPM.
//
// It speaks raw TPM 2.0 command framing on swtpm's TCP data channel and the
// swtpm control protocol on the control channel, which allows tests to
// simulate a platform reset (PCRs return to zero). It must never be used as
// evidence of a hardware root of trust.
package swtpm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const (
	headerSize = 10
	// maxResponse bounds the response size accepted from the TPM.
	maxResponse = 1 << 16
	// cmdInit is the swtpm control-channel CMD_INIT command.
	cmdInit = 2
	timeout = 30 * time.Second
)

// Conn is a transport.TPMCloser connected to swtpm. It is safe for
// concurrent use; commands are serialized.
type Conn struct {
	mu       sync.Mutex
	conn     net.Conn
	ctrlAddr string
}

var _ transport.TPMCloser = (*Conn)(nil)

// Dial connects to the swtpm data channel at addr. ctrlAddr is the control
// channel used by Reset.
func Dial(addr, ctrlAddr string) (*Conn, error) {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("swtpm: dial %s: %w", addr, err)
	}
	return &Conn{conn: c, ctrlAddr: ctrlAddr}, nil
}

// Send transmits one TPM command and returns the complete response.
func (c *Conn) Send(cmd []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := c.conn.Write(cmd); err != nil {
		return nil, fmt.Errorf("swtpm: write: %w", err)
	}
	hdr := make([]byte, headerSize)
	if _, err := io.ReadFull(c.conn, hdr); err != nil {
		return nil, fmt.Errorf("swtpm: read header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[2:6])
	if n < headerSize || n > maxResponse {
		return nil, fmt.Errorf("swtpm: invalid response size %d", n)
	}
	rsp := make([]byte, n)
	copy(rsp, hdr)
	if _, err := io.ReadFull(c.conn, rsp[headerSize:]); err != nil {
		return nil, fmt.Errorf("swtpm: read body: %w", err)
	}
	return rsp, nil
}

// Close closes the data channel.
func (c *Conn) Close() error { return c.conn.Close() }

// Reset re-initializes the TPM through the control channel and issues
// TPM2_Startup(CLEAR), which is equivalent to a platform reboot: PCRs are
// reset and transient objects and sessions are flushed.
func (c *Conn) Reset() error {
	if c.ctrlAddr == "" {
		return errors.New("swtpm: no control address configured")
	}
	ctrl, err := net.DialTimeout("tcp", c.ctrlAddr, timeout)
	if err != nil {
		return fmt.Errorf("swtpm: dial control %s: %w", c.ctrlAddr, err)
	}
	defer func() { _ = ctrl.Close() }()
	if err := ctrl.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	var req [8]byte
	binary.BigEndian.PutUint32(req[0:4], cmdInit)
	if _, err := ctrl.Write(req[:]); err != nil {
		return fmt.Errorf("swtpm: CMD_INIT: %w", err)
	}
	var res [4]byte
	if _, err := io.ReadFull(ctrl, res[:]); err != nil {
		return fmt.Errorf("swtpm: CMD_INIT response: %w", err)
	}
	if code := binary.BigEndian.Uint32(res[:]); code != 0 {
		return fmt.Errorf("swtpm: CMD_INIT failed with code %#x", code)
	}
	if _, err := (tpm2.Startup{StartupType: tpm2.TPMSUClear}).Execute(c); err != nil {
		return fmt.Errorf("swtpm: startup: %w", err)
	}
	return nil
}
