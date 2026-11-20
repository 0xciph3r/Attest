//go:build !linux

package agent

import "net"

// peerProcess is only implemented on Linux, the agent's only platform.
func peerProcess(*net.UnixConn) (*Caller, error) { return nil, ErrUnsupported }
