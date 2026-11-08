package api

import (
	"context"
	"errors"
	"fmt"
	"net"

	"google.golang.org/grpc/credentials"
)

// PeerCred is the AuthInfo of a connection on the admin socket: the
// effective UID of the connecting process, as reported by the kernel at
// connect time.
type PeerCred struct {
	credentials.CommonAuthInfo
	UID uint32
}

// AuthType implements credentials.AuthInfo.
func (PeerCred) AuthType() string { return "peercred" }

// peerCredentials authenticates Unix socket clients by their kernel-reported
// UID. It provides no encryption; it is only for local sockets, whose
// traffic does not leave the host.
type peerCredentials struct{}

var errNotUnix = errors.New("api: admin connections must use a Unix socket")

func (peerCredentials) ServerHandshake(c net.Conn) (net.Conn, credentials.AuthInfo, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil, nil, errNotUnix
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, nil, err
	}
	var (
		uid  uint32
		uerr error
	)
	if err := raw.Control(func(fd uintptr) { uid, uerr = peerUID(fd) }); err != nil {
		return nil, nil, err
	}
	if uerr != nil {
		return nil, nil, fmt.Errorf("api: read peer credentials: %w", uerr)
	}
	return c, PeerCred{CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity}, UID: uid}, nil
}

func (peerCredentials) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("api: peer credentials are server-side only")
}

func (peerCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "peercred"}
}

func (p peerCredentials) Clone() credentials.TransportCredentials { return p }

func (peerCredentials) OverrideServerName(string) error { return nil }
