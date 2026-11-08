package api

import (
	"net"
	"time"

	"golang.org/x/net/netutil"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	attestv1 "github.com/0xciph3r/attest/api/gen/attest/v1"
	"github.com/0xciph3r/attest/internal/eventlog"
)

// MaxMessageSize bounds request messages: the largest permitted event log
// plus room for the rest of the evidence.
const MaxMessageSize = eventlog.MaxLogSize + 64<<10

// Resource limits for the node-facing listener, which accepts
// unauthenticated connections.
const (
	maxConcurrentStreams = 64
	connectionTimeout    = 10 * time.Second
	maxConnectionIdle    = 5 * time.Minute
)

// LimitNodeListener bounds l to MaxNodeConnections concurrent connections;
// further connections wait in the kernel backlog.
func LimitNodeListener(l net.Listener) net.Listener {
	return netutil.LimitListener(l, MaxNodeConnections)
}

// NewNodeGRPCServer returns a gRPC server for NodeService over TLS with
// attestd's server identity. Calls are admitted by rl before their request
// is read.
func NewNodeGRPCServer(ns *NodeServer, cert *ServerCert, rl *RateLimiter) *grpc.Server {
	s := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(ServerTLS(cert))),
		grpc.InTapHandle(rl.TapHandle),
		grpc.MaxRecvMsgSize(MaxMessageSize),
		grpc.MaxConcurrentStreams(maxConcurrentStreams),
		grpc.ConnectionTimeout(connectionTimeout),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 30 * time.Second}),
		grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionIdle: maxConnectionIdle}),
	)
	attestv1.RegisterNodeServiceServer(s, ns)
	return s
}
