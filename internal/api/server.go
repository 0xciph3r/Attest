package api

import (
	"time"

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
)

// NewNodeGRPCServer returns a gRPC server for NodeService over TLS with
// attestd's server identity.
func NewNodeGRPCServer(ns *NodeServer, cert *ServerCert) *grpc.Server {
	s := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(ServerTLS(cert))),
		grpc.MaxRecvMsgSize(MaxMessageSize),
		grpc.MaxConcurrentStreams(maxConcurrentStreams),
		grpc.ConnectionTimeout(connectionTimeout),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 30 * time.Second}),
	)
	attestv1.RegisterNodeServiceServer(s, ns)
	return s
}
