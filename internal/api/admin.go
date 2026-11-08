package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	attestv1 "github.com/0xciph3r/attest/api/gen/attest/v1"
	"github.com/0xciph3r/attest/internal/audit"
	"github.com/0xciph3r/attest/internal/enrollment"
	"github.com/0xciph3r/attest/internal/identity"
	"github.com/0xciph3r/attest/internal/store"
	"github.com/0xciph3r/attest/internal/verifier"
)

// Role is an operator's permission set on the admin socket.
type Role string

// Roles. Viewers can read status and the node inventory. Admins can also
// change nodes and policy. Break-glass is reserved for emergency secret
// access and grants nothing else; it is deliberately not a superset of
// admin, so that routine administration never carries it.
const (
	RoleViewer     Role = "viewer"
	RoleAdmin      Role = "admin"
	RoleBreakGlass Role = "break-glass"
)

// ActionAdminDenied is audited when an admin RPC is refused.
const ActionAdminDenied = "admin.denied"

// MaxAdminMessageSize bounds admin requests; the largest is a policy
// document.
const MaxAdminMessageSize = 1 << 20

var operatorName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// Operator is a local user permitted on the admin socket.
type Operator struct {
	Name string
	Role Role
}

// methodRoles lists, for each AdminService method, the roles that may call
// it. Methods not listed are refused for every caller.
var methodRoles = map[string][]Role{
	attestv1.AdminService_GetStatus_FullMethodName:    {RoleViewer, RoleAdmin},
	attestv1.AdminService_ListNodes_FullMethodName:    {RoleViewer, RoleAdmin},
	attestv1.AdminService_RegisterNode_FullMethodName: {RoleAdmin},
	attestv1.AdminService_RevokeNode_FullMethodName:   {RoleAdmin},
	attestv1.AdminService_ApplyPolicy_FullMethodName:  {RoleAdmin},
}

// AdminServer implements AdminService for authenticated local operators.
type AdminServer struct {
	attestv1.UnimplementedAdminServiceServer
	st        *store.Store
	ca        *identity.CA
	enroll    *enrollment.Service
	verifier  *verifier.Service
	identity  *identity.Service
	operators map[uint32]Operator
	version   string
	now       func() time.Time
	log       *slog.Logger
}

// AdminConfig configures an AdminServer.
type AdminConfig struct {
	Store      *store.Store
	CA         *identity.CA
	Enrollment *enrollment.Service
	Verifier   *verifier.Service
	Identity   *identity.Service
	// Operators maps permitted UIDs to operators. Any other UID is refused.
	Operators map[uint32]Operator
	Version   string
	Now       func() time.Time
	Log       *slog.Logger
}

// NewAdminServer returns an AdminService implementation.
func NewAdminServer(cfg AdminConfig) (*AdminServer, error) {
	if cfg.Store == nil || cfg.CA == nil || cfg.Enrollment == nil || cfg.Verifier == nil || cfg.Identity == nil {
		return nil, errors.New("api: admin server needs a store, CA, and enrollment, verifier and identity services")
	}
	ops := make(map[uint32]Operator, len(cfg.Operators))
	names := make(map[string]bool, len(cfg.Operators))
	for uid, op := range cfg.Operators {
		if !operatorName.MatchString(op.Name) {
			return nil, fmt.Errorf("api: operator name %q must match %s", op.Name, operatorName)
		}
		if names[op.Name] {
			return nil, fmt.Errorf("api: operator name %q is used by more than one UID", op.Name)
		}
		switch op.Role {
		case RoleViewer, RoleAdmin, RoleBreakGlass:
		default:
			return nil, fmt.Errorf("api: operator %q has unknown role %q", op.Name, op.Role)
		}
		names[op.Name] = true
		ops[uid] = op
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &AdminServer{st: cfg.Store, ca: cfg.CA, enroll: cfg.Enrollment, verifier: cfg.Verifier,
		identity: cfg.Identity, operators: ops, version: cfg.Version, now: cfg.Now, log: cfg.Log}, nil
}

// NewAdminGRPCServer returns a gRPC server for AdminService that
// authenticates callers by peer UID. Serve it only on a Unix socket.
func NewAdminGRPCServer(as *AdminServer) *grpc.Server {
	s := grpc.NewServer(
		grpc.Creds(peerCredentials{}),
		grpc.MaxRecvMsgSize(MaxAdminMessageSize),
		grpc.UnaryInterceptor(as.authorize),
		grpc.StreamInterceptor(func(any, grpc.ServerStream, *grpc.StreamServerInfo, grpc.StreamHandler) error {
			return status.Error(codes.Unimplemented, "streaming is not supported")
		}),
	)
	attestv1.RegisterAdminServiceServer(s, as)
	return s
}

type actorKey struct{}

// actor returns the authenticated operator's audit actor.
func actor(ctx context.Context) string {
	a, _ := ctx.Value(actorKey{}).(string)
	return a
}

// authorize admits a call only from a configured operator whose role
// permits the method. Refusals are audited; if that fails, the call fails
// with INTERNAL rather than proceeding unrecorded.
func (s *AdminServer) authorize(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no peer credentials")
	}
	cred, ok := p.AuthInfo.(PeerCred)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no peer credentials")
	}
	op, known := s.operators[cred.UID]
	who := "uid:" + strconv.FormatUint(uint64(cred.UID), 10)
	if known {
		who = "operator:" + op.Name
	}
	var reason string
	switch {
	case !known:
		reason = "unknown_operator"
	case !permits(methodRoles[info.FullMethod], op.Role):
		reason = "role_not_permitted"
	}
	if reason != "" {
		meta, err := json.Marshal(map[string]any{"uid": cred.UID, "reason": reason})
		if err == nil {
			_, err = s.st.AppendAudit(ctx, audit.Record{Time: s.now(), Actor: who, Action: ActionAdminDenied,
				Object: "rpc" + info.FullMethod, Metadata: meta})
		}
		if err != nil {
			s.log.Error("audit admin denial", "method", info.FullMethod, "actor", who, "err", err)
			return nil, status.Error(codes.Internal, "internal error")
		}
		return nil, status.Error(codes.PermissionDenied, "denied: "+reason)
	}
	return h(context.WithValue(ctx, actorKey{}, who), req)
}

func permits(roles []Role, r Role) bool {
	for _, x := range roles {
		if x == r {
			return true
		}
	}
	return false
}

func (s *AdminServer) status(ctx context.Context, method string, err error) error {
	return toStatus(ctx, s.log, "AdminService/"+method, err)
}

// GetStatus implements AdminService.
func (s *AdminServer) GetStatus(ctx context.Context, _ *attestv1.GetStatusRequest) (*attestv1.GetStatusResponse, error) {
	head, err := s.st.AuditHead(ctx)
	if err != nil {
		return nil, s.status(ctx, "GetStatus", err)
	}
	return &attestv1.GetStatusResponse{Version: s.version, TrustDomain: s.ca.TrustDomain(),
		CaNotAfter: timestamppb.New(s.ca.Cert().NotAfter), AuditSequence: head.Sequence, AuditHeadHash: head.Hash[:]}, nil
}

// RegisterNode implements AdminService.
func (s *AdminServer) RegisterNode(ctx context.Context, req *attestv1.RegisterNodeRequest) (*attestv1.RegisterNodeResponse, error) {
	n, err := s.enroll.Register(ctx, actor(ctx), req.GetNodeId(), req.GetEkCertificate())
	if err != nil {
		return nil, s.status(ctx, "RegisterNode", err)
	}
	return &attestv1.RegisterNodeResponse{Node: toNode(n)}, nil
}

// RevokeNode implements AdminService.
func (s *AdminServer) RevokeNode(ctx context.Context, req *attestv1.RevokeNodeRequest) (*attestv1.RevokeNodeResponse, error) {
	if err := s.enroll.Revoke(ctx, actor(ctx), req.GetNodeId()); err != nil {
		return nil, s.status(ctx, "RevokeNode", err)
	}
	return &attestv1.RevokeNodeResponse{}, nil
}

// ListNodes implements AdminService.
func (s *AdminServer) ListNodes(ctx context.Context, _ *attestv1.ListNodesRequest) (*attestv1.ListNodesResponse, error) {
	nodes, err := s.st.Nodes(ctx)
	if err != nil {
		return nil, s.status(ctx, "ListNodes", err)
	}
	out := &attestv1.ListNodesResponse{Nodes: make([]*attestv1.Node, 0, len(nodes))}
	for _, n := range nodes {
		out.Nodes = append(out.Nodes, toNode(n))
	}
	return out, nil
}

// ApplyPolicy implements AdminService.
func (s *AdminServer) ApplyPolicy(ctx context.Context, req *attestv1.ApplyPolicyRequest) (*attestv1.ApplyPolicyResponse, error) {
	var (
		v   int64
		err error
	)
	switch req.GetKind() {
	case attestv1.PolicyKind_POLICY_KIND_MEASUREMENT:
		v, err = s.verifier.ApplyPolicy(ctx, actor(ctx), req.GetDocument())
	case attestv1.PolicyKind_POLICY_KIND_WORKLOAD:
		v, err = s.identity.ApplyWorkloadPolicy(ctx, actor(ctx), req.GetDocument())
	default:
		err = fmt.Errorf("%w: unknown policy kind %v", errInvalid, req.GetKind())
	}
	if err != nil {
		return nil, s.status(ctx, "ApplyPolicy", err)
	}
	return &attestv1.ApplyPolicyResponse{Version: v}, nil
}

func toNode(n *store.Node) *attestv1.Node {
	out := &attestv1.Node{Id: n.ID, EkType: n.EKType, EkDigest: n.EKDigest, EkDevelopment: n.EKDevelopment,
		RegisteredBy: n.RegisteredBy, RegisteredAt: ts(n.RegisteredAt), EnrolledAt: ts(n.EnrolledAt), RevokedAt: ts(n.RevokedAt)}
	switch n.State {
	case store.NodeRegistered:
		out.State = attestv1.NodeState_NODE_STATE_REGISTERED
	case store.NodeEnrolled:
		out.State = attestv1.NodeState_NODE_STATE_ENROLLED
	case store.NodeRevoked:
		out.State = attestv1.NodeState_NODE_STATE_REVOKED
	}
	return out
}

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}
