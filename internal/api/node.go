package api

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/timestamppb"

	attestv1 "github.com/0xciph3r/attest/api/gen/attest/v1"
	"github.com/0xciph3r/attest/internal/enrollment"
	"github.com/0xciph3r/attest/internal/identity"
	"github.com/0xciph3r/attest/internal/policy"
	"github.com/0xciph3r/attest/internal/verifier"
)

// MaxCSRSize bounds workload certificate requests.
const MaxCSRSize = 4096

// NodeServer implements NodeService.
type NodeServer struct {
	attestv1.UnimplementedNodeServiceServer
	enroll   *enrollment.Service
	verifier *verifier.Service
	identity *identity.Service
	log      *slog.Logger
}

// NodeConfig configures a NodeServer.
type NodeConfig struct {
	Enrollment *enrollment.Service
	Verifier   *verifier.Service
	Identity   *identity.Service
	Log        *slog.Logger
}

// NewNodeServer returns a NodeService implementation.
func NewNodeServer(cfg NodeConfig) (*NodeServer, error) {
	if cfg.Enrollment == nil || cfg.Verifier == nil || cfg.Identity == nil {
		return nil, errors.New("api: node server needs enrollment, verifier and identity services")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &NodeServer{enroll: cfg.Enrollment, verifier: cfg.Verifier, identity: cfg.Identity, log: cfg.Log}, nil
}

func (s *NodeServer) status(ctx context.Context, method string, err error) error {
	return toStatus(ctx, s.log, "NodeService/"+method, err)
}

// BeginEnrollment implements NodeService.
func (s *NodeServer) BeginEnrollment(ctx context.Context, req *attestv1.BeginEnrollmentRequest) (*attestv1.BeginEnrollmentResponse, error) {
	ch, err := s.enroll.Begin(ctx, req.GetNodeId(), req.GetAkPublic())
	if err != nil {
		return nil, s.status(ctx, "BeginEnrollment", err)
	}
	return &attestv1.BeginEnrollmentResponse{ChallengeId: ch.ID, CredentialBlob: ch.CredentialBlob,
		EncryptedSecret: ch.EncryptedSecret, ExpiresAt: timestamppb.New(ch.ExpiresAt)}, nil
}

// CompleteEnrollment implements NodeService.
func (s *NodeServer) CompleteEnrollment(ctx context.Context, req *attestv1.CompleteEnrollmentRequest) (*attestv1.CompleteEnrollmentResponse, error) {
	if err := s.enroll.Complete(ctx, req.GetNodeId(), req.GetChallengeId(), req.GetAkPublic(), req.GetSecret()); err != nil {
		return nil, s.status(ctx, "CompleteEnrollment", err)
	}
	return &attestv1.CompleteEnrollmentResponse{}, nil
}

// GetChallenge implements NodeService.
func (s *NodeServer) GetChallenge(ctx context.Context, req *attestv1.GetChallengeRequest) (*attestv1.GetChallengeResponse, error) {
	c, err := s.verifier.Challenge(ctx, req.GetNodeId())
	if err != nil {
		return nil, s.status(ctx, "GetChallenge", err)
	}
	return &attestv1.GetChallengeResponse{ChallengeId: c.ID, Nonce: c.Nonce, Pcrs: c.PCRs,
		ExpiresAt: timestamppb.New(c.ExpiresAt)}, nil
}

// Attest implements NodeService. When the evidence binds a node key, the
// node identity is issued in the same call: the verdict is never exposed
// as a separately redeemable token.
func (s *NodeServer) Attest(ctx context.Context, req *attestv1.AttestRequest) (*attestv1.AttestResponse, error) {
	ev := req.GetEvidence()
	if ev == nil {
		return nil, s.status(ctx, "Attest", errInvalid)
	}
	in := &verifier.Evidence{Attest: ev.GetAttest(), Signature: ev.GetSignature(), PCRs: ev.GetPcrs(), EventLog: ev.GetEventLog()}
	if k := ev.GetNodeKey(); k != nil {
		in.NodeKey = &verifier.KeyEvidence{Public: k.GetPublic(), Certify: k.GetCertify(), CertifySignature: k.GetCertifySignature()}
	}
	v, err := s.verifier.Verify(ctx, req.GetNodeId(), req.GetChallengeId(), req.GetNonce(), in)
	if err != nil {
		return nil, s.status(ctx, "Attest", err)
	}
	resp := &attestv1.AttestResponse{AttestationId: v.AttestationID, PolicyVersion: v.PolicyVersion,
		Reference: v.Reference, VerifiedAt: timestamppb.New(v.VerifiedAt)}
	if v.NodeKey != nil {
		id, err := s.identity.IssueNode(ctx, v.NodeID, v.AttestationID, v.NodeKey.Key)
		if err != nil {
			return nil, s.status(ctx, "Attest", err)
		}
		resp.Identity = x509Identity(id)
	}
	return resp, nil
}

// IssueWorkloadIdentity implements NodeService. The node is authenticated
// by its TLS client certificate: the handshake proved possession of the
// certificate's key, and the identity service verifies the certificate
// against the current trust bundle and its issuance record.
func (s *NodeServer) IssueWorkloadIdentity(ctx context.Context, req *attestv1.IssueWorkloadIdentityRequest) (*attestv1.IssueWorkloadIdentityResponse, error) {
	parent := clientCert(ctx)
	if parent == nil {
		return nil, s.status(ctx, "IssueWorkloadIdentity", identity.ErrUntrusted)
	}
	if len(req.GetCsr()) == 0 || len(req.GetCsr()) > MaxCSRSize {
		return nil, s.status(ctx, "IssueWorkloadIdentity", errInvalid)
	}
	csr, err := x509.ParseCertificateRequest(req.GetCsr())
	if err != nil || csr.CheckSignature() != nil {
		return nil, s.status(ctx, "IssueWorkloadIdentity", errInvalid)
	}
	caller := policy.Caller{SystemdUnit: req.GetSystemdUnit(), UID: req.GetUid()}
	// The node the agent runs on is the one its certificate names; the
	// identity service verifies the certificate before trusting this.
	if len(parent.URIs) == 1 {
		if pid, err := identity.ParseID(parent.URIs[0].String()); err == nil && pid.Kind == identity.KindNode {
			caller.NodeID = pid.Name
		}
	}
	id, err := s.identity.IssueWorkload(ctx, parent, caller, csr.PublicKey)
	if err != nil {
		return nil, s.status(ctx, "IssueWorkloadIdentity", err)
	}
	return &attestv1.IssueWorkloadIdentityResponse{Identity: x509Identity(id)}, nil
}

// clientCert returns the TLS client certificate of the request, if any.
func clientCert(ctx context.Context) *x509.Certificate {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || !info.State.HandshakeComplete || len(info.State.PeerCertificates) == 0 {
		return nil
	}
	return info.State.PeerCertificates[0]
}

func x509Identity(id *identity.Identity) *attestv1.X509Identity {
	out := &attestv1.X509Identity{SpiffeId: id.ID.String(), Certificate: id.Cert.Raw, NotAfter: timestamppb.New(id.Cert.NotAfter)}
	for _, c := range id.Bundle {
		out.Bundle = append(out.Bundle, c.Raw)
	}
	return out
}
