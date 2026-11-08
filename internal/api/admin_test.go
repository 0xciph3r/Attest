package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	attestv1 "github.com/0xciph3r/attest/api/gen/attest/v1"
	"github.com/0xciph3r/attest/internal/audit"
	"github.com/0xciph3r/attest/internal/enrollment"
	"github.com/0xciph3r/attest/internal/tpm/swtpm/swtpmtest"
	"github.com/0xciph3r/attest/internal/verifier/verifiertest"
)

// admin serves AdminService on a Unix socket with the current process's
// UID mapped to op (or unmapped if op is nil), and returns a client.
func (e *env) admin(op *Operator) attestv1.AdminServiceClient {
	e.t.Helper()
	ops := map[uint32]Operator{uint32(os.Getuid()) + 1: {Name: "other", Role: RoleAdmin}}
	if op != nil {
		ops[uint32(os.Getuid())] = *op
	}
	as, err := NewAdminServer(AdminConfig{Store: e.st, CA: e.ca, Enrollment: e.enr, Verifier: e.ver, Identity: e.ident,
		Operators: ops, Version: "test", Now: e.clk.Now, Log: e.log})
	if err != nil {
		e.t.Fatal(err)
	}
	path := filepath.Join(shortDir(e.t), "admin.sock")
	l, err := ListenUnix(path, 0o600, -1)
	if err != nil {
		e.t.Fatal(err)
	}
	srv := NewAdminGRPCServer(as)
	go func() { _ = srv.Serve(l) }()
	e.t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("unix://"+path, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = conn.Close() })
	return attestv1.NewAdminServiceClient(conn)
}

func (e *env) ekCert() []byte {
	e.t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.ekCA.IssueEKCert(e.t, &k.PublicKey)
}

// auditTail returns the newest audit entry.
func (e *env) auditTail() audit.Entry {
	e.t.Helper()
	var last audit.Entry
	for en, err := range e.st.AuditEntries(bg) {
		if err != nil {
			e.t.Fatal(err)
		}
		last = en
	}
	return last
}

var alice = &Operator{Name: "alice", Role: RoleAdmin}

func TestAdminLifecycle(t *testing.T) {
	e := newEnv(t)
	c := e.admin(alice)

	st, err := c.GetStatus(bg, &attestv1.GetStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	head := e.auditTail()
	if st.GetVersion() != "test" || st.GetTrustDomain() != "attest.local" || st.GetAuditSequence() != head.Sequence ||
		string(st.GetAuditHeadHash()) != string(head.Hash[:]) || !st.GetCaNotAfter().AsTime().Equal(e.ca.Cert().NotAfter) {
		t.Fatalf("status %v", st)
	}

	reg, err := c.RegisterNode(bg, &attestv1.RegisterNodeRequest{NodeId: "n7", EkCertificate: e.ekCert()})
	if err != nil {
		t.Fatal(err)
	}
	if n := reg.GetNode(); n.GetState() != attestv1.NodeState_NODE_STATE_REGISTERED || n.GetRegisteredBy() != "operator:alice" ||
		n.GetEnrolledAt() != nil || n.GetEkType() == "" {
		t.Fatalf("registered %v", n)
	}
	if a := e.auditTail(); a.Actor != "operator:alice" || a.Action != enrollment.ActionRegister {
		t.Fatalf("audit %s %s", a.Actor, a.Action)
	}

	if _, err := c.RevokeNode(bg, &attestv1.RevokeNodeRequest{NodeId: "n7"}); err != nil {
		t.Fatal(err)
	}
	list, err := c.ListNodes(bg, &attestv1.ListNodesRequest{})
	if err != nil || len(list.GetNodes()) != 1 || list.GetNodes()[0].GetState() != attestv1.NodeState_NODE_STATE_REVOKED ||
		list.GetNodes()[0].GetRevokedAt() == nil {
		t.Fatalf("list %v, %v", list, err)
	}

	for kind, doc := range map[attestv1.PolicyKind][]byte{
		attestv1.PolicyKind_POLICY_KIND_MEASUREMENT: verifiertest.PolicyJSON(t, true, e.boot),
		attestv1.PolicyKind_POLICY_KIND_WORKLOAD:    []byte(workloadPolicy),
	} {
		r, err := c.ApplyPolicy(bg, &attestv1.ApplyPolicyRequest{Kind: kind, Document: doc})
		if err != nil || r.GetVersion() < 2 {
			t.Fatalf("%v: %v, %v", kind, r, err)
		}
		if a := e.auditTail(); a.Actor != "operator:alice" {
			t.Fatalf("%v audited as %s", kind, a.Actor)
		}
	}
}

func TestAdminRejects(t *testing.T) {
	e := newEnv(t)
	c := e.admin(alice)
	before := e.auditTail().Sequence

	_, err := c.RegisterNode(bg, &attestv1.RegisterNodeRequest{NodeId: "n7", EkCertificate: e.ekCert()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.RegisterNode(bg, &attestv1.RegisterNodeRequest{NodeId: "n7", EkCertificate: e.ekCert()})
	expectCode(t, "duplicate node", err, codes.AlreadyExists, "")
	_, err = c.RegisterNode(bg, &attestv1.RegisterNodeRequest{NodeId: "../n", EkCertificate: e.ekCert()})
	expectCode(t, "malformed node ID", err, codes.InvalidArgument, "")
	_, err = c.RegisterNode(bg, &attestv1.RegisterNodeRequest{NodeId: "n8", EkCertificate: []byte("junk")})
	expectCode(t, "junk EK certificate", err, codes.PermissionDenied, "ek_cert_invalid")
	foreign := swtpmtest.NewCA(t, "Untrusted EK CA")
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.RegisterNode(bg, &attestv1.RegisterNodeRequest{NodeId: "n8", EkCertificate: foreign.IssueEKCert(t, &k.PublicKey)})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("untrusted EK root: %v", err)
	}

	_, err = c.RevokeNode(bg, &attestv1.RevokeNodeRequest{NodeId: "ghost"})
	expectCode(t, "revoke unknown", err, codes.NotFound, "")
	if _, err := c.RevokeNode(bg, &attestv1.RevokeNodeRequest{NodeId: "n7"}); err != nil {
		t.Fatal(err)
	}
	_, err = c.RevokeNode(bg, &attestv1.RevokeNodeRequest{NodeId: "n7"})
	expectCode(t, "revoke twice", err, codes.NotFound, "")

	for name, req := range map[string]*attestv1.ApplyPolicyRequest{
		"unspecified kind":        {Document: []byte(workloadPolicy)},
		"unknown kind":            {Kind: 99, Document: []byte(workloadPolicy)},
		"invalid workload":        {Kind: attestv1.PolicyKind_POLICY_KIND_WORKLOAD, Document: []byte(`{"schema":"x"}`)},
		"workload as measurement": {Kind: attestv1.PolicyKind_POLICY_KIND_MEASUREMENT, Document: []byte(workloadPolicy)},
		"empty document":          {Kind: attestv1.PolicyKind_POLICY_KIND_MEASUREMENT},
	} {
		_, err := c.ApplyPolicy(bg, req)
		expectCode(t, name, err, codes.InvalidArgument, "")
	}
	_, err = c.ApplyPolicy(bg, &attestv1.ApplyPolicyRequest{Kind: attestv1.PolicyKind_POLICY_KIND_WORKLOAD,
		Document: make([]byte, MaxAdminMessageSize)})
	expectCode(t, "oversized policy", err, codes.ResourceExhausted, "")

	// Only the successful register and revoke changed the ledger.
	if got := e.auditTail().Sequence; got != before+2 {
		t.Fatalf("audit advanced %d entries", got-before)
	}
}

func TestAdminAuthorization(t *testing.T) {
	calls := map[string]func(attestv1.AdminServiceClient) error{
		"GetStatus": func(c attestv1.AdminServiceClient) error {
			_, err := c.GetStatus(bg, &attestv1.GetStatusRequest{})
			return err
		},
		"ListNodes": func(c attestv1.AdminServiceClient) error {
			_, err := c.ListNodes(bg, &attestv1.ListNodesRequest{})
			return err
		},
		"RegisterNode": func(c attestv1.AdminServiceClient) error {
			_, err := c.RegisterNode(bg, &attestv1.RegisterNodeRequest{NodeId: "n7", EkCertificate: []byte("x")})
			return err
		},
		"RevokeNode": func(c attestv1.AdminServiceClient) error {
			_, err := c.RevokeNode(bg, &attestv1.RevokeNodeRequest{NodeId: "n7"})
			return err
		},
		"ApplyPolicy": func(c attestv1.AdminServiceClient) error {
			_, err := c.ApplyPolicy(bg, &attestv1.ApplyPolicyRequest{})
			return err
		},
	}
	reads := map[string]bool{"GetStatus": true, "ListNodes": true}
	for _, tc := range []struct {
		name   string
		op     *Operator
		actor  string
		reason string
		allow  func(method string) bool
	}{
		{"unknown UID", nil, "uid:", "unknown_operator", func(string) bool { return false }},
		{"viewer", &Operator{Name: "bob", Role: RoleViewer}, "operator:bob", "role_not_permitted", func(m string) bool { return reads[m] }},
		{"break-glass", &Operator{Name: "eve", Role: RoleBreakGlass}, "operator:eve", "role_not_permitted", func(string) bool { return false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			c := e.admin(tc.op)
			for method, call := range calls {
				before := e.auditTail().Sequence
				err := call(c)
				if tc.allow(method) {
					if err != nil {
						t.Errorf("%s refused: %v", method, err)
					}
					continue
				}
				if status.Code(err) != codes.PermissionDenied || !strings.HasSuffix(status.Convert(err).Message(), tc.reason) {
					t.Errorf("%s: %v", method, err)
					continue
				}
				a := e.auditTail()
				var meta struct {
					Reason string `json:"reason"`
				}
				_ = json.Unmarshal(a.Metadata, &meta)
				if a.Sequence != before+1 || a.Action != ActionAdminDenied || !strings.HasPrefix(a.Actor, tc.actor) ||
					a.Object != "rpc/attest.v1.AdminService/"+method || meta.Reason != tc.reason {
					t.Errorf("%s denial audited as +%d %s %s %s %s", method, a.Sequence-before, a.Actor, a.Action, a.Object, meta.Reason)
				}
			}
		})
	}
}

func TestAdminDenialFailsClosedWithoutAudit(t *testing.T) {
	e := newEnv(t)
	c := e.admin(&Operator{Name: "bob", Role: RoleViewer})
	if err := e.st.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := c.RevokeNode(bg, &attestv1.RevokeNodeRequest{NodeId: "n1"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(e.logs.String(), "audit admin denial") {
		t.Fatal("audit failure not logged")
	}
}

func TestAdminRequiresUnixSocket(t *testing.T) {
	e := newEnv(t)
	as, err := NewAdminServer(AdminConfig{Store: e.st, CA: e.ca, Enrollment: e.enr, Verifier: e.ver, Identity: e.ident,
		Operators: map[uint32]Operator{uint32(os.Getuid()): *alice}})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewAdminGRPCServer(as)
	go func() { _ = srv.Serve(l) }()
	defer srv.Stop()
	conn, err := grpc.NewClient(l.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(bg, 2*time.Second)
	defer cancel()
	if _, err := attestv1.NewAdminServiceClient(conn).GetStatus(ctx, &attestv1.GetStatusRequest{}); err == nil {
		t.Fatal("admin call over TCP succeeded")
	}
}

func TestNewAdminServerRejectsConfig(t *testing.T) {
	e := newEnv(t)
	base := func(ops map[uint32]Operator) AdminConfig {
		return AdminConfig{Store: e.st, CA: e.ca, Enrollment: e.enr, Verifier: e.ver, Identity: e.ident, Operators: ops}
	}
	for name, cfg := range map[string]AdminConfig{
		"no services":    {},
		"bad name":       base(map[uint32]Operator{1: {Name: "Alice Smith", Role: RoleAdmin}}),
		"empty name":     base(map[uint32]Operator{1: {Role: RoleAdmin}}),
		"unknown role":   base(map[uint32]Operator{1: {Name: "alice", Role: "root"}}),
		"empty role":     base(map[uint32]Operator{1: {Name: "alice"}}),
		"duplicate name": base(map[uint32]Operator{1: {Name: "alice", Role: RoleAdmin}, 2: {Name: "alice", Role: RoleViewer}}),
	} {
		if _, err := NewAdminServer(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
