package store

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/0xciph3r/attest/internal/audit"
)

var ctx = context.Background()

func digest(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func update(t *testing.T, s *Store, fn func(*Tx) error) error {
	t.Helper()
	return s.Update(ctx, fn)
}

func mustUpdate(t *testing.T, s *Store, fn func(*Tx) error) {
	t.Helper()
	if err := s.Update(ctx, fn); err != nil {
		t.Fatal(err)
	}
}

// rejectedByConstraint runs raw SQL, bypassing the Go API, and requires the
// schema itself to refuse it (not, say, a typo in the statement).
func rejectedByConstraint(t *testing.T, s *Store, name, stmt string) {
	t.Helper()
	_, err := s.db.ExecContext(ctx, stmt)
	if err == nil {
		t.Errorf("%s: accepted", name)
	} else if !strings.Contains(err.Error(), "constraint failed") {
		t.Errorf("%s: unexpected error %v", name, err)
	}
}

func testNode(id string, ek byte) *Node {
	return &Node{
		ID: id, EKType: "eccp256", EKCert: []byte{1}, EKPublic: []byte{ek}, EKDigest: digest(ek),
		RegisteredBy: "operator:alice", RegisteredAt: time.Now(),
	}
}

func TestUpdateRollsBackAuditOnError(t *testing.T) {
	s, _ := openTemp(t)
	boom := errors.New("boom")
	err := update(t, s, func(tx *Tx) error {
		if _, err := tx.AppendAudit(audit.Record{Time: time.Now(), Actor: "a", Action: "b", Object: "c"}); err != nil {
			return err
		}
		if err := tx.InsertNode(testNode("n1", 1)); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if h, _ := s.AuditHead(ctx); h.Sequence != 0 {
		t.Fatal("audit entry survived rollback")
	}
	if _, err := s.Node(ctx, "n1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("node survived rollback")
	}
}

func TestNodeLifecycle(t *testing.T) {
	s, _ := openTemp(t)
	mustUpdate(t, s, func(tx *Tx) error { return tx.InsertNode(testNode("n1", 1)) })

	if err := update(t, s, func(tx *Tx) error { return tx.InsertNode(testNode("n2", 1)) }); !errors.Is(err, ErrConflict) {
		t.Fatalf("second live node with the same EK: %v", err)
	}
	if err := update(t, s, func(tx *Tx) error { return tx.InsertNode(testNode("n1", 2)) }); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate node ID: %v", err)
	}

	mustUpdate(t, s, func(tx *Tx) error { return tx.EnrollNode("n1", []byte{9}, digest(9), time.Now()) })
	if err := update(t, s, func(tx *Tx) error { return tx.EnrollNode("n1", []byte{8}, digest(8), time.Now()) }); !errors.Is(err, ErrConflict) {
		t.Fatalf("re-enrollment: %v", err)
	}
	n, err := s.Node(ctx, "n1")
	if err != nil || n.State != NodeEnrolled || !bytes.Equal(n.AKName, digest(9)) || n.EnrolledAt.IsZero() {
		t.Fatalf("got %+v, %v", n, err)
	}

	mustUpdate(t, s, func(tx *Tx) error { return tx.RevokeNode("n1", time.Now()) })
	if err := update(t, s, func(tx *Tx) error { return tx.RevokeNode("n1", time.Now()) }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double revoke: %v", err)
	}
	// A revoked node releases its EK and AK.
	mustUpdate(t, s, func(tx *Tx) error { return tx.InsertNode(testNode("n1-reinstalled", 1)) })
	mustUpdate(t, s, func(tx *Tx) error { return tx.EnrollNode("n1-reinstalled", []byte{9}, digest(9), time.Now()) })

	mustUpdate(t, s, func(tx *Tx) error { return tx.InsertNode(testNode("n3", 3)) })
	if err := update(t, s, func(tx *Tx) error { return tx.EnrollNode("n3", []byte{9}, digest(9), time.Now()) }); !errors.Is(err, ErrConflict) {
		t.Fatalf("AK shared by two live nodes: %v", err)
	}
	nodes, err := s.Nodes(ctx)
	if err != nil || len(nodes) != 3 {
		t.Fatalf("got %d nodes, %v", len(nodes), err)
	}
}

func TestSchemaGuardsNodes(t *testing.T) {
	s, _ := openTemp(t)
	mustUpdate(t, s, func(tx *Tx) error {
		if err := tx.InsertNode(testNode("n1", 1)); err != nil {
			return err
		}
		if err := tx.EnrollNode("n1", []byte{9}, digest(9), time.Now()); err != nil {
			return err
		}
		if err := tx.InsertNode(testNode("n2", 2)); err != nil {
			return err
		}
		return tx.RevokeNode("n2", time.Now())
	})
	for name, stmt := range map[string]string{
		"delete":              `DELETE FROM nodes WHERE id = 'n1'`,
		"swap EK":             `UPDATE nodes SET ek_public = x'02' WHERE id = 'n1'`,
		"swap AK":             `UPDATE nodes SET ak_name = zeroblob(32) WHERE id = 'n1'`,
		"un-enroll":           `UPDATE nodes SET state = 'registered', ak_public = NULL, ak_name = NULL, enrolled_at = NULL WHERE id = 'n1'`,
		"un-revoke":           `UPDATE nodes SET state = 'registered', revoked_at = NULL WHERE id = 'n2'`,
		"enroll without AK":   `UPDATE nodes SET state = 'enrolled' WHERE id = 'n2'`,
		"enrolled without AK": `INSERT INTO nodes (id, state, ek_type, ek_cert, ek_public, ek_digest, ek_development, registered_by, registered_at) VALUES ('x', 'enrolled', 'eccp256', x'01', x'01', zeroblob(32), 0, 'a', 1)`,
		"unsupported EK type": `INSERT INTO nodes (id, state, ek_type, ek_cert, ek_public, ek_digest, ek_development, registered_by, registered_at) VALUES ('x', 'registered', 'eccp384', x'01', x'01', randomblob(32), 0, 'a', 1)`,
	} {
		rejectedByConstraint(t, s, name, stmt)
	}
}

func TestChallengesAreSingleUse(t *testing.T) {
	s, _ := openTemp(t)
	now := time.Now()
	mustUpdate(t, s, func(tx *Tx) error {
		if err := tx.InsertNode(testNode("n1", 1)); err != nil {
			return err
		}
		if err := tx.InsertEnrollmentChallenge(&EnrollmentChallenge{
			ID: "e1", NodeID: "n1", AKPublic: []byte{1}, AKName: digest(1), SecretHash: digest(2),
			IssuedAt: now, ExpiresAt: now.Add(time.Minute),
		}); err != nil {
			return err
		}
		return tx.InsertAttestChallenge(&AttestChallenge{
			ID: "a1", NodeID: "n1", NonceHash: digest(3), IssuedAt: now, ExpiresAt: now.Add(time.Minute),
		})
	})
	mustUpdate(t, s, func(tx *Tx) error {
		c, err := tx.AttestChallenge("a1")
		if err != nil || !bytes.Equal(c.NonceHash, digest(3)) || !c.ConsumedAt.IsZero() {
			t.Fatalf("got %+v, %v", c, err)
		}
		if err := tx.ConsumeAttestChallenge("a1", now); err != nil {
			return err
		}
		return tx.ConsumeEnrollmentChallenge("e1", now, false)
	})
	mustUpdate(t, s, func(tx *Tx) error {
		if err := tx.ConsumeAttestChallenge("a1", now); !errors.Is(err, ErrConsumed) {
			t.Errorf("attest challenge reused: %v", err)
		}
		if err := tx.ConsumeEnrollmentChallenge("e1", now, true); !errors.Is(err, ErrConsumed) {
			t.Errorf("enrollment challenge reused: %v", err)
		}
		if _, err := tx.AttestChallenge("missing"); !errors.Is(err, ErrNotFound) {
			t.Errorf("missing challenge: %v", err)
		}
		return nil
	})
	for name, stmt := range map[string]string{
		"reset attest consumption":     `UPDATE attest_challenges SET consumed_at = NULL`,
		"re-consume attest":            `UPDATE attest_challenges SET consumed_at = consumed_at + 1`,
		"reset enrollment consumption": `UPDATE enrollment_challenges SET consumed_at = NULL, outcome = NULL`,
		"flip enrollment outcome":      `UPDATE enrollment_challenges SET outcome = 'success'`,
		"expiry before issue":          `INSERT INTO attest_challenges (id, node_id, nonce_hash, issued_at, expires_at) VALUES ('a2', 'n1', zeroblob(32), 10, 10)`,
		"unknown node":                 `INSERT INTO attest_challenges (id, node_id, nonce_hash, issued_at, expires_at) VALUES ('a3', 'nope', zeroblob(32), 1, 10)`,
	} {
		rejectedByConstraint(t, s, name, stmt)
	}
	// Changing the nonce of an unconsumed challenge is also refused.
	mustUpdate(t, s, func(tx *Tx) error {
		return tx.InsertAttestChallenge(&AttestChallenge{ID: "a4", NodeID: "n1", NonceHash: digest(4), IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
	})
	rejectedByConstraint(t, s, "nonce rewritten", `UPDATE attest_challenges SET nonce_hash = zeroblob(32), consumed_at = 1 WHERE id = 'a4'`)
}

func TestAttestationsAndPolicies(t *testing.T) {
	s, _ := openTemp(t)
	now := time.Now()
	var seq uint64
	mustUpdate(t, s, func(tx *Tx) error {
		if err := tx.InsertNode(testNode("n1", 1)); err != nil {
			return err
		}
		for _, id := range []string{"a1", "a2"} {
			if err := tx.InsertAttestChallenge(&AttestChallenge{ID: id, NodeID: "n1", NonceHash: digest(1), IssuedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
				return err
			}
		}
		e, err := tx.AppendAudit(audit.Record{Time: now, Actor: "node:n1", Action: "attest.verify", Object: "node/n1"})
		seq = e.Sequence
		return err
	})

	var v1, v2 int64
	mustUpdate(t, s, func(tx *Tx) error {
		var err error
		if v1, err = tx.InsertPolicy(&Policy{Kind: PolicyMeasurement, Document: []byte("{}"), Digest: digest(1), CreatedAt: now, CreatedBy: "op"}); err != nil {
			return err
		}
		v2, err = tx.InsertPolicy(&Policy{Kind: PolicyMeasurement, Document: []byte("{ }"), Digest: digest(2), CreatedAt: now, CreatedBy: "op"})
		return err
	})
	if v1 != 1 || v2 != 2 {
		t.Fatalf("versions %d %d", v1, v2)
	}
	p, err := s.CurrentPolicy(ctx, PolicyMeasurement)
	if err != nil || p.Version != 2 || !bytes.Equal(p.Digest, digest(2)) {
		t.Fatalf("got %+v, %v", p, err)
	}

	pass := &Attestation{NodeID: "n1", ChallengeID: "a1", VerifiedAt: now, Passed: true, PolicyVersion: 2,
		Reference: "fw", PCRDigest: digest(5), ResetCount: 1, RestartCount: 2, EvidenceHash: digest(6), AuditSeq: seq}
	mustUpdate(t, s, func(tx *Tx) error { _, err := tx.InsertAttestation(pass); return err })
	got, err := s.LatestAttestation(ctx, "n1")
	if err != nil || !got.Passed || got.PolicyVersion != 2 || got.Reference != "fw" || got.AuditSeq != seq {
		t.Fatalf("got %+v, %v", got, err)
	}

	dup := *pass
	if err := update(t, s, func(tx *Tx) error { _, err := tx.InsertAttestation(&dup); return err }); !errors.Is(err, ErrConflict) {
		t.Fatalf("second attestation for one challenge: %v", err)
	}
	passNoPolicy := &Attestation{NodeID: "n1", ChallengeID: "a2", VerifiedAt: now, Passed: true, EvidenceHash: digest(6), AuditSeq: seq}
	if err := update(t, s, func(tx *Tx) error { _, err := tx.InsertAttestation(passNoPolicy); return err }); !errors.Is(err, ErrConflict) {
		t.Fatalf("pass without policy: %v", err)
	}
	failNoReason := &Attestation{NodeID: "n1", ChallengeID: "a2", VerifiedAt: now, EvidenceHash: digest(6), AuditSeq: seq}
	if err := update(t, s, func(tx *Tx) error { _, err := tx.InsertAttestation(failNoReason); return err }); !errors.Is(err, ErrConflict) {
		t.Fatalf("failure without reason: %v", err)
	}

	for name, stmt := range map[string]string{
		"rewrite attestation": `UPDATE attestations SET result = 'pass'`,
		"delete attestation":  `DELETE FROM attestations`,
		"rewrite policy":      `UPDATE policies SET document = x'00' WHERE version = 1`,
		"delete policy":       `DELETE FROM policies WHERE version = 2`,
		"skip policy version": `INSERT INTO policies VALUES (4, 'measurement', x'00', zeroblob(32), 1, 'op')`,
		"unknown policy kind": `INSERT INTO policies VALUES (3, 'secrets', x'00', zeroblob(32), 1, 'op')`,
	} {
		rejectedByConstraint(t, s, name, stmt)
	}
	if _, err := s.CurrentPolicy(ctx, "other"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
