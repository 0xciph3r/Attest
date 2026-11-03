package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xciph3r/attest/internal/audit"
)

// identityFixture creates an enrolled node with one passing attestation
// that bound key digest(7), and a workload policy.
func identityFixture(t *testing.T, s *Store) (attestationID int64, nextSeq func(tx *Tx) uint64) {
	t.Helper()
	now := time.Now()
	nextSeq = func(tx *Tx) uint64 {
		e, err := tx.AppendAudit(audit.Record{Time: now, Actor: "attestd", Action: "test", Object: "x"})
		if err != nil {
			t.Fatal(err)
		}
		return e.Sequence
	}
	mustUpdate(t, s, func(tx *Tx) error {
		if err := tx.InsertNode(testNode("n1", 1)); err != nil {
			return err
		}
		if err := tx.EnrollNode("n1", []byte{1}, digest(9), now); err != nil {
			return err
		}
		for _, id := range []string{"c1", "c2"} {
			if err := tx.InsertAttestChallenge(&AttestChallenge{ID: id, NodeID: "n1", NonceHash: digest(1), IssuedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
				return err
			}
		}
		if _, err := tx.InsertPolicy(&Policy{Kind: PolicyMeasurement, Document: []byte("{}"), Digest: digest(1), CreatedAt: now, CreatedBy: "op"}); err != nil {
			return err
		}
		if _, err := tx.InsertPolicy(&Policy{Kind: PolicyWorkload, Document: []byte("{}"), Digest: digest(2), CreatedAt: now, CreatedBy: "op"}); err != nil {
			return err
		}
		var err error
		attestationID, err = tx.InsertAttestation(&Attestation{NodeID: "n1", ChallengeID: "c1", VerifiedAt: now, Passed: true,
			PolicyVersion: 1, Reference: "fw", PCRDigest: digest(5), EvidenceHash: digest(6), KeyBinding: digest(7), AuditSeq: nextSeq(tx)})
		if err != nil {
			return err
		}
		_, err = tx.InsertAttestation(&Attestation{NodeID: "n1", ChallengeID: "c2", VerifiedAt: now, Reason: "pcr_mismatch",
			EvidenceHash: digest(6), KeyBinding: digest(8), AuditSeq: nextSeq(tx)})
		return err
	})
	return attestationID, nextSeq
}

func TestIdentityRecords(t *testing.T) {
	s, _ := openTemp(t)
	attID, nextSeq := identityFixture(t, s)
	now := time.Now().UTC().Truncate(time.Microsecond)
	nodeID := func(serial string, attestation int64, key []byte) *Identity {
		return &Identity{Serial: serial, Kind: IdentityNode, SPIFFEID: "spiffe://td/attest/node/n1", NodeID: "n1",
			AttestationID: attestation, PublicKeyHash: key, Issuer: "ca1", IssuedAt: now, NotBefore: now,
			NotAfter: now.Add(time.Hour)}
	}
	workloadID := func(serial, parent string, notAfter time.Time) *Identity {
		return &Identity{Serial: serial, Kind: IdentityWorkload, SPIFFEID: "spiffe://td/workload/api", NodeID: "n1",
			Workload: "api", ParentSerial: parent, AttestationID: attID, PolicyVersion: 2, PublicKeyHash: digest(3),
			Issuer: "ca1", IssuedAt: now, NotBefore: now, NotAfter: notAfter}
	}
	insert := func(id *Identity) error {
		return update(t, s, func(tx *Tx) error { id.AuditSeq = nextSeq(tx); return tx.InsertIdentity(id) })
	}
	const (
		node = "00000000000000000000000000000001"
		wl   = "00000000000000000000000000000002"
	)

	if err := insert(nodeID(node, attID, digest(7))); err != nil {
		t.Fatal(err)
	}
	got, err := s.Identity(ctx, node)
	if err != nil || got.Kind != IdentityNode || got.AttestationID != attID || !got.NotAfter.Equal(now.Add(time.Hour)) || !got.RevokedAt.IsZero() {
		t.Fatalf("got %+v, %v", got, err)
	}
	if err := insert(workloadID(wl, node, now.Add(time.Minute))); err != nil {
		t.Fatal(err)
	}

	for name, id := range map[string]*Identity{
		"second node identity for one attestation": nodeID("00000000000000000000000000000003", attID, digest(7)),
		"node identity from failed attestation":    nodeID("00000000000000000000000000000004", attID+1, digest(8)),
		"node identity for unbound key":            nodeID("00000000000000000000000000000005", attID, digest(3)),
		"workload outliving its node identity":     workloadID("00000000000000000000000000000006", node, now.Add(2*time.Hour)),
		"workload without node parent":             workloadID("00000000000000000000000000000007", wl, now.Add(time.Minute)),
	} {
		if err := insert(id); !errors.Is(err, ErrConflict) {
			t.Errorf("%s: got %v", name, err)
		}
	}

	mustUpdate(t, s, func(tx *Tx) error { return tx.RevokeIdentity(node, now) })
	if err := update(t, s, func(tx *Tx) error { return tx.RevokeIdentity(node, now) }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revoke: %v", err)
	}
	if err := insert(workloadID("00000000000000000000000000000008", node, now.Add(time.Minute))); !errors.Is(err, ErrConflict) {
		t.Fatalf("workload under revoked node identity: %v", err)
	}

	for name, stmt := range map[string]string{
		"unrevoke":        `UPDATE identity_records SET revoked_at = NULL`,
		"extend validity": `UPDATE identity_records SET not_after = not_after + 1 WHERE serial = '` + wl + `'`,
		"rebind workload": `UPDATE identity_records SET workload = 'db', revoked_at = 1 WHERE serial = '` + wl + `'`,
		"delete identity": `DELETE FROM identity_records`,
	} {
		rejectedByConstraint(t, s, name, stmt)
	}
}

func TestMigration0003PreservesPolicies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		t.Fatal(err)
	}
	old := &Store{db: db}
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	for _, m := range ms[:2] {
		if err := old.apply(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	mustUpdate(t, old, func(tx *Tx) error {
		if err := tx.InsertNode(testNode("n1", 1)); err != nil {
			return err
		}
		if err := tx.InsertAttestChallenge(&AttestChallenge{ID: "c1", NodeID: "n1", NonceHash: digest(1), IssuedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
			return err
		}
		if _, err := tx.InsertPolicy(&Policy{Kind: PolicyMeasurement, Document: []byte("{}"), Digest: digest(1), CreatedAt: now, CreatedBy: "op"}); err != nil {
			return err
		}
		e, err := tx.AppendAudit(audit.Record{Time: now, Actor: "a", Action: "b", Object: "c"})
		if err != nil {
			return err
		}
		_, err = tx.exec(`INSERT INTO attestations (node_id, challenge_id, verified_at, result, policy_version, reference,
			pcr_digest, evidence_hash, audit_seq) VALUES ('n1', 'c1', 1, 'pass', 1, 'fw', zeroblob(32), zeroblob(32), ?)`, int64(e.Sequence)) //nolint:gosec // test
		return err
	})
	_ = db.Close()

	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	p, err := s.CurrentPolicy(ctx, PolicyMeasurement)
	if err != nil || p.Version != 1 {
		t.Fatalf("policy after migration: %+v, %v", p, err)
	}
	a, err := s.LatestAttestation(ctx, "n1")
	if err != nil || a.PolicyVersion != 1 || a.KeyBinding != nil {
		t.Fatalf("attestation after migration: %+v, %v", a, err)
	}
	rejectedByConstraint(t, s, "policy trigger restored", `UPDATE policies SET document = x'00'`)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO attest_challenges VALUES ('c9', 'n1', zeroblob(32), 1, 2, NULL)`); err != nil {
		t.Fatal(err)
	}
	rejectedByConstraint(t, s, "policy FK enforced", `INSERT INTO attestations (node_id, challenge_id, verified_at, result, reason, policy_version, evidence_hash, audit_seq) VALUES ('n1', 'c9', 1, 'fail', 'x', 99, zeroblob(32), 1)`)
}
