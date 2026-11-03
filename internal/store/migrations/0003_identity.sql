-- attest:foreign-keys-off
-- Workload identity. As elsewhere, constraints and triggers catch
-- application bugs; they are not a defence against direct write access.

-- Rebuild policies to admit the workload policy kind (SQLite cannot alter
-- a CHECK constraint in place).
CREATE TABLE policies_new (
    version    INTEGER PRIMARY KEY CHECK (version > 0),
    kind       TEXT    NOT NULL CHECK (kind IN ('measurement', 'workload')),
    document   BLOB    NOT NULL CHECK (length(document) > 0),
    digest     BLOB    NOT NULL CHECK (length(digest) = 32),
    created_at INTEGER NOT NULL,
    created_by TEXT    NOT NULL CHECK (length(created_by) > 0)
) STRICT;
INSERT INTO policies_new SELECT version, kind, document, digest, created_at, created_by FROM policies;
DROP TABLE policies;
ALTER TABLE policies_new RENAME TO policies;

CREATE TRIGGER policies_no_update BEFORE UPDATE ON policies
BEGIN SELECT RAISE(ABORT, 'policies are append-only'); END;

CREATE TRIGGER policies_no_delete BEFORE DELETE ON policies
BEGIN SELECT RAISE(ABORT, 'policies are append-only'); END;

CREATE TRIGGER policies_contiguous BEFORE INSERT ON policies
WHEN NEW.version IS NOT (SELECT COALESCE(MAX(version), 0) + 1 FROM policies)
BEGIN SELECT RAISE(ABORT, 'policy versions must be contiguous'); END;

-- SHA-256 of the public key the node asked to have certified, bound into
-- the quote's qualifying data. NULL for attestations that bound no key.
ALTER TABLE attestations ADD COLUMN key_binding BLOB
    CHECK (key_binding IS NULL OR length(key_binding) = 32);

-- Every X.509 identity issued. A node identity is backed by exactly one
-- passing attestation whose quote bound the certified key. A workload
-- identity is issued under a live node identity and cannot outlive it.
CREATE TABLE identity_records (
    serial          TEXT    PRIMARY KEY CHECK (length(serial) = 32),
    kind            TEXT    NOT NULL CHECK (kind IN ('node', 'workload')),
    spiffe_id       TEXT    NOT NULL CHECK (spiffe_id LIKE 'spiffe://%'),
    node_id         TEXT    NOT NULL REFERENCES nodes (id),
    workload        TEXT,
    parent_serial   TEXT    REFERENCES identity_records (serial),
    attestation_id  INTEGER NOT NULL REFERENCES attestations (id),
    policy_version  INTEGER REFERENCES policies (version),
    public_key_hash BLOB    NOT NULL CHECK (length(public_key_hash) = 32),
    issuer          TEXT    NOT NULL CHECK (length(issuer) > 0),
    issued_at       INTEGER NOT NULL,
    not_before      INTEGER NOT NULL,
    not_after       INTEGER NOT NULL CHECK (not_after > not_before),
    revoked_at      INTEGER,
    audit_seq       INTEGER NOT NULL UNIQUE REFERENCES audit_entries (seq),
    CHECK ((kind = 'node') = (workload IS NULL)),
    CHECK ((kind = 'node') = (parent_serial IS NULL)),
    CHECK ((kind = 'workload') = (policy_version IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX identity_records_node_attestation
    ON identity_records (attestation_id) WHERE kind = 'node';
CREATE INDEX identity_records_node ON identity_records (node_id, kind);

CREATE TRIGGER identity_records_node_attested BEFORE INSERT ON identity_records
WHEN NEW.kind = 'node' AND NOT EXISTS (
    SELECT 1 FROM attestations a JOIN nodes n ON n.id = a.node_id
    WHERE a.id = NEW.attestation_id AND a.node_id = NEW.node_id
      AND a.result = 'pass' AND a.key_binding = NEW.public_key_hash
      AND n.state = 'enrolled')
BEGIN SELECT RAISE(ABORT, 'node identity requires a passing attestation binding its key'); END;

CREATE TRIGGER identity_records_workload_parent BEFORE INSERT ON identity_records
WHEN NEW.kind = 'workload' AND NOT EXISTS (
    SELECT 1 FROM identity_records p JOIN nodes n ON n.id = p.node_id
    WHERE p.serial = NEW.parent_serial AND p.kind = 'node'
      AND p.node_id = NEW.node_id AND p.attestation_id = NEW.attestation_id
      AND p.revoked_at IS NULL AND NEW.not_after <= p.not_after
      AND n.state = 'enrolled')
BEGIN SELECT RAISE(ABORT, 'workload identity requires a live parent node identity'); END;

CREATE TRIGGER identity_records_no_delete BEFORE DELETE ON identity_records
BEGIN SELECT RAISE(ABORT, 'identity records are append-only'); END;

-- The only permitted update records revocation, once.
CREATE TRIGGER identity_records_revoke_only BEFORE UPDATE ON identity_records
WHEN OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL
  OR NEW.serial IS NOT OLD.serial OR NEW.kind IS NOT OLD.kind
  OR NEW.spiffe_id IS NOT OLD.spiffe_id OR NEW.node_id IS NOT OLD.node_id
  OR NEW.workload IS NOT OLD.workload OR NEW.parent_serial IS NOT OLD.parent_serial
  OR NEW.attestation_id IS NOT OLD.attestation_id OR NEW.policy_version IS NOT OLD.policy_version
  OR NEW.public_key_hash IS NOT OLD.public_key_hash OR NEW.issuer IS NOT OLD.issuer
  OR NEW.issued_at IS NOT OLD.issued_at OR NEW.not_before IS NOT OLD.not_before
  OR NEW.not_after IS NOT OLD.not_after OR NEW.audit_seq IS NOT OLD.audit_seq
BEGIN SELECT RAISE(ABORT, 'identity records may only be revoked'); END;
