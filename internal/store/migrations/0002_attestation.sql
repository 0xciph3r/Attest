-- Node enrollment, attestation challenges, attestation results and
-- versioned policies. As with the audit ledger, constraints and triggers
-- enforce the application's invariants against bugs; they are not a
-- defence against someone with direct write access to the database file.

-- Policies are append-only and versioned contiguously across all kinds; the
-- current policy of a kind is its highest version.
CREATE TABLE policies (
    version    INTEGER PRIMARY KEY CHECK (version > 0),
    kind       TEXT    NOT NULL CHECK (kind IN ('measurement')),
    document   BLOB    NOT NULL CHECK (length(document) > 0),
    digest     BLOB    NOT NULL CHECK (length(digest) = 32),
    created_at INTEGER NOT NULL,
    created_by TEXT    NOT NULL CHECK (length(created_by) > 0)
) STRICT;

CREATE TRIGGER policies_no_update BEFORE UPDATE ON policies
BEGIN SELECT RAISE(ABORT, 'policies are append-only'); END;

CREATE TRIGGER policies_no_delete BEFORE DELETE ON policies
BEGIN SELECT RAISE(ABORT, 'policies are append-only'); END;

CREATE TRIGGER policies_contiguous BEFORE INSERT ON policies
WHEN NEW.version IS NOT (SELECT COALESCE(MAX(version), 0) + 1 FROM policies)
BEGIN SELECT RAISE(ABORT, 'policy versions must be contiguous'); END;

-- A node is a machine identified by its TPM endorsement key. An operator
-- registers it (state 'registered'); it becomes 'enrolled' once it proves
-- an AK is resident in that TPM; 'revoked' is terminal.
CREATE TABLE nodes (
    id             TEXT    PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
    state          TEXT    NOT NULL CHECK (state IN ('registered', 'enrolled', 'revoked')),
    ek_type        TEXT    NOT NULL CHECK (ek_type IN ('rsa2048', 'eccp256')),
    ek_cert        BLOB    NOT NULL CHECK (length(ek_cert) > 0),
    ek_public      BLOB    NOT NULL CHECK (length(ek_public) > 0),
    ek_digest      BLOB    NOT NULL CHECK (length(ek_digest) = 32),
    ek_development INTEGER NOT NULL CHECK (ek_development IN (0, 1)),
    ak_public      BLOB,
    ak_name        BLOB,
    registered_by  TEXT    NOT NULL CHECK (length(registered_by) > 0),
    registered_at  INTEGER NOT NULL,
    enrolled_at    INTEGER,
    revoked_at     INTEGER,
    CHECK ((ak_public IS NULL) = (ak_name IS NULL)),
    CHECK ((ak_public IS NULL) = (enrolled_at IS NULL)),
    CHECK (state <> 'registered' OR ak_public IS NULL),
    CHECK (state <> 'enrolled' OR ak_public IS NOT NULL),
    CHECK ((state = 'revoked') = (revoked_at IS NOT NULL))
) STRICT;

-- One live node per TPM and per AK. Revoked nodes release their EK so the
-- machine can be registered again.
CREATE UNIQUE INDEX nodes_live_ek ON nodes (ek_digest) WHERE state <> 'revoked';
CREATE UNIQUE INDEX nodes_live_ak ON nodes (ak_name) WHERE state <> 'revoked' AND ak_name IS NOT NULL;

CREATE TRIGGER nodes_no_delete BEFORE DELETE ON nodes
BEGIN SELECT RAISE(ABORT, 'nodes are revoked, not deleted'); END;

CREATE TRIGGER nodes_identity_immutable BEFORE UPDATE ON nodes
WHEN NEW.id IS NOT OLD.id
  OR NEW.ek_type IS NOT OLD.ek_type
  OR NEW.ek_cert IS NOT OLD.ek_cert
  OR NEW.ek_public IS NOT OLD.ek_public
  OR NEW.ek_digest IS NOT OLD.ek_digest
  OR NEW.ek_development IS NOT OLD.ek_development
  OR NEW.registered_by IS NOT OLD.registered_by
  OR NEW.registered_at IS NOT OLD.registered_at
  OR (OLD.ak_public IS NOT NULL AND (NEW.ak_public IS NOT OLD.ak_public OR NEW.ak_name IS NOT OLD.ak_name))
  OR (OLD.enrolled_at IS NOT NULL AND NEW.enrolled_at IS NOT OLD.enrolled_at)
BEGIN SELECT RAISE(ABORT, 'node identity fields are immutable'); END;

CREATE TRIGGER nodes_state_transition BEFORE UPDATE OF state ON nodes
WHEN NOT (
       (OLD.state = 'registered' AND NEW.state IN ('registered', 'enrolled', 'revoked'))
    OR (OLD.state = 'enrolled'   AND NEW.state IN ('enrolled', 'revoked'))
    OR (OLD.state = 'revoked'    AND NEW.state = 'revoked' AND NEW.revoked_at IS OLD.revoked_at)
)
BEGIN SELECT RAISE(ABORT, 'invalid node state transition'); END;

-- Enrollment challenge: a secret encrypted to the node's EK for one AK
-- name. Only a hash of the secret is stored. Single use: the only permitted
-- update records consumption.
CREATE TABLE enrollment_challenges (
    id          TEXT    PRIMARY KEY CHECK (length(id) > 0),
    node_id     TEXT    NOT NULL REFERENCES nodes (id),
    ak_public   BLOB    NOT NULL CHECK (length(ak_public) > 0),
    ak_name     BLOB    NOT NULL CHECK (length(ak_name) > 0),
    secret_hash BLOB    NOT NULL CHECK (length(secret_hash) = 32),
    issued_at   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL CHECK (expires_at > issued_at),
    consumed_at INTEGER,
    outcome     TEXT    CHECK (outcome IN ('success', 'failure')),
    CHECK ((consumed_at IS NULL) = (outcome IS NULL))
) STRICT;

CREATE TRIGGER enrollment_challenges_single_use BEFORE UPDATE ON enrollment_challenges
WHEN OLD.consumed_at IS NOT NULL
  OR NEW.consumed_at IS NULL
  OR NEW.id IS NOT OLD.id OR NEW.node_id IS NOT OLD.node_id
  OR NEW.ak_public IS NOT OLD.ak_public OR NEW.ak_name IS NOT OLD.ak_name
  OR NEW.secret_hash IS NOT OLD.secret_hash
  OR NEW.issued_at IS NOT OLD.issued_at OR NEW.expires_at IS NOT OLD.expires_at
BEGIN SELECT RAISE(ABORT, 'enrollment challenges are single-use'); END;

-- Attestation challenge: a fresh nonce bound to one node. Only its hash is
-- stored. Single use.
CREATE TABLE attest_challenges (
    id          TEXT    PRIMARY KEY CHECK (length(id) > 0),
    node_id     TEXT    NOT NULL REFERENCES nodes (id),
    nonce_hash  BLOB    NOT NULL CHECK (length(nonce_hash) = 32),
    issued_at   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL CHECK (expires_at > issued_at),
    consumed_at INTEGER
) STRICT;

CREATE TRIGGER attest_challenges_single_use BEFORE UPDATE ON attest_challenges
WHEN OLD.consumed_at IS NOT NULL
  OR NEW.consumed_at IS NULL
  OR NEW.id IS NOT OLD.id OR NEW.node_id IS NOT OLD.node_id
  OR NEW.nonce_hash IS NOT OLD.nonce_hash
  OR NEW.issued_at IS NOT OLD.issued_at OR NEW.expires_at IS NOT OLD.expires_at
BEGIN SELECT RAISE(ABORT, 'attestation challenges are single-use'); END;

-- Attestation results, one per consumed challenge. Append-only.
CREATE TABLE attestations (
    id             INTEGER PRIMARY KEY,
    node_id        TEXT    NOT NULL REFERENCES nodes (id),
    challenge_id   TEXT    NOT NULL UNIQUE REFERENCES attest_challenges (id),
    verified_at    INTEGER NOT NULL,
    result         TEXT    NOT NULL CHECK (result IN ('pass', 'fail')),
    reason         TEXT,
    policy_version INTEGER REFERENCES policies (version),
    reference      TEXT,
    pcr_digest     BLOB    CHECK (pcr_digest IS NULL OR length(pcr_digest) = 32),
    reset_count    INTEGER,
    restart_count  INTEGER,
    evidence_hash  BLOB    NOT NULL CHECK (length(evidence_hash) = 32),
    audit_seq      INTEGER NOT NULL UNIQUE REFERENCES audit_entries (seq),
    CHECK ((result = 'pass') = (reason IS NULL)),
    CHECK (result <> 'pass' OR (policy_version IS NOT NULL AND reference IS NOT NULL AND pcr_digest IS NOT NULL))
) STRICT;

CREATE INDEX attestations_node ON attestations (node_id, verified_at);

CREATE TRIGGER attestations_no_update BEFORE UPDATE ON attestations
BEGIN SELECT RAISE(ABORT, 'attestations are append-only'); END;

CREATE TRIGGER attestations_no_delete BEFORE DELETE ON attestations
BEGIN SELECT RAISE(ABORT, 'attestations are append-only'); END;
