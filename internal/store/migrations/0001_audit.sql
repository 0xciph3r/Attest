-- Audit ledger. See internal/audit for the hash-chain format.
--
-- The triggers below make the application's append-only contract explicit and
-- stop accidental or buggy writes. They do NOT make the table immutable: anyone
-- with direct write access to this file can drop the triggers. Tampering by
-- such a party is detected by verifying against a trusted, externally held
-- checkpoint (attestctl audit verify).
CREATE TABLE audit_entries (
    seq         INTEGER PRIMARY KEY CHECK (seq > 0),
    recorded_at INTEGER NOT NULL,
    actor       TEXT    NOT NULL CHECK (length(actor) > 0),
    action      TEXT    NOT NULL CHECK (length(action) > 0),
    object      TEXT    NOT NULL CHECK (length(object) > 0),
    metadata    BLOB,
    prev_hash   BLOB    NOT NULL CHECK (length(prev_hash) = 32),
    hash        BLOB    NOT NULL CHECK (length(hash) = 32)
) STRICT;

CREATE TRIGGER audit_entries_no_update
BEFORE UPDATE ON audit_entries
BEGIN
    SELECT RAISE(ABORT, 'audit_entries is append-only');
END;

CREATE TRIGGER audit_entries_no_delete
BEFORE DELETE ON audit_entries
BEGIN
    SELECT RAISE(ABORT, 'audit_entries is append-only');
END;

-- Every insert must extend the current head: next sequence number and the
-- head's hash as prev_hash. This also blocks INSERT OR REPLACE over existing
-- rows, which would otherwise bypass the delete trigger.
CREATE TRIGGER audit_entries_extend_head
BEFORE INSERT ON audit_entries
WHEN NEW.seq IS NOT (SELECT COALESCE(MAX(seq), 0) + 1 FROM audit_entries)
  OR NEW.prev_hash IS NOT COALESCE(
        (SELECT hash FROM audit_entries ORDER BY seq DESC LIMIT 1),
        zeroblob(32))
BEGIN
    SELECT RAISE(ABORT, 'audit_entries insert must extend the chain head');
END;
