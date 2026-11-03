-- REPLACE conflict resolution (INSERT OR REPLACE, REPLACE INTO, UPDATE OR
-- REPLACE) deletes the conflicting row without firing DELETE triggers
-- unless recursive_triggers is on, so it could swap out an enrolled node or
-- reset a consumed challenge despite the no-delete and transition triggers.
-- Attest's own connections turn recursive_triggers on; these triggers also
-- refuse key reuse on connections that do not. As elsewhere they catch
-- application bugs and injected SQL, not an attacker with write access to
-- the file.

CREATE TRIGGER nodes_no_replace BEFORE INSERT ON nodes
WHEN EXISTS (SELECT 1 FROM nodes WHERE id = NEW.id)
  OR (NEW.state <> 'revoked' AND EXISTS (
        SELECT 1 FROM nodes WHERE state <> 'revoked'
        AND (ek_digest = NEW.ek_digest OR ak_name = NEW.ak_name)))
BEGIN SELECT RAISE(ABORT, 'nodes cannot be replaced'); END;

CREATE TRIGGER enrollment_challenges_no_replace BEFORE INSERT ON enrollment_challenges
WHEN EXISTS (SELECT 1 FROM enrollment_challenges WHERE id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'enrollment challenges cannot be replaced'); END;

CREATE TRIGGER enrollment_challenges_no_delete BEFORE DELETE ON enrollment_challenges
BEGIN SELECT RAISE(ABORT, 'enrollment challenges cannot be deleted'); END;

CREATE TRIGGER attest_challenges_no_replace BEFORE INSERT ON attest_challenges
WHEN EXISTS (SELECT 1 FROM attest_challenges WHERE id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'attestation challenges cannot be replaced'); END;

CREATE TRIGGER attest_challenges_no_delete BEFORE DELETE ON attest_challenges
BEGIN SELECT RAISE(ABORT, 'attestation challenges cannot be deleted'); END;

CREATE TRIGGER attestations_no_replace BEFORE INSERT ON attestations
WHEN EXISTS (SELECT 1 FROM attestations
             WHERE id = NEW.id OR challenge_id = NEW.challenge_id OR audit_seq = NEW.audit_seq)
BEGIN SELECT RAISE(ABORT, 'attestations cannot be replaced'); END;

CREATE TRIGGER identity_records_no_replace BEFORE INSERT ON identity_records
WHEN EXISTS (SELECT 1 FROM identity_records
             WHERE serial = NEW.serial OR audit_seq = NEW.audit_seq
                OR (NEW.kind = 'node' AND kind = 'node' AND attestation_id = NEW.attestation_id))
BEGIN SELECT RAISE(ABORT, 'identity records cannot be replaced'); END;
