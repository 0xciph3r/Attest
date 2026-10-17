# Attest security properties

Each property below is a claim Attest makes, stated so that it can be tested.
A feature is complete only when its property has a mechanism, documented
assumptions, defined failure behavior and a named test that exercises the
failure, not just the happy path. Threats and adversaries (A1–A10) are defined
in [threat-model.md](threat-model.md).

Status key: **implemented** · **designed** · **planned**.

## Summary

| ID  | Property            | Status       |
| --- | ------------------- | ------------ |
| P1  | Enrollment          | designed     |
| P2  | Freshness           | planned      |
| P3  | Evidence            | planned      |
| P4  | Identity            | planned      |
| P5  | Authorization       | planned      |
| P6  | Workload isolation  | planned      |
| P7  | Secret handling     | planned      |
| P8  | Audit integrity     | implemented  |
| P9  | Failure behavior    | partial      |
| P10 | Recovery            | partial      |

## P1 Enrollment

**Claim.** A machine becomes an enrolled node only if an authenticated
operator registered its TPM's endorsement key beforehand, and the attestation
key presented at enrollment is proven to reside in that same TPM.

- Mechanism: operator pre-registration of the EK; EK certificate validation;
  credential activation binding the AK to the EK. See
  [enrollment.md](enrollment.md).
- Assumptions: 1, 5.
- Failure behavior: no pending registration, invalid EK chain, AK with
  incorrect attributes or failed activation → enrollment rejected and audited;
  no node record transitions to `enrolled`.
- Tests: planned (weeks 03–05).

## P2 Freshness

**Claim.** Each accepted quote was produced after the control plane issued the
challenge it answers, and each challenge is accepted at most once.

- Mechanism: ≥128-bit random nonce from `crypto/rand`, stored only as a hash,
  bound to one node, expiring, and consumed in the same transaction that
  records the verification result. The nonce is the quote's qualifying data
  (`extraData`).
- Failure behavior: unknown, expired, consumed or other-node challenge →
  reject.
- Tests: planned — replay of a consumed challenge, cross-node challenge,
  expired challenge, concurrent double submission.

## P3 Evidence

**Claim.** Attestation succeeds only if the quote signature verifies under the
node's enrolled AK, the quoted PCR digest matches the supplied PCR values, the
measured-boot event log replays to those PCR values, and the measurements
satisfy the active policy version.

- Failure behavior: every check failure has a distinct, tested reason code.
  Malformed input is rejected before cryptographic processing.
- Tests: planned — invalid signature, wrong AK, PCR mismatch, event-log/PCR
  mismatch, disallowed measurement, truncated and oversized evidence.

## P4 Identity

**Claim.** No workload identity is issued to a node without a successful
attestation that is no older than the policy's maximum attestation age.
Identities are short-lived and name exactly one workload.

- Tests: planned — failed attestation yields no identity; stale attestation
  yields no identity; expiry is enforced.

## P5 Authorization

**Claim.** Successful attestation grants nothing on its own. Each secret
release requires an explicit grant to the requesting workload identity under
the policy version in force at the time of the request.

- Tests: planned — attested workload without a grant is denied; revoked grant
  takes effect on the next request.

## P6 Workload isolation

**Claim.** Two workloads on the same node do not receive each other's
identities or permissions by sharing the node or the agent socket.

- Mechanism: the agent identifies callers by kernel-reported peer credentials
  (`SO_PEERCRED`) mapped to configured systemd units; requests are made on
  behalf of that workload only.
- Assumption: 4 (node kernel trusted at request time).
- Tests: planned — workload B cannot obtain A's identity or secrets via the
  agent socket.

## P7 Secret handling

**Claim.** Secret plaintext never appears in logs, error messages, audit
records or the database. Stored secrets are ciphertext under a data key that
is itself wrapped by a master key stored outside the database.

- Tests: planned — canary secret value searched for in logs, database file,
  WAL, error responses and audit export after success and failure paths.

## P8 Audit integrity — implemented

**Claim.** Given a set of trusted checkpoints, `attestctl audit verify`
detects any alteration, reordering, insertion or removal of ledger entries at
or before the highest checkpointed sequence, and any truncation or rollback of
the ledger below it.

Mechanism (specified in [audit-ledger.md](audit-ledger.md)):

- Each entry's hash is `SHA-256(prev_hash || canonical_body)`, where the body
  includes the sequence number and length-prefixed fields.
- Sequence numbers are contiguous from 1.
- A checkpoint is an Ed25519 signature over `(sequence, hash, time, key_id)`
  with domain separation.
- Verification fails closed: no checkpoint supplied is an error unless the
  caller explicitly accepts an internally-consistent-only result.

Assumptions:

- Assumption 8: the checkpoint signing key is not available to an attacker who
  can write the database, and checkpoints are kept where that attacker cannot
  replace them. The recommended deployment has an auditor sign checkpoints
  offline, from a read-only database copy or export, with a key that never
  touches the control plane.

What it does **not** provide:

- Entries after the newest checkpoint are only internally consistent; an
  attacker with write access can rewrite or remove them without detection.
- It does not prove that records were truthful when written (A9).
- The SQLite triggers that reject UPDATE, DELETE and out-of-order inserts guard
  against application bugs. They are not a security boundary: anyone who can
  write the file can drop them.

Failure behavior: verification stops at the first fault and reports the
sequence number and category (`sequence discontinuity`, `previous-hash
mismatch`, `entry hash mismatch`, `does not match trusted checkpoint`,
`truncated`, `invalid checkpoint signature`, `untrusted key`, `checkpoints
conflict`). `attestctl` exits 1 for verification failures and 2 when the check
could not run.

Tests:

| Case                                               | Test                                                      |
| -------------------------------------------------- | --------------------------------------------------------- |
| Altered actor/action/object/metadata/time          | `internal/audit` `TestVerifyDetectsTampering`             |
| Swapped, deleted, duplicated or renumbered entries | `TestVerifyDetectsTampering`                              |
| Field-boundary shifting                            | `TestCanonicalFieldBoundaries`                            |
| Rewritten and fully re-hashed history              | `TestVerifyDetectsTampering`, `TestCheckpointDetectsPrivilegedRewrite`, e2e `privileged rewrite` |
| Truncation and restored older backup               | `TestVerifyDetectsTampering`, `TestRestoredBackupIsDetectedAsTruncation`, e2e `restored backup is rollback` |
| Forged, altered or untrusted checkpoints           | `TestVerifyCheckpointTrust`, e2e `untrusted key`          |
| No checkpoint supplied                             | `TestVerifyCheckpointTrust`, e2e `unanchored requires explicit opt-in` |
| Database rejects UPDATE/DELETE/non-head INSERT     | `internal/store` `TestDatabaseEnforcesAppendOnly`         |
| Concurrent appends never fork the chain            | `TestConcurrentAppendsFormOneChain`                       |
| Tampered JSONL export                              | e2e `verified export`                                     |

## P9 Failure behavior

**Claim.** Every security-sensitive operation fails closed: if a required
policy, state or audit step cannot complete, the operation does not take
effect.

- Implemented: audit verification treats read errors, missing checkpoints and
  unknown keys as failures; the store refuses databases with a newer schema;
  private keys with group/other permissions are refused.
- Contract for later components: an operation that must be audited performs
  its state change and its audit append in a way that a failed append prevents
  the effect (same transaction, or append-before-release for secret delivery).
- Tests: planned per component — inject audit-store failure and assert no
  identity or secret is released.

## P10 Recovery

**Claim.** Restoring a backup cannot silently roll back the audit ledger,
reintroduce a superseded policy, or duplicate identity state.

- Implemented: a restored ledger shorter than a trusted checkpoint fails
  verification as truncated; a database migrated by a newer binary is refused.
- Planned: control-plane startup verifies the ledger against the latest
  checkpoint supplied in configuration and refuses to serve if it fails;
  policy versions and identity serials are checked against audited history.
