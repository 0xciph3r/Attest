# Attest threat model

Status: draft for the v1 MVP. Review this document before reviewing code. It
defines what Attest defends against, what it assumes, and what it explicitly
does not protect. Companion documents:
[security-properties.md](security-properties.md) states the properties as
testable claims, [enrollment.md](enrollment.md) defines node enrollment and key
lifecycle, and [audit-ledger.md](audit-ledger.md) specifies the audit format.

## 1. System summary

Attest establishes a chain from a machine's measured boot state, to a
short-lived identity issued to a workload on that machine, to a policy decision
made when that workload requests a secret.

| Component      | Runs on        | Role                                                                    |
| -------------- | -------------- | ----------------------------------------------------------------------- |
| `attestd`      | Control plane  | Enrollment, verification, identity issuance, policy, secret broker, audit |
| `attest-agent` | Each node      | TPM access, evidence collection, local workload authentication          |
| `attestctl`    | Operator / CI  | Administration and offline audit verification                           |
| `libattest`    | Workload       | Client for the agent's Unix socket                                      |
| TPM 2.0        | Each node      | Root of trust for reporting (quotes over PCRs)                          |

The MVP has a single control-plane instance backed by SQLite.

## 2. Assets

| Asset                                   | Why it matters                                                       |
| --------------------------------------- | -------------------------------------------------------------------- |
| Secret plaintext                        | The thing ultimately being protected                                 |
| Secret master key (KEK)                 | Decrypts every stored secret                                         |
| Identity CA private key                 | Can mint any workload identity                                       |
| Enrollment records (EK/AK bindings)     | Decide which hardware is allowed to attest                           |
| Challenges (nonces)                     | Guarantee freshness; a reusable nonce enables replay                 |
| Policy (versioned)                      | Decides which measurements, workloads and secrets are acceptable     |
| Issued workload identities              | Bearer of authority until expiry                                     |
| Audit ledger                            | Evidence of who did what; basis for incident response                |
| Audit checkpoint signing key            | Anchors the ledger; must be held outside the control plane           |
| Operator credentials                    | Can change enrollment, policy and secrets                            |

## 3. Trust boundaries

```
 Operator ──TB1──▶ attestd ◀──TB2──▶ attest-agent ◀──TB4──▶ workload
                     │                    │
                    TB5                  TB3
                     ▼                    ▼
           SQLite / key files            TPM

 Auditor ──TB6──▶ ledger export / database copy (offline)
```

| Boundary | Between                             | Crossing must be                                                      |
| -------- | ----------------------------------- | --------------------------------------------------------------------- |
| TB1      | Operator/CI and `attestd`           | Authenticated, authorized per operation, audited                      |
| TB2      | Agent and `attestd` over network    | Mutually authenticated TLS; evidence bound to a fresh challenge       |
| TB3      | Agent and TPM                       | Trusted only for what the TPM signs; the agent itself is not trusted to report measurements |
| TB4      | Workload and agent (Unix socket)    | Caller identified by kernel-reported credentials, mapped to a configured workload boundary |
| TB5      | `attestd` and its storage/keys      | Private keys never in the database; secrets only as ciphertext        |
| TB6      | Auditor and the ledger              | Verified offline against checkpoints the control plane cannot forge   |

## 4. Assumptions

Attest's guarantees hold only while these assumptions hold. Each is a place a
reviewer should push.

1. **TPM integrity.** The TPM correctly implements TPM 2.0, keeps EK and AK
   private keys inside the TPM, and the EK certificate chain is issued by a
   manufacturer whose roots the operator has configured.
2. **Measured boot.** Platform firmware (the core root of trust for
   measurement) measures each boot component into PCRs before executing it.
   Attest verifies what was measured, not what was executed after boot.
3. **Control plane host is trusted** in v1. Its root user, kernel and storage
   are within the trusted computing base. Compromise of the control plane is
   out of scope except for audit tamper-evidence relative to checkpoints held
   elsewhere.
4. **Node kernel is trusted at request time** for identifying local callers
   (peer credentials on the Unix socket, cgroup/systemd unit membership).
   A compromised node kernel can impersonate any workload on that node.
5. **Operators approve enrollment** out of band (e.g. by recording the EK of a
   machine they physically control).
6. **Clocks are roughly synchronized** (minutes, not hours). Freshness relies
   on single-use challenges, not timestamps; clock skew affects identity
   validity windows.
7. **Cryptographic primitives** (SHA-256, Ed25519, ECDSA P-256, AES-GCM, TLS
   1.3) are secure and implemented correctly by the Go standard library and
   `go-tpm`.
8. **The audit checkpoint key and published checkpoints** are stored outside
   the control plane's administrative domain.

## 5. Adversaries

| ID  | Adversary                                         | In scope | Notes                                                        |
| --- | ------------------------------------------------- | -------- | ------------------------------------------------------------ |
| A1  | Network attacker between agent and `attestd`      | Yes      | Can observe, replay, drop and modify traffic                 |
| A2  | Unenrolled machine posing as a node               | Yes      | May run a genuine TPM or `swtpm`                             |
| A3  | Enrolled node booted into a modified chain        | Yes      | Detected only if the modification is measured and the policy forbids it |
| A4  | Malicious unprivileged workload on an enrolled node | Yes    | Shares the node and agent socket with other workloads        |
| A5  | Unauthenticated or under-privileged operator      | Yes      | Includes CI credentials with limited scope                   |
| A6  | Reader of database, backups, logs or config       | Yes      | Must not obtain secret plaintext or private keys             |
| A7  | Writer of the database file                       | Partial  | Audit tampering is detectable relative to a trusted checkpoint; other state is not protected |
| A8  | Root or kernel compromise on a node after boot    | No       | Can impersonate workloads and read delivered secrets         |
| A9  | Compromise of the control-plane host              | No       | Except detection of audit rewriting before the last external checkpoint |
| A10 | Physical attacker with TPM bus access             | No       | Bus sniffing/interposers against discrete TPMs are documented attacks |

## 6. Threats and mitigations

Status: **implemented** (code and tests exist), **designed** (specified, not
built), **planned** (scheduled week in the MVP plan).

### Spoofing

| Threat                                              | Adversary | Mitigation                                                                                  | Status        |
| --------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------- | ------------- |
| Unapproved machine enrolls itself                   | A2        | Operator pre-registers EK; enrollment rejected without a pending registration               | designed (W03) |
| AK not resident in the claimed TPM                  | A2        | Credential activation binds AK name to EK (`MakeCredential`/`ActivateCredential`)            | designed (W03) |
| Software TPM accepted as hardware                   | A2        | EK chain must verify against configured roots; `swtpm` roots are dev-only and flagged in results | designed (W03) |
| Workload claims another workload's identity         | A4        | Agent identifies callers via kernel peer credentials mapped to configured systemd units      | planned (W06–08) |
| Forged operator request                             | A5        | Authenticated admin API; per-operation authorization                                       | planned        |
| Forged audit checkpoint                             | A7        | Ed25519 signature by a key not held on the control plane                                    | implemented   |

### Tampering

| Threat                                              | Adversary | Mitigation                                                                  | Status       |
| --------------------------------------------------- | --------- | --------------------------------------------------------------------------- | ------------ |
| Modified boot chain reported as good                | A3        | Quote signature over PCRs; event-log replay must reproduce quoted PCRs; policy on measurements | planned (W03–05) |
| Evidence modified in transit                        | A1        | Quote is signed by AK; TLS on TB2                                           | planned      |
| Audit entry altered, reordered or removed           | A7        | Hash chain plus externally held signed checkpoints                          | implemented  |
| Accidental audit UPDATE/DELETE by application bug   | —         | SQLite triggers reject UPDATE, DELETE and non-head inserts                  | implemented  |
| Database rolled back to an older backup             | A7        | Checkpoint ahead of the restored head reports truncation                    | implemented  |
| Policy altered without record                       | A5, A7    | Versioned policy; every apply audited                                       | planned      |

### Repudiation

| Threat                                     | Mitigation                                                                  | Status      |
| ------------------------------------------ | --------------------------------------------------------------------------- | ----------- |
| Operator denies a state change             | Every state-changing operation appended to the ledger with the authenticated actor | planned (per component) |
| Secret release or denial not recorded      | Broker fails closed if the audit append fails                               | planned (W09–10) |

### Information disclosure

| Threat                                     | Adversary | Mitigation                                                                  | Status      |
| ------------------------------------------ | --------- | --------------------------------------------------------------------------- | ----------- |
| Secret plaintext in logs/errors/DB         | A6        | Envelope encryption; secret values never logged; leak tests on logs and DB  | planned (W09–10) |
| Private keys in database or backups        | A6        | Keys stored as separate files (0600), never in SQLite                       | partially implemented (audit key loader enforces 0600) |
| Secret metadata in audit records           | A6        | Audit metadata contract forbids secret values; broker records secret IDs only | planned     |

### Denial of service

Availability is not a v1 goal. Required behavior is that every failure is
**closed**: if attestation, policy evaluation or audit append cannot complete,
the requested identity or secret is not issued. An attacker who can make the
control plane unavailable can deny service; this is accepted.

### Elevation of privilege

| Threat                                                    | Adversary | Mitigation                                                    | Status     |
| --------------------------------------------------------- | --------- | ------------------------------------------------------------- | ---------- |
| Successful attestation treated as access to all secrets   | A3, A4    | Attestation only gates identity; secrets require explicit grants | planned    |
| Workload inherits node-wide identity                      | A4        | Identities are per workload; no node-wide secret access       | planned    |
| Ordinary operator reads secret values                     | A5        | Separate secret-read and break-glass permissions, each audited | planned    |
| Replay of an old valid quote                              | A1        | Challenge is random (≥128 bits), single-use, expiring, bound into the quote's qualifying data | planned (W03–05) |

## 7. Explicitly out of scope for v1

- Protection against a compromised host kernel or root administrator, on nodes
  or on the control plane.
- Proof that a workload is free of application vulnerabilities.
- Runtime integrity: boot PCRs say nothing about what happened after boot.
- Preventing an authorized workload from copying a secret it received.
- High availability, distributed consensus, or protection against every
  privileged database administrator.
- Physical attacks on the TPM, including bus interposers.
- Regulatory compliance of any kind.

## 8. Residual risks and open questions

- **Time of check vs. time of use.** A node can be compromised after a
  successful attestation. Identity lifetime bounds the exposure window; the
  lifetime is a policy decision that trades availability against exposure.
- **PCR policy brittleness.** Firmware and kernel updates change PCRs.
  Policies that are too strict cause outages; policies that are too loose
  accept modified chains. The policy format must make allowed values explicit
  and reviewable.
- **Virtual TPMs.** A cloud vTPM's guarantees depend on the hypervisor and
  provider. Evidence from each platform must be documented separately in
  [platform-limitations.md](platform-limitations.md) and never treated as
  equivalent to a discrete TPM.
- **Entries after the last checkpoint** are only internally consistent. An
  attacker with database write access can rewrite or delete them undetectably.
  Checkpoint frequency is therefore a security parameter.
- **Truthfulness of audit records.** The ledger proves records were not changed
  after the fact. It cannot prove that a compromised control plane recorded
  events truthfully in the first place.

## 9. Review checklist

A reviewer should be able to answer "yes" to each before the MVP is declared
done:

- [ ] Every in-scope threat maps to a mitigation with a named test.
- [ ] Every assumption is either justified or listed as a residual risk.
- [ ] Every "fails closed" claim has a test that injects the failure.
- [ ] Nothing in the README or docs claims protection listed in section 7.
