# Node enrollment and key lifecycle

Status: **implemented** in process (`internal/enrollment`), tested against
`swtpm`. The network transport between agent and control plane arrives with
the gRPC API in weeks 06–08. This document defines the protocol and state
machine that the implementation and tests follow. Property: [P1 Enrollment](security-properties.md#p1-enrollment).

## Goals

- A machine becomes an enrolled node only with prior operator approval.
- The attestation key (AK) used for quotes is proven to live in the TPM the
  operator approved.
- Enrollment establishes *which key may attest*, nothing more. It grants no
  identity and no secret access; each identity still requires a fresh,
  policy-compliant attestation.

## Keys

### On each node (inside the TPM)

| Key | Properties | Purpose |
| --- | ---------- | ------- |
| Endorsement key (EK) | Manufacturer-provisioned, decrypt-only, certified by the manufacturer CA | Identifies the TPM. Never signs. |
| Attestation key (AK) | Created by the agent inside the TPM; `restricted`, `sign`, `fixedTPM`, `fixedParent`, `sensitiveDataOrigin`, `userWithAuth` | Signs quotes. `restricted` ensures it only signs TPM-generated structures, so it cannot be used to sign forged quote data. |

### On the control plane (files, never in SQLite)

| Key | Purpose | Storage (MVP) |
| --- | ------- | ------------- |
| Identity CA key | Signs workload identities | File, 0600, owned by the `attestd` user |
| Secret master key (KEK) | Wraps per-secret data keys | File, 0600; separate from the CA key |
| `attestd` TLS key | Authenticates the control plane to agents and operators | File, 0600 |
| Audit checkpoint key | Signs audit checkpoints | **Not on the control plane.** Held by an auditor |

## Enrollment protocol

```
Operator          attestctl/attestd                  attest-agent / TPM
   │  register EK cert ──▶│ 1. cert chains to a configured root
   │                      │    node: registered (audited)
   │                      │
   │                      │◀── AK public area ───────────────────┤
   │                      │  2. node is registered (not enrolled/revoked)
   │                      │  3. AK attributes are exactly as required;
   │                      │     AK name computed by the control plane
   │                      │  4. EK cert re-verified; EK public derived from it
   │                      │  5. secret ← random 32 bytes
   │                      │     blob ← MakeCredential(EK, name(AK), secret)
   │                      │──── blob, challenge id ──────────────▶│
   │                      │                                       │ ActivateCredential
   │                      │                                       │ (succeeds only if AK
   │                      │                                       │  with that name is in
   │                      │                                       │  the TPM holding EK)
   │                      │◀──── recovered secret ────────────────┤
   │                      │  6. single use, not expired, same node,
   │                      │     constant-time hash compare
   │                      │  7. node: enrolled, AK stored (audited)
```

1. **Registration.** An operator registers the machine's EK certificate,
   obtained out of band (e.g. read during provisioning). The certificate must
   chain to a configured root; an EK that chains only to a development root is
   refused unless the current measurement policy sets
   `allow_development_roots`. The EK public area is *derived* from the
   certificate and the TCG default template; nothing the node later claims
   about its EK is used. This is the approval step; no node can create its own
   registration. One EK maps to at most one live (non-revoked) node.
2. **Begin.** The agent sends only its AK public area. The control plane
   requires the node to be `registered`, parses the AK and requires its
   attributes to equal the AK template exactly (below), computes the AK name
   itself, and re-verifies the registered EK certificate (roots or validity
   may have changed). It stores only `SHA-256(secret)`, with a two-minute
   expiry.
3. **Activation.** The agent calls `ActivateCredential`. The TPM releases the
   secret only if an object with the given name is loaded in the same TPM as
   the EK. Returning the secret proves AK residency in the approved TPM.
4. **Completion.** In one transaction the control plane consumes the
   challenge, re-checks expiry, node, node state, EK certificate and
   development-root policy, compares the secret hash in constant time, stores
   the AK and moves the node to `enrolled`, and appends `node.enroll`. If any
   write fails, nothing is recorded and enrollment fails.

A challenge admits **one attempt**: a wrong secret, wrong node, expired
challenge or failed re-check consumes it. Every denial at begin or completion
appends `node.enroll.denied` with a reason code (`node_unknown`,
`node_state_invalid`, `ak_invalid`, `ek_untrusted`, `ek_development_root`,
`challenge_unknown`, `challenge_consumed`, `challenge_expired`,
`challenge_wrong_node`, `activation_failed`, `ak_in_use`) and leaves the node
state unchanged. Malformed node or challenge IDs are refused before any state
is read, so attacker-chosen strings do not reach the ledger.

### AK template

The AK is an owner-hierarchy primary created from a fixed template: ECC P-256,
ECDSA-SHA256, name algorithm SHA-256, no auth policy, attributes exactly
`fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | noDA |
restricted | sign`. Because primaries are derived from the hierarchy seed, the
agent recreates the same AK after every boot without storing a key blob or
using a persistent handle. Clearing the owner hierarchy changes the AK, which
requires re-enrollment.

## Node state machine

```
           register             activate OK
  (none) ───────────▶ registered ───────────▶ enrolled
                          │                       │
                          │ revoke                │ revoke
                          ▼                       ▼
                       revoked ◀──────────────────┘
```

- Database triggers enforce the transitions, forbid deletion, and make the
  node ID, EK and enrolled AK immutable.
- There are no transitions out of `revoked`. Re-admitting the same machine
  requires a new registration under a new node ID, which is a new audited
  operator decision.
- Registrations do not expire in v1; an unused registration must be revoked.
- Revocation takes effect for the next challenge and the next verification;
  identities already issued expire according to their lifetime. Revocation of
  live identities is out of scope for v1 and is why identity lifetimes must be
  short.
- One EK and one AK each map to at most one live node.

## Key lifecycle

| Event | Handling |
| ----- | -------- |
| AK rotation | Treated as re-enrollment: operator approval, new credential activation, old AK rejected afterwards. |
| TPM replaced or cleared | EK or AK changes; old node record is revoked and a new registration is required. |
| Identity CA rotation | New CA added to the trust bundle before it signs; old CA removed after the longest identity lifetime has elapsed. Procedure to be specified with the identity work (weeks 06–08). |
| KEK rotation | New KEK wraps new data keys; existing data keys are re-wrapped. Procedure to be specified with the broker (weeks 09–10). |
| Checkpoint key rotation | Auditor signs a checkpoint with the new key that chains from a checkpoint verified with the old key; verifiers trust both public keys during the overlap. |
| Suspected key compromise | CA or KEK: rotate and re-issue/re-wrap, review the ledger from the last trusted checkpoint. Checkpoint key: stop trusting it, re-verify history against checkpoints signed before the suspected compromise. |

## Development with `swtpm`

`swtpm_setup` creates an RSA EK certificate signed by a locally generated CA.
That certificate proves nothing about hardware. Attest therefore:

- treats configured roots as either production or development; a chain is
  tried against production roots first;
- refuses development-root EKs at registration, enrollment and every
  attestation unless the current measurement policy sets
  `allow_development_roots`, so withdrawing that flag takes effect at once;
- records development-root use on the node and in every attestation's audit
  metadata (`development: true`).

## Decisions

| Question | Decision |
| -------- | -------- |
| EK without a certificate | Not supported in v1. An EK certificate chaining to a configured root is required. |
| EK key types | RSA-2048 (TCG low range, NV index `0x01c00002`) and ECC NIST P-256 (`0x01c0000a`). ECC P-384 and the high-range templates are deferred. |
| EK certificate encoding | DER, with trailing NV padding of all `0x00` or all `0xff` tolerated. The TCG critical subject-alternative-name containing only a directory name is accepted; any other unhandled critical extension is refused. |
| EK certificate validity | Checked at registration and enrollment. An expired EK certificate cannot enroll; an already enrolled node keeps attesting with its enrolled AK. |
| AK storage | Deterministic owner-hierarchy primary; nothing persisted (see above). |
| TPM library | `github.com/google/go-tpm` for TPM commands and credential creation. `go-attestation`/`go-eventlog` are not used: their event-log replay accepts empty logs and unlogged PCRs and applies firmware workarounds, which conflicts with the fail-closed requirement. Attest has its own strict parser (`internal/eventlog`). |
