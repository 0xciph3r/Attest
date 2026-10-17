# Node enrollment and key lifecycle

Status: **design**. Implementation is scheduled for weeks 03–05. This document
defines the protocol and state machine that implementation and tests must
follow. Property: [P1 Enrollment](security-properties.md#p1-enrollment).

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
   │  register EK ───────▶│ node: pending (audited)
   │                      │
   │                      │◀── EK pub (+cert), AK public area ───┤ (TLS, server pinned)
   │                      │  1. EK matches a pending registration
   │                      │  2. EK cert chains to a configured root
   │                      │  3. AK attributes are exactly as required
   │                      │  4. secret ← random 32 bytes
   │                      │     blob ← MakeCredential(EK, name(AK), secret)
   │                      │──── blob, enrollment id ─────────────▶│
   │                      │                                       │ ActivateCredential
   │                      │                                       │ (succeeds only if AK
   │                      │                                       │  with that name is in
   │                      │                                       │  the TPM holding EK)
   │                      │◀──── recovered secret ────────────────┤
   │                      │  5. constant-time compare, single use, not expired
   │                      │  6. node: enrolled, AK pub stored (audited)
```

1. **Registration.** An operator runs `attestctl node register` with the EK
   public key or EK certificate obtained from the machine out of band (e.g.
   during provisioning). The node enters `pending` with an expiry. This is the
   approval step; no node can create its own registration.
2. **Request.** The agent sends its EK public key, EK certificate if
   available, and the AK public area. The control plane computes the AK name
   itself from the public area; it never trusts a client-supplied name.
3. **Validation.** Reject unless the EK matches a pending, unexpired
   registration; the EK certificate (when required by configuration) chains to
   a configured manufacturer root; and the AK attributes match the table above
   exactly.
4. **Credential challenge.** The control plane generates a random secret and
   uses `MakeCredential` to encrypt it to the EK, bound to the AK name. It
   stores only a hash of the secret, with a short expiry.
5. **Activation.** The agent calls `ActivateCredential`. The TPM releases the
   secret only if an object with the given name is loaded in the same TPM as
   the EK. Returning the secret proves AK residency.
6. **Completion.** On match, in one transaction: consume the challenge, store
   the AK public key, move the node to `enrolled`, append `node.enroll` to the
   audit ledger. If the audit append fails, the transaction aborts.

Any failure appends a `node.enroll.denied` audit entry with a reason code and
leaves the node state unchanged.

## Node state machine

```
           register             activate OK
  (none) ───────────▶ pending ─────────────▶ enrolled
                        │                       │
                 expiry │                       │ revoke
                        ▼                       ▼
                     expired                 revoked
```

- There are no transitions out of `expired` or `revoked`. Re-enrolling the
  same machine requires a new registration, which is a new audited operator
  decision.
- Revocation takes effect for the next attestation; identities already issued
  expire according to their lifetime. Revocation of live identities is out of
  scope for v1 and is why identity lifetimes must be short.
- One EK maps to at most one non-terminal node record. One node has exactly
  one active AK.

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

`swtpm_setup` can create EK certificates signed by a locally generated CA.
Those certificates prove nothing about hardware. The control plane must:

- refuse non-hardware EK roots unless they are explicitly configured as
  development roots;
- record in every attestation result whether a development root was used;
- never let development-root nodes satisfy a policy that requires hardware.

## Open decisions

- EK certificate availability varies across vendors and cloud vTPMs. Decide
  whether an EK public-key hash without a certificate is acceptable, and under
  which explicit configuration.
- RSA-2048 vs ECC P-256 EK templates; support both or pick one for v1.
- Whether the AK is persisted at a TPM handle or reloaded from a saved context
  by the agent.
- Library choice: `github.com/google/go-tpm` (low-level TPM 2.0) with or
  without `github.com/google/go-attestation` helpers.
