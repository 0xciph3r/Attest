# Platform limitations

What Attest's evidence proves depends on the platform. This document records,
per platform, what has been tested and what an accepted attestation does and
does not mean. A platform not listed here is unsupported.

## Current status

Only the development platform has been exercised. No hardware TPM has been
tested yet.

| Platform | Evidence source | Status | What an accepted attestation means |
| -------- | --------------- | ------ | ---------------------------------- |
| Linux + `swtpm` | Software TPM, simulated event log | tested (development only) | The protocol, credential activation and verifier work against a real TPM 2.0 implementation. **Nothing** about hardware or boot integrity: the EK certificate comes from a local CA and the PCRs hold whatever the test extended. |
| Linux + discrete/firmware TPM 2.0 | Hardware TPM, UEFI measured boot | planned (hardware pilot) | To be documented after testing. |
| Cloud vTPMs | Provider-specific | not planned for v1 | Must be documented per provider; never equivalent to a physical TPM. |

### Development with `swtpm`

`make swtpm-up` runs `swtpm` in Docker (works with Docker Desktop and
OrbStack on macOS) and writes its local EK CA to `.swtpm/`. `make test-tpm`
runs the integration tests against it. That CA must only ever be configured
as a *development* root, and the measurement policy must set
`allow_development_roots` for such nodes to enroll or attest. Every verdict for
such a node is marked `development`.

`swtpm_setup` provisions an RSA-2048 EK certificate only; the tests provision
an ECC P-256 certificate themselves to exercise that path.

### TPM and firmware requirements

- TPM 2.0 with an EK certificate in NV at the TCG low-range index for RSA-2048
  (`0x01c00002`) or ECC P-256 (`0x01c0000a`). TPMs that only provide P-384 or
  high-range EK templates are not supported yet, nor are TPMs without an EK
  certificate.
- A SHA-256 PCR bank.
- A TCG crypto-agile (TPM 2.0 format) event log with SHA-256 digests, readable
  by the agent (on Linux,
  `/sys/kernel/security/tpm0/binary_bios_measurements`, which requires root).
- The event log must replay exactly. Attest applies **no** firmware
  workarounds; some real firmware logs are known to need them and will be
  rejected (`event_log_replay_mismatch` or `event_log_invalid`) until a
  specific workaround is reviewed and added.
- The owner hierarchy must not be cleared after enrollment: the AK is derived
  from the owner seed, so clearing it requires re-enrollment.
- EK certificate validity is checked at registration and enrollment.
  Manufacturer EK certificates that have expired cannot be enrolled.

## General limitations

- Attest runs on Linux only. The node agent requires TPM 2.0 access
  (`/dev/tpmrm0`). The control plane and `attestctl` build as static,
  CGO-free binaries.
- Boot PCRs describe the boot chain, not runtime state.
- Development on macOS is supported for the control plane, CLI and audit
  tooling, and for TPM integration tests via `swtpm` in Docker. The node agent
  itself targets Linux.
