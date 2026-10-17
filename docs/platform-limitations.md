# Platform limitations

What Attest's evidence proves depends on the platform. This document records,
per platform, what has been tested and what an accepted attestation does and
does not mean. A platform not listed here is unsupported.

## Current status

No platform has been validated yet. TPM attestation is scheduled for weeks
03–05; this file will be filled in as each platform is tested.

| Platform | Evidence source | Status | What an accepted attestation means |
| -------- | --------------- | ------ | ---------------------------------- |
| Linux + `swtpm` | Software TPM | planned (development only) | The protocol and verifier work. **Nothing** about hardware or boot integrity. |
| Linux + discrete/firmware TPM 2.0 | Hardware TPM, UEFI measured boot | planned (hardware pilot) | To be documented after testing. |
| Cloud vTPMs | Provider-specific | not planned for v1 | Must be documented per provider; never equivalent to a physical TPM. |

## General limitations

- Attest runs on Linux only. The node agent requires TPM 2.0 access
  (`/dev/tpmrm0`). The control plane and `attestctl` build as static,
  CGO-free binaries.
- Boot PCRs describe the boot chain, not runtime state.
- Development on macOS is supported for the control plane, CLI and audit
  tooling; TPM and agent tests require Linux.
