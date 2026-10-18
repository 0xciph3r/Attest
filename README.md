# Attest

Attest lets a distributed system cryptographically prove the state of a Linux
node before issuing it an identity — and only hands it keys after the proof
checks out.

It is a self-hosted platform that uses TPM-backed measured-boot attestation to
govern workload identity and access to secrets:

1. **Evidence** — a TPM quote over measured-boot PCRs, bound to a fresh challenge.
2. **Verification** — signatures, freshness, measurements and enrollment are checked.
3. **Identity** — a short-lived workload identity is issued only after verification.
4. **Secret release** — each request is authorized against current policy and audited.

> **Status: early development (weeks 01–02 of a 12-week MVP).** Attest is not
> production-ready and makes no compliance claims. Read the
> [threat model](docs/threat-model.md) for what it does and does not protect.

## What works today

The tamper-evident audit ledger and its offline tooling:

- Hash-chained, append-only audit entries in SQLite, with database triggers
  that reject updates, deletes and out-of-order inserts.
- Ed25519-signed checkpoints, created by an auditor key that does not live on
  the control plane.
- `attestctl audit verify` detects alteration, reordering, truncation and
  backup rollback relative to trusted checkpoints.

Enrollment, TPM verification, workload identity and the secret broker are
designed or planned; see [security properties](docs/security-properties.md)
for the status of each.

## Quick start

Requires Go 1.26.6 or later (earlier 1.26 releases have a reachable
`encoding/asn1` vulnerability, GO-2026-5972).

```bash
make build    # bin/attestctl (static, CGO-free)
make check    # gofmt, vet, lint, race tests, e2e tests
make e2e      # reproduce the audit attack scenarios against real database files
```

Usage against an Attest database (the `attestd` server that writes it arrives
in a later milestone; the e2e tests create one):

```bash
bin/attestctl audit keygen --key auditor.key --pub auditor.pub
bin/attestctl audit checkpoint --db attest.db --key auditor.key -o cp-1.json
bin/attestctl audit verify --db attest.db --pubkey auditor.pub --checkpoint cp-1.json
```

See [audit-ledger.md](docs/audit-ledger.md) for the format and the operating
procedure.

## Repository layout

```
cmd/attestctl/      operator CLI
internal/audit/     hash chain, checkpoints, verification
internal/store/     SQLite persistence and migrations
e2e/                end-to-end tests against built binaries
docs/               threat model, security properties, designs
```

Planned: `cmd/attestd`, `cmd/attest-agent`, `api/proto`, `internal/{enrollment,verifier,identity,policy,broker}`, `libattest`, `deploy/`.

## Documentation

- [Threat model](docs/threat-model.md)
- [Security properties](docs/security-properties.md)
- [Audit ledger](docs/audit-ledger.md)
- [Enrollment and key lifecycle](docs/enrollment.md)
- [Platform limitations](docs/platform-limitations.md)

## License

[Apache 2.0](LICENSE)
