# Saturation testing

These tests check that Attest's security invariants still hold under
concurrent load, floods and faults. They also show that refusals stay cheap.
They are correctness tests run under stress, not benchmarks. The throughput
figures below are a single measurement on a developer laptop and are not a
capacity claim.

```sh
make saturation          # SCALE=10, verbose, prints the figures below
make saturation-smoke    # SCALE=1 with the race detector; runs in CI
```

The tests live in `internal/api/saturation_test.go` behind the `saturation`
build tag. They drive the real gRPC node service, store and ledger. Most use
an in-memory transport; the rate-limit and stalled-connection tests use real
TCP. `ATTEST_SATURATION_SCALE` multiplies the work in each test.

## What each test asserts

| Test | Load | Asserted invariant |
| ---- | ---- | ------------------ |
| Attest | Concurrent challenge and attest for several nodes | Every attestation succeeds, IDs are distinct, and the ledger verifies |
| Replay race | The same accepted answer submitted concurrently | Accepted exactly once; every other submission is denied `challenge_consumed` |
| Issue workload | Concurrent workload identity issuance | Serials are distinct, one record per certificate, and the ledger verifies |
| Unauthenticated flood | Mixed junk: unknown nodes, forged and replayed challenges, foreign AKs, bad quotes, wrong enrollment secrets, missing client certificates | The database dump and the audit head are byte-for-byte unchanged; the node can still be issued an identity; goroutines and heap do not grow (P1, P2) |
| Rate limit | Flood from one address over TCP | Admitted calls stay within the token-bucket bound; the rest are refused `RESOURCE_EXHAUSTED`; the peer recovers |
| Stalled connections | Up to 512 TCP connections that never handshake | A real node is still served, and each stalled connection is closed by the server |
| Audit fault | Attestation load while a database trigger makes audit appends fail | Failures are `INTERNAL` with no internal detail; every reported success has its row and audit entry; nothing else is recorded; service resumes when the fault clears (P9) |

The flood test is mutation-checked. Removing the enrollment secret check, so
that unauthenticated completions write state, makes it fail.

## Measured (SCALE=10)

Apple Silicon laptop, Go 1.26, SQLite in WAL mode, in-process transport
unless noted.

| Test | Calls | Rate | p50 | p99 |
| ---- | ----- | ---- | --- | --- |
| Challenge + attest | 4,000 | ~1,050/s | 2.1 ms | 180 ms |
| Replay race | 3,200 | ~800/s | 17 ms | 22 ms |
| Workload issuance | 4,000 | ~1,400/s | 0.7 ms | 180 ms |
| Unauthenticated flood | 32,000 | ~6,900/s | 0.4 ms | 21 ms |
| Rate-limited flood (TCP) | 1.39 M | ~70,000/s refused | 0.2 ms | 0.5 ms |
| Attest through audit fault | 10,367 | ~1,150/s | 1.1 ms | 105 ms |

State-changing calls serialise on SQLite's single writer, which accounts for
the p99 tail. Unauthenticated refusals never write, so they cost about a
sixth of an accepted attestation. Rate-limit refusals happen before the
request is read and cost even less.
