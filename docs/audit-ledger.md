# Audit ledger format and operation

This document specifies the audit ledger precisely enough for an independent
verifier to be written without reading Attest's code. Implementation:
`internal/audit`. Security claims: [security-properties.md](security-properties.md#p8-audit-integrity--implemented).

## Entry

| Field      | Type        | Notes                                                    |
| ---------- | ----------- | -------------------------------------------------------- |
| `seq`      | uint64      | 1-based, contiguous                                      |
| `time`     | timestamp   | UTC, nanosecond precision                                |
| `actor`    | UTF-8 text  | Non-empty authenticated principal, e.g. `operator:alice` |
| `action`   | UTF-8 text  | Non-empty stable operation name, e.g. `node.enroll`      |
| `object`   | UTF-8 text  | Non-empty target, e.g. `node/7f3a…`                       |
| `metadata` | bytes       | Optional, ≤ 64 KiB. MUST NOT contain secret values       |
| `prev_hash`| 32 bytes    | Hash of entry `seq-1`; 32 zero bytes for `seq = 1`       |
| `hash`     | 32 bytes    | See below                                                |

### Canonical body

All integers are unsigned 64-bit big-endian. `field(x)` is `u64(len(x)) || x`.

```
body = u64(seq)
    || u64(time as Unix nanoseconds, two's complement)
    || field(actor)
    || field(action)
    || field(object)
    || field(metadata)          ; empty metadata encodes as u64(0)
```

### Hash

```
hash = SHA-256(prev_hash || body)
```

Including `seq` in the body and `prev_hash` in the digest makes reordering,
insertion and deletion change every subsequent hash. Length prefixes prevent
moving bytes between adjacent fields without changing the hash.

## Checkpoint

A checkpoint signs a ledger head.

```
signed = field("attest/audit/checkpoint/v1")
      || u64(sequence)
      || hash                   ; 32 raw bytes
      || u64(time as Unix nanoseconds)
      || field(key_id)

signature = Ed25519(signing_key, signed)
key_id    = "ed25519:" || hex(SHA-256(raw 32-byte public key)[0:8])
```

Checkpoints with `sequence = 0` are invalid. Files are JSON:

```json
{
  "sequence": 12,
  "hash": "<64 hex chars>",
  "time": "2026-10-17T19:30:00.123456789Z",
  "key_id": "ed25519:0123456789abcdef",
  "signature": "<base64>"
}
```

Keys are PEM: `PRIVATE KEY` (PKCS#8) and `PUBLIC KEY` (PKIX).

## Verification algorithm

1. If no checkpoints are supplied and the caller has not explicitly accepted
   an unanchored result, fail.
2. Verify every checkpoint signature under a trusted key whose ID matches
   `key_id`. Fail on any unknown key, invalid signature, or two checkpoints
   with the same sequence and different hashes.
3. Walk entries from the first. For each entry, with `head` initially
   `(0, zero hash)`:
   - `seq` must equal `head.seq + 1`;
   - `prev_hash` must equal `head.hash`;
   - `hash` must equal `SHA-256(head.hash || body)`;
   - if a checkpoint exists at `seq`, its hash must equal `hash`.
4. After the last entry, `head.seq` must be at least the highest checkpointed
   sequence; otherwise the ledger was truncated or rolled back.

Any error reading entries is a verification failure.

## JSON Lines export

`attestctl audit export` writes one JSON object per line:

```json
{"seq":1,"time":"…Z","actor":"…","action":"…","object":"…","metadata":"<base64, omitted if empty>","prev_hash":"<hex>","hash":"<hex>"}
```

Unknown fields are rejected on import. An export has no integrity of its own;
always verify it against checkpoints.

## Operating procedure

Checkpoints only protect history if the checkpoint key and the checkpoint
files are outside the control plane's reach.

1. **Create an auditor key** on a machine that is not the control plane:

   ```bash
   attestctl audit keygen --key auditor.key --pub auditor.pub
   ```

2. **Obtain the ledger** without trusting `attestd`: copy the database
   (for example with `sqlite3 attest.db "VACUUM INTO 'copy.db'"` or from a
   backup) or run `attestctl audit export` on the control plane and transfer
   the file.

3. **Checkpoint**, chaining from the previous trusted checkpoint so the new
   one only extends verified history:

   ```bash
   attestctl audit checkpoint --db copy.db --key auditor.key \
       --checkpoint cp-previous.json -o cp-$(date +%F).json
   ```

   The very first checkpoint has no predecessor and trusts the ledger as it
   exists at that moment; take it as early as possible.

4. **Store checkpoints** somewhere the control plane administrators cannot
   rewrite: write-once object storage, a separate repository with protected
   history, or printed in a change record.

5. **Verify** whenever the ledger is relied upon, and routinely:

   ```bash
   attestctl audit verify --db copy.db --pubkey auditor.pub \
       --checkpoint cp-2026-10-01.json --checkpoint cp-2026-10-17.json
   ```

   Exit status 0 means verified, 1 means the evidence failed verification, 2
   means the check could not run.

Checkpoint frequency bounds how much recent history can be silently
rewritten. Choose it as a security parameter, not an operational convenience.

## Reproducing the integrity tests

```bash
make race    # unit tests, including tamper cases
make e2e     # attestctl against real database files
```

`e2e/audit_test.go` performs each attack against a real database: editing an
export, restoring an older backup, presenting a checkpoint from an untrusted
key, and dropping the triggers to rewrite and re-hash history.
