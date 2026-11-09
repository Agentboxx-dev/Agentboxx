# Verifying logs without Python

`verifiers/go/main.go` is an independent verifier for the [log format](log-format.md). It uses only the Go standard library, so an auditor can build one static binary and check a log without installing Python or any package.

## Build

```bash
cd verifiers/go
go build -o agentbox-verify main.go
```

## Usage

```bash
# Hash chain only
agentbox-verify run.ndjson

# Hash chain + Ed25519 receipt
agentbox-verify run.ndjson --receipt receipt.json --pubkey <64-hex-chars | pubkey-file>

# Also check per-record HMAC signatures and the closing manifest (needs the shared key)
agentbox-verify run.ndjson --key-file ~/.agentbox/key
```

## What is checked

1. Every line parses, `seq` runs 1, 2, 3... with no gaps, and `prev_hash` links to the previous `hash` (the first is 64 zeros).
2. `hash = sha256_hex(prev_hash + sha256_hex(canon(event)))`.
3. With `--receipt`:
   - The supplied Ed25519 public key must be valid and must not represent a low-order point.
   - The Ed25519 signature must verify over `canon(payload)`.
   - `payload.record_count` and `payload.final_hash` must equal the log's last `seq` and `hash`.
   - Invalid signatures and rejected public keys are reported as verification failures.
4. With `--key-file`: each record's HMAC `sig` and the closing manifest are checked.

Numbers are hashed using their original text from the log, so Python's float formatting is reproduced exactly.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Intact |
| 1 | Tampered or corrupt (modified record, altered hash, forged receipt, receipt not matching the log) |
| 2 | Incomplete (never closed) |
| 3 | Bad input (missing file, malformed key, bad arguments) |

## Cross-check in CI

The `cross-verify` job builds the Go binary and runs `python scripts/crosscheck_go.py verifiers/go/agentbox-verify`, which checks that the Python and Go verifiers agree on valid, tampered, forged and truncated logs.