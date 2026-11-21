# Agentboxx Verify GitHub Action

Automate verification of autonomous agent flight logs and evidence bundles directly in your CI pipeline.

## Usage

Use the action in your GitHub Actions workflow:

```yaml
name: Verify Agent Flight Log

on:
  pull_request:
    branches: [main]

jobs:
  audit-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Verify Agent Execution Log
        uses: Agentboxx-dev/Agentboxx/.github/actions/verify@v1
        with:
          log-path: runs/agent-session.ndjson
```

### With Ed25519 Public-Key Receipt Verification

```yaml
      - name: Verify Signed Evidence Bundle
        uses: Agentboxx-dev/Agentboxx/.github/actions/verify@v1
        with:
          log-path: runs/agent-session.agentbox.zip
          pubkey: ${{ secrets.AGENTBOXX_ED25519_PUBKEY }}
```

## Inputs

| Input | Description | Required | Default |
|---|---|---|---|
| `log-path` | Path to `.ndjson`, `.ndjson.gz`, or `.json.zip` bundle | **Yes** | — |
| `pubkey` | Path or hex string of the Ed25519 public key | No | `""`|
| `key` | HMAC symmetric secret key or path to key file | No | `""` |

## Outputs

| Output | Description |
|---|---|
]| `verified` | `"true"` if log is intact, `"false"` otherwise |
| `exit-code` | Exit code from `agentbox verify` |

## Features

- **Automated PR Check Annotations:** Annotates PR commits with `::notice::` when intact or `::error::` when tampered.
- **GitHub Step Summary:** Posts a verification report card directly to $GITHUB_STEP_SUMMARY.
- **Strict Exit Codes:** Returns exit code 0 on intact logs and non-zero on tampered logs to protect merges.
