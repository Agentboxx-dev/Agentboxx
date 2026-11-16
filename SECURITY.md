# Security Policy

Agentboxx is a tamper-evident flight recorder and security isolation harness for AI agents. Because containment and cryptographic auditability are our core missions, security reports are handled with high priority.

## Supported Versions

Only the current minor release series and the `main` branch receive security patches.

| Version | Supported          | Security Notes |
| ------- | ------------------ | -------------- |
| 0.3.x   | :white_check_mark: | Current release (Docker sandbox, egress proxy, task contracts, Ed25519 receipts) |
| < 0.3   | :x:                | Unsupported; please upgrade to 0.3.0+ |
| main    | :white_check_mark: | Development branch |

---

## Reporting a Vulnerability

Please **do not open a public issue or discussion** for security vulnerabilities.

### Preferred: GitHub Private Vulnerability Reporting
Submit an advisory report through GitHub:
1. Navigate to [Agentboxx Security Advisories](https://github.com/Agentboxx-dev/Agentboxx/security/advisories/new).
2. Click **"Report a vulnerability"**.
3. Include:
   - Vulnerability type and severity assessment.
   - Detailed proof-of-concept (PoC) or reproduction steps.
   - Affected versions, OS, and runtime environment.

### Alternative: Security Contact
If you cannot use GitHub Security Advisories, contact the maintainers directly at:
- **Email:** `security@agentboxx.dev` (or via GitHub: [@Prathmesh010190](https://github.com/Prathmesh010190))

### Response Time & SLA
- **Initial acknowledgment:** Within 48 hours.
- **Triage and reproduction:** Within 5 business days.
- **Fix delivery & coordinated disclosure:** Target 14–30 days depending on severity.

---

## Scope & Trust Boundaries

Agentboxx enforces three explicit trust zones:

### In-Scope Vulnerabilities
- **Sandbox escapes:** Any technique allowing code inside the Docker sandbox to break out, write outside `/workspace`, or affect host files/processes.
- **Audit tampering:** Forging, altering, truncating, or reordering records without invalidating `agentbox verify` or the Ed25519 run receipt.
- **Secret leakage:** Key material (`~/.agentbox/key`, Ed25519 private keys) or unredacted secrets leaking into logs despite configured redaction patterns.
- **File assertion escapes:** Bypassing `_safe_resolve()` / `_safe_read()` using symlinks, hardlinks, FIFOs, device nodes, or path traversal to read host files or cause DoS/OOM.
- **Contract assertion bypasses:** Executing host code from an untrusted workspace via `assert_command` without the explicit `allow_unsafe_host_exec=True` safeguard.
- **Egress proxy bypasses:** Escaping the network proxy to reach non-allowlisted hosts or ports when an `EgressPolicy` is active.

### Out-of-Scope
- **Local Backend execution:** The local backend executes directly on the host with the caller's privileges and has **no isolation boundary**. It is explicitly dev-only and unsupported for untrusted workloads.
- **Host compromise:** Flaws that require prior root/administrator access or physical access to the host machine.
- **Third-party software vulnerabilities:** Zero-days in Docker Engine, containerd, the Linux kernel, or Python runtime (report these upstream).
- **Heuristic secret redaction limits:** RegEx redaction cannot detect completely arbitrary unstructured secrets. If a standard token format is missed, please submit a regular pull request.

---

## Security Practices for Users

1. **Always use the Docker backend for untrusted agents:** Never use the local backend with untrusted models or unreviewed prompts.
2. **Protect your signing keys:** The HMAC secret key (`~/.agentbox/key`) and Ed25519 private key must remain readable only by your host user (`chmod 600`).
3. **Run inside a dedicated VM in production:** For multi-tenant or mission-critical environments, host the Docker daemon inside an ephemeral virtual machine.
