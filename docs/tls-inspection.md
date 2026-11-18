# TLS Inspection & Body Redaction

## Overview

Agentboxx's egress proxy supports optional **TLS inspection** that
allows it to read, inspect, and redact HTTPS request bodies before
they leave the host.  This prevents agents from leaking secrets
(API keys, tokens, passwords) to allowlisted domains.

## How It Works

1. When `inspect_tls=True`, the proxy generates a short-lived
   **ephemeral root CA** (RSA 2048-bit, valid for 24 hours).
2. The CA certificate is mounted into the Docker container's
   trust store (`/etc/ssl/certs/`).
3. When an agent makes an HTTPS request via CONNECT, the proxy
   terminates TLS using a per-host certificate signed by the
   ephemeral CA, reads the HTTP request, parses JSON bodies,
   runs `redact_value()` on payloads (replacing secrets with
   `[REDACTED:...]` markers), records payload hashes and
   redaction counts in `network.egress` events, then opens a
   fresh TLS connection to the real upstream server and forwards
   the (potentially redacted) request.

## Usage

    from agentbox import EgressPolicy
    from agentbox.egress_proxy import EgressProxy

    policy = EgressPolicy(
        allowed_domains=["api.github.com", "api.openai.com"],
        inspect_tls=True,
    )
    proxy = EgressProxy(policy)
    proxy.start()

    # Mount the CA cert into the container:
    ca_pem = proxy.ca_cert_pem  # bytes
    # Write to /etc/ssl/certs/agentboxx-ca.pem inside the container

    proxy.stop()

## Security Considerations

- The CA private key **never leaves the host process** and is not
  written to disk.
- The CA certificate is valid for only **24 hours**.
- Per-host leaf certificates are valid for only **24 hours** and
  are cached in-memory for the lifetime of the EgressProxy.
- TLS inspection is **opt-in** (inspect_tls=False by default).
  When disabled, the proxy behaves as a transparent CONNECT tunnel.

## Events

Each intercepted request generates a network.egress event:

| Field                   | Description                                |
|-------------------------|--------------------------------------------|
| type                    | Always "network.egress"                    |
| method                  | HTTP method (e.g., POST)                   |
| host                    | Target hostname                            |
| port                    | Target port                                |
| original_payload_hash   | SHA-256 hash of the original request body  |
| redaction_counts        | Dict mapping redaction pattern to count    |
| redacted                | True if any secrets were redacted          |
| ts                      | Unix timestamp                             |
