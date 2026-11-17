"""MITM TLS handler: terminate, inspect, redact, and forward HTTPS requests.

Called by :class:`~agentbox.egress_proxy._ProxyHandler` when ``inspect_tls``
is enabled.  The handler:

1. Accepts the inbound TLS handshake using a per-host certificate signed by
   the ephemeral CA.
2. Reads the HTTP request and parses JSON bodies.
3. Runs :func:`~agentbox.redact.redact_value` on JSON payloads, replacing
   secrets with ``[REDACTED:...]`` markers.
4. Records payload hashes and redaction counts in ``network.egress`` events.
5. Opens a fresh TLS connection to the real upstream and forwards the
   (potentially modified) request.
6. Streams the upstream response back to the agent.
"""

from __future__ import annotations

import hashlib
import json
import logging
import queue
import socket
import ssl
import tempfile
import time
from pathlib import Path

from .egress_ca import EphemeralCA
from .redact import redact_value

log = logging.getLogger(__name__)


def _write_temp_pem(data: bytes, suffix: str) -> str:
    """Write PEM bytes to a named temp file; caller must delete it."""
    tmp = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    tmp.write(data)
    tmp.close()
    return tmp.name


def mitm_intercept(
    client_sock: socket.socket,
    host: str,
    port: int,
    ca: EphemeralCA,
    event_queue: "queue.Queue[dict]",
) -> None:
    """Terminate TLS, inspect/redact the request body, and forward upstream."""
    cert_pem, key_pem = ca.issue_host_cert(host)
    cert_path = _write_temp_pem(cert_pem, ".crt")
    key_path = _write_temp_pem(key_pem, ".key")

    try:
        _do_mitm(client_sock, host, port, cert_path, key_path, event_queue)
    finally:
        Path(cert_path).unlink(missing_ok=True)
        Path(key_path).unlink(missing_ok=True)


def _do_mitm(
    client_sock: socket.socket,
    host: str,
    port: int,
    cert_path: str,
    key_path: str,
    event_queue: "queue.Queue[dict]",
) -> None:
    # --- inbound TLS (proxy acts as server) --------------------------------
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

    try:
        tls_in = server_ctx.wrap_socket(client_sock, server_side=True)
    except ssl.SSLError as exc:
        log.debug("MITM: TLS handshake with client failed: %s", exc)
        return

    try:
        # --- read request -----------------------------------------------------
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = tls_in.recv(65536)
            if not chunk:
                return
            raw += chunk

        header_blob, _, body = raw.partition(b"\r\n\r\n")
        header_lines = header_blob.split(b"\r\n")
        request_line = header_lines[0].decode("utf-8", errors="replace")
        parts = request_line.split(" ", 2)
        if len(parts) < 3:
            return
        method, path, http_ver = parts

        headers: dict[str, str] = {}
        for line in header_lines[1:]:
            k, _, v = line.partition(b": ")
            headers[k.decode("utf-8", errors="replace").lower()] = (
                v.decode("utf-8", errors="replace").strip()
            )

        # Read remaining body bytes if Content-Length says there is more.
        content_length = int(headers.get("content-length", "0") or "0")
        while len(body) < content_length:
            chunk = tls_in.recv(65536)
            if not chunk:
                break
            body += chunk

        # --- redact JSON bodies -----------------------------------------------
        redaction_counts: dict[str, int] = {}
        original_hash = hashlib.sha256(body).hexdigest()

        content_type = headers.get("content-type", "")
        if "application/json" in content_type and body:
            try:
                parsed = json.loads(body)
                cleaned, redaction_counts = redact_value(parsed)
                if redaction_counts:
                    body = json.dumps(cleaned, separators=(",", ":")).encode()
                    headers["content-length"] = str(len(body))
            except (json.JSONDecodeError, TypeError) as exc:
                log.debug("MITM: JSON redaction skipped: %s", exc)

        # --- record event -----------------------------------------------------
        event_queue.put({
            "type": "network.egress",
            "method": method,
            "host": host,
            "port": port,
            "original_payload_hash": original_hash,
            "redaction_counts": redaction_counts,
            "redacted": bool(redaction_counts),
            "ts": time.time(),
        })

        # --- re-assemble request ----------------------------------------------
        req_line = f"{method} {path} {http_ver}\r\n".encode()
        hdr_block = b"".join(
            f"{k}: {v}\r\n".encode() for k, v in headers.items()
        )
        outbound = req_line + hdr_block + b"\r\n" + body

        # --- forward upstream (real TLS) --------------------------------------
        client_ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=30) as raw_up:
            with client_ctx.wrap_socket(raw_up, server_hostname=host) as tls_out:
                tls_out.sendall(outbound)
                while True:
                    resp = tls_out.recv(65536)
                    if not resp:
                        break
                    tls_in.sendall(resp)

    except (OSError, ssl.SSLError) as exc:
        log.debug("MITM: relay error: %s", exc)
    finally:
        try:
            tls_in.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        tls_in.close()
