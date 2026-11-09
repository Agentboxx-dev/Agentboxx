"""Lightweight HTTP/HTTPS forward proxy with domain allowlist for sandbox egress.

Runs on the host as a daemon thread. Docker containers route traffic through
it via HTTP_PROXY / HTTPS_PROXY environment variables. Domain filtering on
HTTPS inspects the CONNECT hostname (SNI) without TLS interception.

Limitations
-----------
- Soft enforcement. Programs that ignore proxy env-vars can bypass the filter.
  For hard enforcement use ``--network none`` (fully offline).
- HTTPS filtering sees only the hostname from the CONNECT request, not the
  full URL or request body (no TLS interception / MITM).
"""

import http.server
import queue
import select
import socket
import socketserver
import threading
import time
import urllib.parse
import urllib.request
from ipaddress import ip_address, ip_network

# Private / reserved networks blocked by default
_BLOCKED_NETWORKS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),  # cloud metadata lives here
    ip_network("::1/128"),
    ip_network("fc00::/7"),
    ip_network("fe80::/10"),
]


def _is_private(addr_str: str) -> bool:
    try:
        return any(ip_address(addr_str) in net for net in _BLOCKED_NETWORKS)
    except ValueError:
        return False


class EgressPolicy:
    """Which domains are allowed for outbound connections."""

    def __init__(
        self,
        allowed_domains: list[str] | None = None,
        block_private: bool = True,
    ):
        self.allowed_domains: set[str] = set()
        self.wildcard_suffixes: list[str] = []
        self.block_private = block_private
        for d in (allowed_domains or []):
            d = d.lower().strip()
            if d.startswith("*."):
                self.wildcard_suffixes.append(d[2:])
            else:
                self.allowed_domains.add(d)

    def check(self, hostname: str, port: int = 443) -> tuple[bool, str | None]:
        """Return *(allowed, blocked_reason)*."""
        hostname = hostname.lower().strip()
        if ":" in hostname and not hostname.startswith("["):
            hostname = hostname.rsplit(":", 1)[0]
        if self.block_private and _is_private(hostname):
            return False, "private_ip"
        if self.block_private:
            try:
                for *_, addr in socket.getaddrinfo(
                    hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM
                ):
                    if _is_private(addr[0]):
                        return False, "resolves_to_private_ip"
            except socket.gaierror:
                pass
        if hostname in self.allowed_domains:
            return True, None
        for suffix in self.wildcard_suffixes:
            if hostname == suffix or hostname.endswith("." + suffix):
                return True, None
        return False, "domain_not_allowed"

    def to_dict(self) -> dict:
        domains = sorted(self.allowed_domains)
        domains.extend(f"*.{s}" for s in sorted(self.wildcard_suffixes))
        return {
            "allowed_domains": domains,
            "block_private": self.block_private,
        }


class _ProxyHandler(http.server.BaseHTTPRequestHandler):
    policy: EgressPolicy
    event_queue: "queue.Queue[dict]"

    def log_message(self, fmt, *args):  # silence stderr
        pass

    def _emit(self, method, host, port, allowed, reason=None):
        self.event_queue.put(
            {
                "method": method,
                "host": host,
                "port": port,
                "allowed": allowed,
                "blocked_reason": reason,
                "ts": time.time(),
            }
        )

    def do_CONNECT(self):
        host, _, port_s = self.path.partition(":")
        port = int(port_s) if port_s else 443
        allowed, reason = self.policy.check(host, port)
        self._emit("CONNECT", host, port, allowed, reason)
        if not allowed:
            self.send_error(403, f"Blocked: {reason}")
            return
        try:
            upstream = socket.create_connection((host, port), timeout=30)
        except OSError as exc:
            self.send_error(502, f"Upstream unreachable: {exc}")
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        _splice(self.connection, upstream)
        upstream.close()

    def _forward(self):
        parsed = urllib.parse.urlparse(self.path)
        host = parsed.hostname or ""
        port = parsed.port or 80
        allowed, reason = self.policy.check(host, port)
        self._emit(self.command, host, port, allowed, reason)
        if not allowed:
            self.send_error(403, f"Blocked: {reason}")
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length > 0 else None
            headers = {
                k: v
                for k, v in self.headers.items()
                if k.lower() not in ("proxy-connection", "host")
            }
            req = urllib.request.Request(
                self.path, data=body, headers=headers, method=self.command
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                self.send_response(resp.status)
                for k, v in resp.headers.items():
                    if k.lower() != "transfer-encoding":
                        self.send_header(k, v)
                self.end_headers()
                while chunk := resp.read(65536):
                    self.wfile.write(chunk)
        except Exception as exc:
            self.send_error(502, str(exc)[:200])

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _forward


def _splice(a: socket.socket, b: socket.socket, timeout: float = 120):
    a.setblocking(False)
    b.setblocking(False)
    try:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            readable, _, _ = select.select([a, b], [], [a, b], 5.0)
            for s in readable:
                other = b if s is a else a
                try:
                    data = s.recv(65536)
                    if not data:
                        return
                    other.sendall(data)
                except (BlockingIOError, ConnectionError, OSError):
                    return
    except (OSError, ValueError):
        pass


class EgressProxy:
    """Threaded forward proxy. Start before the Docker container, stop after."""

    def __init__(
        self, policy: EgressPolicy, bind: str = "0.0.0.0", port: int = 0
    ):
        self.policy = policy
        self.bind = bind
        self.port = port
        self.events: queue.Queue[dict] = queue.Queue()
        self._server: socketserver.ThreadingTCPServer | None = None

    def start(self):
        cls = type(
            "H",
            (_ProxyHandler,),
            {"policy": self.policy, "event_queue": self.events},
        )
        self._server = socketserver.ThreadingTCPServer(
            (self.bind, self.port), cls
        )
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def drain_events(self) -> list[dict]:
        out: list[dict] = []
        while not self.events.empty():
            try:
                out.append(self.events.get_nowait())
            except queue.Empty:
                break
        return out

    @property
    def url(self) -> str:
        return f"http://{self.bind}:{self.port}"