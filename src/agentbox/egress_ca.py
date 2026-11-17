"""Ephemeral CA and per-host certificate generation for MITM TLS inspection.

A short-lived root CA is created once per :class:`EphemeralCA` instance.
For every target hostname the proxy intercepts, a leaf certificate signed
by this CA is generated on-the-fly and cached for the lifetime of the
instance.

The CA certificate must be injected into the container's trust store
so that the agent's HTTP client accepts the proxy's certificates.

Security: the CA key never leaves the host process and the CA certificate
is valid for only 24 hours.
"""

from __future__ import annotations

import datetime
from datetime import timezone
import ipaddress
import threading
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class EphemeralCA:
    """Process-scoped root CA that issues per-host leaf certificates."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._ca_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048,
        )
        now = datetime.datetime.now(timezone.utc)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Agentboxx Ephemeral CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Agentboxx"),
        ])
        self._ca_cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self._ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(hours=24))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0), critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(self._ca_key, hashes.SHA256())
        )
        self._host_cache: dict[str, Tuple[bytes, bytes]] = {}

    @property
    def ca_cert_pem(self) -> bytes:
        """PEM-encoded CA certificate (mount this inside the container)."""
        return self._ca_cert.public_bytes(serialization.Encoding.PEM)

    def issue_host_cert(self, hostname: str) -> Tuple[bytes, bytes]:
        """Return ``(cert_pem, key_pem)`` for *hostname*, cached per instance."""
        with self._lock:
            if hostname in self._host_cache:
                return self._host_cache[hostname]

        host_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048,
        )
        now = datetime.datetime.now(timezone.utc)
        san_names: list[x509.GeneralName] = [x509.DNSName(hostname)]
        try:
            san_names.append(x509.IPAddress(ipaddress.ip_address(hostname)))
        except ValueError:
            pass

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ]))
            .issuer_name(self._ca_cert.subject)
            .public_key(host_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(hours=24))
            .add_extension(
                x509.SubjectAlternativeName(san_names), critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(self._ca_key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = host_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with self._lock:
            self._host_cache[hostname] = (cert_pem, key_pem)
        return cert_pem, key_pem
