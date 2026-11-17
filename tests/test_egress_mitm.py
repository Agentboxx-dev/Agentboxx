"""Tests for the MITM TLS inspection feature (egress_ca + egress_proxy).

CA certificate generation is tested with real cryptography; policy and proxy
integration is tested without network traffic.
"""

from __future__ import annotations

import pytest
from cryptography import x509

from agentbox.egress_ca import EphemeralCA
from agentbox.egress_proxy import EgressPolicy, EgressProxy


# ---- EphemeralCA -----------------------------------------------------------

class TestEphemeralCA:
    def test_ca_cert_is_valid_pem(self):
        ca = EphemeralCA()
        pem = ca.ca_cert_pem
        assert pem.startswith(b"-----BEGIN CERTIFICATE-----")
        cert = x509.load_pem_x509_certificate(pem)
        assert "Agentboxx" in cert.subject.rfc4514_string()

    def test_ca_cert_has_basic_constraints(self):
        ca = EphemeralCA()
        cert = x509.load_pem_x509_certificate(ca.ca_cert_pem)
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True

    def test_host_cert_is_valid_pem(self):
        ca = EphemeralCA()
        cert_pem, key_pem = ca.issue_host_cert("example.com")
        assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
        assert key_pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----")

    def test_host_cert_contains_san(self):
        ca = EphemeralCA()
        cert_pem, _ = ca.issue_host_cert("test.example.com")
        cert = x509.load_pem_x509_certificate(cert_pem)
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "test.example.com" in dns_names

    def test_host_cert_not_ca(self):
        ca = EphemeralCA()
        cert_pem, _ = ca.issue_host_cert("leaf.test")
        cert = x509.load_pem_x509_certificate(cert_pem)
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

    def test_host_cert_cached(self):
        ca = EphemeralCA()
        a = ca.issue_host_cert("cached.test")
        b = ca.issue_host_cert("cached.test")
        assert a == b  # same content from cache

    def test_different_hosts_get_different_certs(self):
        ca = EphemeralCA()
        a_cert, _ = ca.issue_host_cert("a.test")
        b_cert, _ = ca.issue_host_cert("b.test")
        assert a_cert != b_cert


# ---- EgressPolicy with inspect_tls ----------------------------------------

class TestEgressPolicyInspectTls:
    def test_default_is_false(self):
        p = EgressPolicy(allowed_domains=["example.com"])
        assert p.inspect_tls is False

    def test_can_enable(self):
        p = EgressPolicy(allowed_domains=["example.com"], inspect_tls=True)
        assert p.inspect_tls is True

    def test_to_dict_includes_flag(self):
        p = EgressPolicy(allowed_domains=["x.com"], inspect_tls=True)
        assert p.to_dict()["inspect_tls"] is True

    def test_to_dict_false_by_default(self):
        p = EgressPolicy(allowed_domains=["x.com"])
        assert p.to_dict()["inspect_tls"] is False


# ---- EgressProxy CA lifecycle ----------------------------------------------

class TestEgressProxyCA:
    def test_ca_created_when_inspect_tls(self):
        policy = EgressPolicy(allowed_domains=["a.com"], inspect_tls=True)
        proxy = EgressProxy(policy)
        assert proxy.ca_cert_pem is not None
        assert proxy.ca_cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")

    def test_no_ca_when_inspect_tls_disabled(self):
        policy = EgressPolicy(allowed_domains=["a.com"])
        proxy = EgressProxy(policy)
        assert proxy.ca_cert_pem is None
