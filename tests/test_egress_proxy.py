"""Tests for the network egress filtering proxy."""

import socket
import urllib.error
import urllib.request
import pytest
from agentbox.egress_proxy import EgressPolicy, EgressProxy


class TestEgressPolicy:
    def test_exact_domain_allowed(self):
        p = EgressPolicy(allowed_domains=["pypi.org"])
        assert p.check("pypi.org")[0] is True

    def test_exact_domain_blocked(self):
        p = EgressPolicy(allowed_domains=["pypi.org"])
        allowed, reason = p.check("evil.com")
        assert allowed is False
        assert reason == "domain_not_allowed"

    def test_wildcard_domain(self):
        p = EgressPolicy(allowed_domains=["*.python.org"])
        assert p.check("docs.python.org")[0] is True
        assert p.check("python.org")[0] is True
        assert p.check("evil.org")[0] is False

    def test_private_ip_blocked(self):
        p = EgressPolicy(allowed_domains=["10.0.0.1"])
        allowed, reason = p.check("10.0.0.1")
        assert allowed is False
        assert reason == "private_ip"

    def test_cloud_metadata_blocked(self):
        p = EgressPolicy(allowed_domains=["169.254.169.254"])
        allowed, reason = p.check("169.254.169.254")
        assert allowed is False
        assert reason == "private_ip"

    def test_localhost_blocked(self):
        p = EgressPolicy(allowed_domains=["127.0.0.1"])
        allowed, reason = p.check("127.0.0.1")
        assert allowed is False
        assert reason == "private_ip"

    def test_case_insensitive(self):
        p = EgressPolicy(allowed_domains=["PyPI.org"])
        assert p.check("pypi.ORG")[0] is True

    def test_block_private_disabled(self):
        p = EgressPolicy(allowed_domains=["10.0.0.1"], block_private=False)
        assert p.check("10.0.0.1")[0] is True

    def test_empty_policy_blocks_all(self):
        p = EgressPolicy(allowed_domains=[])
        assert p.check("example.com")[0] is False

    def test_to_dict_roundtrip(self):
        p = EgressPolicy(allowed_domains=["pypi.org", "*.python.org"])
        d = p.to_dict()
        assert "pypi.org" in d["allowed_domains"]
        assert "*.python.org" in d["allowed_domains"]
        assert d["block_private"] is True


class TestEgressProxy:
    def test_starts_and_stops(self):
        proxy = EgressProxy(EgressPolicy([]), bind="127.0.0.1")
        proxy.start()
        assert proxy.port > 0
        s = socket.socket()
        s.settimeout(2)
        s.connect(("127.0.0.1", proxy.port))
        s.close()
        proxy.stop()

    def test_blocks_disallowed_http(self):
        proxy = EgressProxy(
            EgressPolicy(["allowed.example.com"]), bind="127.0.0.1"
        )
        proxy.start()
        try:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy.url})
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                opener.open("http://blocked.example.com/test", timeout=5)
            assert exc_info.value.code == 403
            events = proxy.drain_events()
            assert len(events) >= 1
            assert events[0]["allowed"] is False
            assert events[0]["host"] == "blocked.example.com"
            assert events[0]["blocked_reason"] == "domain_not_allowed"
        finally:
            proxy.stop()

    def test_drain_clears_queue(self):
        proxy = EgressProxy(EgressPolicy([]), bind="127.0.0.1")
        proxy.start()
        try:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy.url})
            )
            try:
                opener.open("http://any.test/", timeout=2)
            except Exception:
                pass
            first = proxy.drain_events()
            assert len(first) >= 1
            second = proxy.drain_events()
            assert len(second) == 0
        finally:
            proxy.stop()