"""Tests for the evidence bundle feature (Issue #33)."""
import hashlib
import hmac as hmac_mod
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

from agentbox.bundle import create_bundle, extract_bundle, is_bundle
from agentbox.signer import load_or_create_key, verify_log


GENESIS = "0" * 64


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def _write_log(path, key, *, events=None, write_manifest=True):
    """Create a minimal valid agentbox log with a correct hash chain."""
    if events is None:
        events = [
            ("session.start", {"session_id": "test", "isolation": {"backend": "local"}}),
            ("step", {
                "session_id": "test", "step_index": 1, "thought": "think",
                "command": "echo hi", "command_fingerprint": "echo",
                "exit_code": 0, "timed_out": False,
                "stdout": {"text": "hi", "total_chars": 2, "total_bytes": 2,
                           "truncated": False, "sha256": _sha("hi")},
                "stderr": {"text": "", "total_chars": 0, "total_bytes": 0,
                           "truncated": False, "sha256": _sha("")},
                "error_signature": None, "error_class": None,
                "workspace_hash": _sha("ws"), "duration_ms": 10,
            }),
            ("session.end", {"reason": "done", "steps": 1}),
        ]

    prev = GENESIS
    lines = []
    for seq, (etype, data) in enumerate(events, 1):
        ev = {
            "schema_version": "1.0",
            "event_id": f"evt-{seq}",
            "event_type": etype,
            "ts": 1700000000.0 + seq,
            "seq": seq,
            "data": data,
        }
        ev_hash = _sha(_canon(ev).encode())
        h = _sha((prev + ev_hash).encode())
        sig = hmac_mod.new(key, h.encode(), hashlib.sha256).hexdigest()
        lines.append(json.dumps({
            "event": ev, "prev_hash": prev, "hash": h, "sig": sig,
        }))
        prev = h

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    if write_manifest:
        payload = {"records": len(events), "final_hash": prev}
        msig = hmac_mod.new(
            key, _canon(payload).encode(), hashlib.sha256
        ).hexdigest()
        mpath = path.with_name(path.stem + ".manifest.json")
        mpath.write_text(json.dumps({"payload": payload, "sig": msig}), encoding="utf-8")

    return prev


# ── is_bundle ─────────────────────────────────────────────────────

class TestIsBundle:
    def test_zip(self):
        assert is_bundle("evidence.zip")

    def test_tar_gz(self):
        assert is_bundle("evidence.tar.gz")

    def test_tgz(self):
        assert is_bundle("evidence.tgz")

    def test_ndjson_is_not_bundle(self):
        assert not is_bundle("log.ndjson")

    def test_random_file(self):
        assert not is_bundle("notes.txt")


# ── create_bundle ─────────────────────────────────────────────────

class TestCreateBundle:
    def test_creates_zip_with_expected_files(self, tmp_path):
        key = load_or_create_key(tmp_path / "key")
        log = tmp_path / "test.ndjson"
        _write_log(log, key)

        bundle = create_bundle(log, fmt="zip")
        assert bundle.exists()
        assert bundle.suffix == ".zip"

        with zipfile.ZipFile(bundle) as zf:
            names = set(zf.namelist())
        assert "audit.ndjson" in names
        assert "manifest.json" in names
        assert "viewer.html" in names
        assert "AUDIT_INSTRUCTIONS.md" in names

    def test_creates_tar_gz(self, tmp_path):
        key = load_or_create_key(tmp_path / "key")
        log = tmp_path / "test.ndjson"
        _write_log(log, key)

        bundle = create_bundle(log, fmt="tar.gz")
        assert bundle.exists()
        assert bundle.name.endswith(".tar.gz")

        with tarfile.open(bundle) as tf:
            names = set(tf.getnames())
        assert "audit.ndjson" in names
        assert "viewer.html" in names

    def test_custom_output_path(self, tmp_path):
        key = load_or_create_key(tmp_path / "key")
        log = tmp_path / "test.ndjson"
        _write_log(log, key)

        out = tmp_path / "my-evidence.zip"
        bundle = create_bundle(log, output=str(out))
        assert bundle == out
        assert out.exists()

    def test_includes_pubkey_when_provided(self, tmp_path):
        key = load_or_create_key(tmp_path / "key")
        log = tmp_path / "test.ndjson"
        _write_log(log, key)

        pub = tmp_path / "ed25519.pub"
        pub.write_text("ab" * 32, encoding="utf-8")

        bundle = create_bundle(log, pubkey_path=str(pub))
        with zipfile.ZipFile(bundle) as zf:
            assert "public.key" in zf.namelist()
            assert zf.read("public.key").decode().strip() == "ab" * 32

    def test_rejects_hmac_key_file(self, tmp_path):
        key = load_or_create_key(tmp_path / "key")
        log = tmp_path / "test.ndjson"
        _write_log(log, key)

        with pytest.raises(ValueError, match="private or HMAC key"):
            create_bundle(log, pubkey_path=str(tmp_path / "key"))

    def test_rejects_ed25519_private_key_by_name(self, tmp_path):
        key = load_or_create_key(tmp_path / "key")
        log = tmp_path / "test.ndjson"
        _write_log(log, key)

        bad = tmp_path / "ed25519.key"
        bad.write_text("secret", encoding="utf-8")

        with pytest.raises(ValueError, match="private or HMAC key"):
            create_bundle(log, pubkey_path=str(bad))

    def test_rejects_pem_private_key_by_content(self, tmp_path):
        key = load_or_create_key(tmp_path / "key")
        log = tmp_path / "test.ndjson"
        _write_log(log, key)

        priv = tmp_path / "mykey.pem"
        priv.write_text("-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n")

        with pytest.raises(ValueError, match="private key marker"):
            create_bundle(log, pubkey_path=str(priv))

    def test_missing_log_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            create_bundle(tmp_path / "nope.ndjson")

    def test_bad_format_raises(self, tmp_path):
        key = load_or_create_key(tmp_path / "key")
        log = tmp_path / "test.ndjson"
        _write_log(log, key)

        with pytest.raises(ValueError, match="unsupported format"):
            create_bundle(log, fmt="rar")

    def test_includes_contract_json_when_present(self, tmp_path):
        key = load_or_create_key(tmp_path / "key")
        log = tmp_path / "test.ndjson"
        events = [
            ("session.start", {
                "session_id": "test", "isolation": {"backend": "local"},
                "contract": {"goal": "make it work", "assertions": []},
            }),
            ("contract.verdict", {
                "passed": True, "summary": "all good", "assertions": [],
            }),
            ("session.end", {"reason": "done", "steps": 0}),
        ]
        _write_log(log, key, events=events)

        bundle = create_bundle(log)
        with zipfile.ZipFile(bundle) as zf:
            assert "contract.json" in zf.namelist()
            contract = json.loads(zf.read("contract.json"))
            assert contract["verdict"]["passed"] is True
            assert contract["definition"]["goal"] == "make it work"

    def test_no_contract_json_when_absent(self, tmp_path):
        key = load_or_create_key(tmp_path / "key")
        log = tmp_path / "test.ndjson"
        _write_log(log, key)

        bundle = create_bundle(log)
        with zipfile.ZipFile(bundle) as zf:
            assert "contract.json" not in zf.namelist()

    def test_viewer_html_is_self_contained(self, tmp_path):
        key = load_or_create_key(tmp_path / "key")
        log = tmp_path / "test.ndjson"
        _write_log(log, key)

        bundle = create_bundle(log)
        with zipfile.ZipFile(bundle) as zf:
            html = zf.read("viewer.html").decode()
        assert "<html" in html.lower()

    def test_verify_standalone_included_when_available(self, tmp_path):
        key = load_or_create_key(tmp_path / "key")
        log = tmp_path / "test.ndjson"
        _write_log(log, key)

        bundle = create_bundle(log)
        with zipfile.ZipFile(bundle) as zf:
            names = zf.namelist()
        # verify.py is only present when running from the source tree
        if (Path(__file__).resolve().parent.parent / "examples" / "verify_standalone.py").exists():
            assert "verify.py" in names

    def test_default_output_name(self, tmp_path):
        key = load_or_create_key(tmp_path / "key")
        log = tmp_path / "my-session.ndjson"
        _write_log(log, key)

        bundle = create_bundle(log)
        assert bundle.name == "evidence-my-session.zip"


# ── extract_bundle ────────────────────────────────────────────────

class TestExtractBundle:
    def test_roundtrip_zip(self, tmp_path):
        key = load_or_create_key(tmp_path / "key")
        log = tmp_path / "test.ndjson"
        _write_log(log, key)

        bundle = create_bundle(log, fmt="zip")
        dest = extract_bundle(bundle, dest=str(tmp_path / "out"))
        assert (dest / "audit.ndjson").exists()
        assert (dest / "viewer.html").exists()
        assert (dest / "AUDIT_INSTRUCTIONS.md").exists()

    def test_roundtrip_tar_gz(self, tmp_path):
        key = load_or_create_key(tmp_path / "key")
        log = tmp_path / "test.ndjson"
        _write_log(log, key)

        bundle = create_bundle(log, fmt="tar.gz")
        dest = extract_bundle(bundle, dest=str(tmp_path / "out"))
        assert (dest / "audit.ndjson").exists()

    def test_rejects_path_traversal_in_zip(self, tmp_path):
        bad_zip = tmp_path / "evil.zip"
        with zipfile.ZipFile(bad_zip, "w") as zf:
            zf.writestr("../../../etc/passwd", "pwned")

        with pytest.raises(ValueError, match="path traversal"):
            extract_bundle(bad_zip, dest=str(tmp_path / "out"))

    def test_unsupported_format_raises(self, tmp_path):
        f = tmp_path / "data.rar"
        f.write_bytes(b"not a real archive")

        with pytest.raises(ValueError, match="unsupported archive"):
            extract_bundle(f)

    def test_missing_bundle_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            extract_bundle(tmp_path / "nope.zip")

    def test_extracted_log_verifies_with_hmac(self, tmp_path):
        """The extracted audit.ndjson must still pass full HMAC verification."""
        key = load_or_create_key(tmp_path / "key")
        log = tmp_path / "test.ndjson"
        _write_log(log, key)

        bundle = create_bundle(log)
        dest = extract_bundle(bundle, dest=str(tmp_path / "out"))

        # Rename manifest to match the extracted log name (audit.ndjson → audit.manifest.json)
        bundled_manifest = dest / "manifest.json"
        if bundled_manifest.exists():
            bundled_manifest.rename(dest / "audit.manifest.json")

        problems, incomplete = verify_log(dest / "audit.ndjson", key)
        assert problems == []
        assert incomplete == []


# ── CLI integration ───────────────────────────────────────────────

class TestCLIBundle:
    def test_cli_bundle_creates_zip(self, tmp_path):
        from agentbox.cli import main

        key = load_or_create_key(tmp_path / "key")
        log = tmp_path / "test.ndjson"
        _write_log(log, key)

        out = tmp_path / "evidence.zip"
        code = main(["bundle", str(log), "-o", str(out)])
        assert code == 0
        assert out.exists()
        with zipfile.ZipFile(out) as zf:
            assert "audit.ndjson" in zf.namelist()

    def test_cli_bundle_creates_tar_gz(self, tmp_path):
        from agentbox.cli import main

        key = load_or_create_key(tmp_path / "key")
        log = tmp_path / "test.ndjson"
        _write_log(log, key)

        out = tmp_path / "evidence.tar.gz"
        code = main(["bundle", str(log), "-o", str(out), "-f", "tar.gz"])
        assert code == 0
        assert out.exists()

    def test_cli_verify_accepts_zip_bundle(self, tmp_path):
        from agentbox.cli import main

        key_path = tmp_path / "key"
        key = load_or_create_key(key_path)
        log = tmp_path / "test.ndjson"
        _write_log(log, key)

        bundle = create_bundle(log, fmt="zip")
        code = main(["verify", str(bundle), "-k", str(key_path)])
        assert code == 0

    def test_cli_verify_accepts_tar_gz_bundle(self, tmp_path):
        from agentbox.cli import main

        key_path = tmp_path / "key"
        key = load_or_create_key(key_path)
        log = tmp_path / "test.ndjson"
        _write_log(log, key)

        bundle = create_bundle(log, fmt="tar.gz")
        code = main(["verify", str(bundle), "-k", str(key_path)])
        assert code == 0

    def test_cli_bundle_rejects_missing_log(self, tmp_path):
        from agentbox.cli import main

        code = main(["bundle", str(tmp_path / "nope.ndjson")])
        assert code != 0
