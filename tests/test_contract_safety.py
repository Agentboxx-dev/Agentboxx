"""End-to-end security regression tests for TaskContract assertions (Issue #55)."""
import hashlib
import os
import sys
import pytest
from agentbox.contract import assert_file_contains, assert_file_exists, assert_file_hash

# ── End-to-end: Assertion.check() with attack fixtures ───────────

class TestFileAssertionsSecurity:

    def test_symlink_outside_workspace_rejected(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        secret = tmp_path / "secret.key"
        secret.write_text("TOP SECRET", encoding="utf-8")
        (ws / "result.txt").symlink_to(secret)

        for a in [
            assert_file_exists("result.txt"),
            assert_file_contains("result.txt", r".*"),
            assert_file_hash("result.txt", "a" * 64),
        ]:
            res = a.check(ws)
            assert res.passed is False, f"{a.kind} should fail on symlink"
            assert "SECURITY" in res.details

    def test_symlink_within_workspace_also_rejected(self, tmp_path):
        """Even symlinks pointing inside the workspace are rejected (strict)."""
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "real.txt").write_text("data", encoding="utf-8")
        (ws / "link.txt").symlink_to(ws / "real.txt")

        res = assert_file_contains("link.txt", r"data").check(ws)
        assert res.passed is False
        assert "SECURITY" in res.details

    def test_symlinked_intermediate_dir_rejected(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "loot.txt").write_text("stolen", encoding="utf-8")
        (ws / "subdir").symlink_to(outside)

        res = assert_file_exists("subdir/loot.txt").check(ws)
        assert res.passed is False
        assert "SECURITY" in res.details

    def test_dotdot_traversal_rejected(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (tmp_path / "outside.txt").write_text("nope", encoding="utf-8")

        for a in [
            assert_file_exists("../outside.txt"),
            assert_file_contains("../outside.txt", r".*"),
            assert_file_hash("../outside.txt", "a" * 64),
        ]:
            res = a.check(ws)
            assert res.passed is False, f"{a.kind} should reject traversal"
            assert "SECURITY" in res.details

    def test_absolute_path_rejected(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()

        for a in [
            assert_file_exists("/etc/passwd"),
            assert_file_contains("/etc/passwd", r"root"),
            assert_file_hash("/etc/passwd", "a" * 64),
        ]:
            res = a.check(ws)
            assert res.passed is False
            assert "SECURITY" in res.details

    @pytest.mark.skipif(sys.platform == "win32", reason="FIFOs are Unix-only")
    def test_fifo_does_not_hang_and_is_rejected(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        os.mkfifo(ws / "trap.fifo")

        for a in [
            assert_file_exists("trap.fifo"),
            assert_file_contains("trap.fifo", r".*"),
            assert_file_hash("trap.fifo", "a" * 64),
        ]:
            res = a.check(ws)
            assert res.passed is False, f"{a.kind} should reject FIFO"
            assert "SECURITY" in res.details

    def test_oversized_file_rejected(self, tmp_path, monkeypatch):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "huge.bin").write_bytes(b"x" * 2000)

        monkeypatch.setattr("agentbox.contract.MAX_ASSERT_FILE_BYTES", 1000)

        for a in [
            assert_file_contains("huge.bin", r"x"),
            assert_file_hash("huge.bin", "a" * 64),
        ]:
            res = a.check(ws)
            assert res.passed is False, f"{a.kind} should reject oversized"
            assert "SECURITY" in res.details

    def test_oversized_file_exists_still_passes(self, tmp_path, monkeypatch):
        """file_exists does not read content, so size cap doesn't apply."""
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "huge.bin").write_bytes(b"x" * 2000)

        monkeypatch.setattr("agentbox.contract.MAX_ASSERT_FILE_BYTES", 1000)
        assert assert_file_exists("huge.bin").check(ws).passed is True


# ── No false positives ───────────────────────────────────────────

class TestLegitimateFilesStillPass:

    def test_regular_file_passes_all_assertions(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        content = b"ANSWER=42\n"
        (ws / "result.txt").write_bytes(content)
        h = hashlib.sha256(content).hexdigest()

        assert assert_file_exists("result.txt").check(ws).passed is True
        assert assert_file_contains("result.txt", r"ANSWER=42").check(ws).passed is True
        assert assert_file_hash("result.txt", h).check(ws).passed is True

    def test_nested_file_in_subdirectory(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "sub").mkdir()
        (ws / "sub" / "out.txt").write_text("ok", encoding="utf-8")

        assert assert_file_exists("sub/out.txt").check(ws).passed is True
        assert assert_file_contains("sub/out.txt", r"ok").check(ws).passed is True

    def test_directory_passes_file_exists(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "outdir").mkdir()

        assert assert_file_exists("outdir").check(ws).passed is True

    def test_missing_file_is_a_clean_failure_not_security(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()

        res = assert_file_exists("nope.txt").check(ws)
        assert res.passed is False
        assert "SECURITY" not in res.details
        assert "does not exist" in res.details

        res2 = assert_file_contains("nope.txt", r"x").check(ws)
        assert res2.passed is False
        assert "SECURITY" not in res2.details
        assert "not found" in res2.details
