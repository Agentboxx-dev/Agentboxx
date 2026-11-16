"""Security regression tests for safe file assertions (Issue #55).

Every attack vector from the threat model gets a dedicated test:
  - symlinks (final component and intermediate directory)
  - path traversal (../ and sibling-prefix)
  - absolute paths
  - FIFOs / named pipes (must never hang)
  - oversized files (host OOM prevention)
  - normal files still pass (no false positives)
"""
import os
import sys

import pytest

from agentbox.contract import (
    UnsafePath,
    _safe_lstat,
    _safe_read,
    _safe_resolve,
)


# ── _safe_resolve unit tests ─────────────────────────────────────

class TestSafeResolve:
    def test_normal_relative_path(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        assert _safe_resolve(ws, "file.txt") == ws / "file.txt"

    def test_nested_relative_path(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        assert _safe_resolve(ws, "sub/dir/file.txt") == ws / "sub" / "dir" / "file.txt"

    def test_rejects_absolute_path(self, tmp_path):
        with pytest.raises(UnsafePath, match="absolute"):
            _safe_resolve(tmp_path, "/etc/passwd")

    def test_rejects_dotdot_traversal(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        with pytest.raises(UnsafePath, match="escapes workspace"):
            _safe_resolve(ws, "../../etc/passwd")

    def test_rejects_sibling_via_traversal(self, tmp_path):
        ws = tmp_path / "workspace"
        ws.mkdir()
        (tmp_path / "workspace-evil").mkdir()
        with pytest.raises(UnsafePath, match="escapes workspace"):
            _safe_resolve(ws, "../workspace-evil/secret.txt")

    def test_rejects_symlinked_intermediate_directory(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("steal me", encoding="utf-8")
        (ws / "escape").symlink_to(outside)

        with pytest.raises(UnsafePath, match="escapes workspace via symlink"):
            _safe_resolve(ws, "escape/secret.txt")


# ── _safe_read unit tests ────────────────────────────────────────

class TestSafeRead:
    def test_reads_normal_file(self, tmp_path):
        f = tmp_path / "ok.txt"
        f.write_text("hello", encoding="utf-8")
        assert _safe_read(f) == b"hello"

    def test_rejects_symlink(self, tmp_path):
        real = tmp_path / "real.txt"
        real.write_text("secret", encoding="utf-8")
        link = tmp_path / "link.txt"
        link.symlink_to(real)
        with pytest.raises(UnsafePath, match="symlink"):
            _safe_read(link)

    @pytest.mark.skipif(sys.platform == "win32", reason="FIFOs are Unix-only")
    def test_rejects_fifo(self, tmp_path):
        fifo = tmp_path / "trap.fifo"
        os.mkfifo(fifo)
        with pytest.raises(UnsafePath, match="FIFO"):
            _safe_read(fifo)

    def test_rejects_oversized_file(self, tmp_path):
        f = tmp_path / "big.bin"
        f.write_bytes(b"x" * 200)
        with pytest.raises(UnsafePath, match="too large"):
            _safe_read(f, max_bytes=100)

    def test_missing_file_raises_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            _safe_read(tmp_path / "nope.txt")


# ── _safe_lstat unit tests ───────────────────────────────────────

class TestSafeLstat:
    def test_accepts_regular_file(self, tmp_path):
        f = tmp_path / "ok.txt"
        f.write_text("ok", encoding="utf-8")
        st = _safe_lstat(f)
        assert st is not None

    def test_accepts_directory(self, tmp_path):
        d = tmp_path / "dir"
        d.mkdir()
        st = _safe_lstat(d)
        assert st is not None

    def test_rejects_symlink(self, tmp_path):
        real = tmp_path / "real.txt"
        real.write_text("ok", encoding="utf-8")
        link = tmp_path / "link.txt"
        link.symlink_to(real)
        with pytest.raises(UnsafePath, match="symlink"):
            _safe_lstat(link)

    @pytest.mark.skipif(sys.platform == "win32", reason="FIFOs are Unix-only")
    def test_rejects_fifo(self, tmp_path):
        fifo = tmp_path / "trap.fifo"
        os.mkfifo(fifo)
        with pytest.raises(UnsafePath, match="FIFO"):
            _safe_lstat(fifo)


