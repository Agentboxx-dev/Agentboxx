"""Tests for crash-safe session finalization and post-mortem recovery (Issue #94)."""
import json

import pytest
from agentbox import Recorder
from agentbox.cli import EXIT_INCOMPLETE, EXIT_OK, EXIT_TAMPERED, main as cli_main
from agentbox.signer import (
    generate_ed25519_keypair,
    load_or_create_key,
    manifest_path,
    receipt_path,
    recover_log,
    verify_file,
    verify_log,
)


def test_unclosed_session_reports_incomplete(tmp_path):
    """A session that crashes without close() lacks session.end and manifest, failing verify with EXIT_INCOMPLETE."""
    key = load_or_create_key(tmp_path / "key")
    rec = Recorder("crash-sess-1", log_dir=str(tmp_path), key_path=tmp_path / "key")
    rec.run("echo step1")
    rec.run("echo step2")
    # Simulate abrupt SIGKILL / crash: close() is never called

    problems, incomplete = verify_log(rec.log_path, key)
    assert not problems, f"Hash chain prior to crash should be intact, got: {problems}"
    assert incomplete, "Unclosed session should report incomplete issues"

    # CLI verify returns EXIT_INCOMPLETE
    code = cli_main(["verify", str(rec.log_path), "--key", str(tmp_path / "key")])
    assert code == EXIT_INCOMPLETE


def test_recover_hard_killed_session(tmp_path, capsys):
    """Hard-killed session can be recovered via agentbox recover, and verifies with exit code 0."""
    key_path = tmp_path / "key"
    key = load_or_create_key(key_path)

    rec = Recorder("crash-sess-2", log_dir=str(tmp_path), key_path=key_path)
    rec.run("echo working")
    rec.run("echo critical_step")
    # Hard crash - no close()

    log_path = rec.log_path

    # Run agentbox recover CLI
    recover_code = cli_main(["recover", str(log_path), "--key", str(key_path)])
    assert recover_code == EXIT_OK
    captured = capsys.readouterr()
    assert "Session recovered" in captured.out

    # After recovery, manifest exists and has status interrupted
    mp = manifest_path(log_path)
    assert mp.exists()
    m_data = json.loads(mp.read_text(encoding="utf-8"))
    assert m_data["payload"].get("status") == "interrupted"

    # Verify log programmatically
    problems, incomplete = verify_log(log_path, key)
    assert not problems, f"Recovered log had problems: {problems}"
    assert not incomplete, f"Recovered log had incomplete: {incomplete}"

    # Verify via CLI returns EXIT_OK and clear interrupted verdict
    verify_code = cli_main(["verify", str(log_path), "--key", str(key_path)])
    assert verify_code == EXIT_OK
    verify_out = capsys.readouterr()
    assert "OK: Session recovered (interrupted execution)." in verify_out.out


def test_recover_with_ed25519_receipt(tmp_path, capsys):
    """Recovering with Ed25519 key generates a valid signed receipt with status interrupted."""
    key_path = tmp_path / "key"
    load_or_create_key(key_path)
    priv_path, pub_path = generate_ed25519_keypair(tmp_path / "ed.key", tmp_path / "ed.pub")

    rec = Recorder("crash-sess-3", log_dir=str(tmp_path), key_path=key_path, ed25519_key_path=priv_path)
    rec.run("echo pre_crash")
    # No close()

    log_path = rec.log_path

    # Recover using CLI with Ed25519 key
    recover_code = cli_main([
        "recover",
        str(log_path),
        "--key", str(key_path),
        "--ed25519-key", str(priv_path),
    ])
    assert recover_code == EXIT_OK

    # Receipt exists and has status interrupted
    rp = receipt_path(log_path)
    assert rp.exists()
    r_data = json.loads(rp.read_text(encoding="utf-8"))
    assert r_data["payload"].get("status") == "interrupted"

    # CLI verify with pubkey verifies receipt and outputs interrupted status
    verify_code = cli_main([
        "verify",
        str(log_path),
        "--pubkey", str(pub_path),
    ])
    assert verify_code == EXIT_OK
    out = capsys.readouterr().out
    assert "OK: Session recovered (interrupted execution)." in out


def test_tampered_records_prior_to_crash_fail(tmp_path, capsys):
    """Truncated or tampered records prior to crash fail recovery and verify with EXIT_TAMPERED."""
    key_path = tmp_path / "key"
    key = load_or_create_key(key_path)

    rec = Recorder("tampered-sess", log_dir=str(tmp_path), key_path=key_path)
    rec.run("echo secret_op")
    rec.run("echo normal_op")
    # Tamper with the first record in the log file
    lines = rec.log_path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["event"]["data"] = {"tampered": True}
    lines[0] = json.dumps(first)
    rec.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # verify_file should detect content modification
    problems = verify_file(rec.log_path, key)
    assert len(problems) > 0

    # recover command should refuse to recover a tampered log
    recover_code = cli_main(["recover", str(rec.log_path), "--key", str(key_path)])
    assert recover_code == EXIT_TAMPERED
    out = capsys.readouterr().out
    assert "CANNOT RECOVER" in out

    # Programmatic recover_log should also raise ValueError
    with pytest.raises(ValueError, match="Cannot recover"):
        recover_log(rec.log_path, key)


def test_recorder_context_manager(tmp_path):
    """Recorder used as a context manager automatically seals on block exit."""
    key_path = tmp_path / "key"
    key = load_or_create_key(key_path)

    with Recorder("ctx-sess", log_dir=str(tmp_path), key_path=key_path) as rec:
        rec.run("echo context_managed")

    assert rec.closed is True
    problems, incomplete = verify_log(rec.log_path, key)
    assert not problems
    assert not incomplete
    assert manifest_path(rec.log_path).exists()


def test_recover_programmatic_api(tmp_path):
    """recover_log programmatic function appends session.recovered and writes manifest."""
    key_path = tmp_path / "key"
    key = load_or_create_key(key_path)

    rec = Recorder("prog-sess", log_dir=str(tmp_path), key_path=key_path)
    rec.run("echo prog_test")

    rec_entry, manifest, receipt = recover_log(rec.log_path, key)
    assert rec_entry["event"]["event_type"] == "session.recovered"
    assert rec_entry["event"]["data"]["status"] == "interrupted"
    assert manifest["payload"]["status"] == "interrupted"

    problems, incomplete = verify_log(rec.log_path, key)
    assert not problems
    assert not incomplete
