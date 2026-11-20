import csv
from pathlib import Path

import pytest

from agentbox import Recorder, cli
from agentbox.signer import load_or_create_key


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    key = load_or_create_key(tmp_path / "test-key")
    real = cli.load_or_create_key
    monkeypatch.setattr(cli, "load_or_create_key", lambda path=None: key if path is None else real(path))
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("TERM", raising=False)


def _make_log(tmp_path, name="test_session", close=True, with_signal=False):
    key_path = tmp_path / "test-key"
    rec = Recorder(
        name,
        workspace=str(tmp_path / f"ws_{name}"),
        log_dir=str(tmp_path / "runs"),
        key_path=key_path,
    )
    rec.run("echo step1")
    rec.run("echo step2")
    if with_signal:
        # Emit an analysis.signal event directly into the writer
        rec.writer.append(
            "analysis.signal",
            {
                "step_index": 2,
                "kind": "loop.exact",
                "severity": "warn",
                "count": 3,
                "hint": "Repeated command on unchanged workspace.",
            },
        )
    if close:
        rec.close("done")
    return rec.log_path


def test_export_csv_produces_correct_columns(tmp_path, capsys):
    log = _make_log(tmp_path, "export_cols", close=True)
    code = cli.main(["export", str(log)])
    assert code == cli.EXIT_OK

    out = capsys.readouterr().out
    lines = [line.strip() for line in out.strip().splitlines() if line.strip()]
    reader = csv.reader(lines)
    header = next(reader)
    assert header == ["step_index", "command", "exit_code", "duration_ms", "signals"]

    rows = list(reader)
    assert len(rows) == 2
    assert rows[0][0] == "1"
    assert rows[0][1] == "echo step1"
    assert rows[1][0] == "2"
    assert rows[1][1] == "echo step2"


def test_export_csv_to_file(tmp_path):
    log = _make_log(tmp_path, "export_file", close=True)
    out_csv = tmp_path / "exported.csv"
    code = cli.main(["export", str(log), "--output", str(out_csv)])
    assert code == cli.EXIT_OK
    assert out_csv.exists()

    with open(out_csv, newline="", encoding="utf-8") as f:
        reader = list(csv.reader(f))
    assert reader[0] == ["step_index", "command", "exit_code", "duration_ms", "signals"]
    assert len(reader) == 3


def test_export_csv_signals_column(tmp_path, capsys):
    log = _make_log(tmp_path, "export_sigs", close=True, with_signal=True)
    code = cli.main(["export", str(log)])
    assert code == cli.EXIT_OK

    out = capsys.readouterr().out
    lines = [line.strip() for line in out.strip().splitlines() if line.strip()]
    reader = list(csv.reader(lines))
    # Second step should contain the signal "loop.exact:warn"
    assert reader[2][0] == "2"
    assert "loop.exact:warn" in reader[2][4]


def test_compress_creates_gz_file(tmp_path):
    log = _make_log(tmp_path, "comp_ok", close=True)
    gz_path = Path(str(log) + ".gz")
    assert not gz_path.exists()

    code = cli.main(["compress", str(log)])
    assert code == cli.EXIT_OK
    assert gz_path.exists()
    assert gz_path.stat().st_size > 0


def test_compress_refuses_incomplete_log(tmp_path, capsys):
    log = _make_log(tmp_path, "comp_incomplete", close=False)
    code = cli.main(["compress", str(log)])
    err = capsys.readouterr().err
    assert code == cli.EXIT_ERROR
    assert "not closed" in err.lower() or "incomplete" in err.lower()


def test_compressed_log_verifies_same_as_original(tmp_path, capsys):
    log = _make_log(tmp_path, "verify_gz", close=True)
    gz_path = Path(str(log) + ".gz")

    # Verify original
    orig_code = cli.main(["verify", str(log)])
    orig_out = capsys.readouterr().out
    assert orig_code == cli.EXIT_OK
    assert "OK: log is intact" in orig_out

    # Compress and verify compressed
    cli.main(["compress", str(log)])
    capsys.readouterr()  # discard compress output

    gz_code = cli.main(["verify", str(gz_path)])
    gz_out = capsys.readouterr().out
    assert gz_code == cli.EXIT_OK
    assert "OK: log is intact" in gz_out


def test_report_reads_gz_log(tmp_path, capsys):
    log = _make_log(tmp_path, "report_gz", close=True)
    gz_path = Path(str(log) + ".gz")
    cli.main(["compress", str(log)])
    capsys.readouterr()

    code = cli.main(["report", str(gz_path)])
    assert code == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "session" in out.lower() or "step" in out.lower()


def test_export_reads_gz_log(tmp_path, capsys):
    log = _make_log(tmp_path, "export_gz", close=True)
    gz_path = Path(str(log) + ".gz")
    cli.main(["compress", str(log)])
    capsys.readouterr()

    code = cli.main(["export", str(gz_path)])
    assert code == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "step_index,command,exit_code,duration_ms,signals" in out
