import io
import os
import sys

import pytest

from agentbox import cli, replay as rp
from agentbox.signer import ChainWriter


# ---------- helpers ----------

def _write_log(tmp_path, close=True, name="s.ndjson", odd_text=None):
    """A 3-step session: ok, failing (with a loop signal + resources), crash. Returns (log, keyfile)."""
    key = bytes(range(32))
    keyfile = tmp_path / "key"
    keyfile.write_text(key.hex())
    log = tmp_path / name
    w = ChainWriter(log, key)
    w.append("session.start", {"session_id": "fix-42", "agent_id": "coder-1", "isolation": {"backend": "docker"}})
    w.append("step", {"step_index": 1, "thought": "list files", "command": "ls", "exit_code": 0,
                      "timed_out": False, "duration_ms": 420,
                      "stdout": {"text": odd_text or "a.py\nb.py\n", "total_bytes": 10, "truncated": False},
                      "stderr": {"text": "", "total_bytes": 0, "truncated": False}})
    w.append("step", {"step_index": 2, "thought": "run tests", "command": "pytest -q", "exit_code": 1,
                      "timed_out": False, "duration_ms": 1500,
                      "stdout": {"text": "", "total_bytes": 0, "truncated": False},
                      "stderr": {"text": "boom\n", "total_bytes": 5, "truncated": False}})
    w.append("analysis.signal", {"step_index": 2, "kind": "repeated_failure", "severity": "warn", "count": 2,
                                 "hint": "try something else"})
    w.append("sandbox.resource", {"step_index": 2, "mem_bytes": 149422080, "mem_limit_bytes": 536870912,
                                  "mem_pct": 27.8, "cpu_pct": 12.0, "pids": 4})
    w.append("step", {"step_index": 3, "thought": "again", "command": "pytest -q", "exit_code": 137,
                      "timed_out": False, "duration_ms": 30,
                      "stdout": {"text": "x" * 50, "total_bytes": 5000, "truncated": True},
                      "stderr": {"text": "", "total_bytes": 0, "truncated": False}})
    w.append("sandbox.crash", {"step_index": 3, "kind": "oom", "exit_code": 137, "running": False,
                               "oom_killed": True, "oom_events": 1})
    if close:
        w.append("session.end", {"reason": "done", "steps": 3})
        w.write_manifest()
    return log, keyfile


def _session(tmp_path, **kw):
    log, _ = _write_log(tmp_path, **kw)
    events, errors = rp.load_events_tolerant(log)
    return rp.build_session(events, errors)


# ---------- frames ----------

def test_one_frame_per_step_with_events_attached(tmp_path):
    s = _session(tmp_path)
    assert s.session_id == "fix-42" and s.agent_id == "coder-1" and s.end_reason == "done"
    assert [f.command for f in s.frames] == ["ls", "pytest -q", "pytest -q"]
    assert not s.frames[0].failed and s.frames[1].failed and s.frames[2].failed
    assert [x["kind"] for x in s.frames[1].signals] == ["repeated_failure"]
    assert s.frames[1].resource["pids"] == 4
    assert s.frames[2].crash["oom_killed"] is True
    assert s.frames[0].signals == [] and s.frames[0].resource is None


def test_truncated_output_is_flagged(tmp_path):
    f = _session(tmp_path).frames[2]
    assert f.output_truncated and f.total_bytes == 5000


def test_events_for_unknown_steps_are_ignored():
    events = [{"event_type": "step", "data": {"step_index": 1, "command": "ls", "exit_code": 0}},
              {"event_type": "analysis.signal", "data": {"step_index": 99, "kind": "x"}}]
    s = rp.build_session(events)
    assert len(s.frames) == 1 and s.frames[0].signals == []


def test_session_without_steps():
    s = rp.build_session([{"event_type": "session.start", "data": {"session_id": "e"}}])
    assert s.frames == []
    text = rp.render_plain(s, 0, rp.Verdict(rp.INCOMPLETE))
    assert "No steps were recorded" in text


def test_odd_event_shapes_do_not_crash():
    events = [{"event_type": "step", "data": {"stdout": 5, "exit_code": "x", "duration_ms": "y"}},
              {"event_type": "step", "data": None}]
    s = rp.build_session(events)
    assert len(s.frames) == 2 and s.frames[0].exit_code is None


def test_tolerant_loader_keeps_good_lines(tmp_path):
    log, _ = _write_log(tmp_path)
    lines = log.read_text(encoding="utf-8").split("\n")
    lines[2] = "not json"
    log.write_text("\n".join(lines), encoding="utf-8")
    events, errors = rp.load_events_tolerant(log)
    assert errors == ["line 3: unreadable record"]
    assert len(events) == len(lines) - 2          # trailing blank + the bad line


# ---------- navigation ----------

def test_navigation_bounds_without_loop():
    st = rp.ReplayState(3)
    assert not st.prev() and st.notice == "Start of session"
    assert st.next() and st.next() and st.index == 2
    assert not st.next() and st.index == 2 and st.notice == "End of session"
    assert st.home() and st.index == 0
    assert st.end() and st.index == 2
    assert not st.end()


def test_navigation_loop_wraps():
    st = rp.ReplayState(2, loop=True)
    assert st.prev() and st.index == 1
    assert st.next() and st.index == 0


def test_navigation_on_empty_session():
    st = rp.ReplayState(0)
    assert not st.next() and not st.prev() and st.index == 0
    st.end()
    assert st.index == 0


def test_scrubber_marks_failures_and_windows_long_sessions(tmp_path):
    s = _session(tmp_path)
    cells = rp.scrubber_cells(s.frames, 0, 10)
    assert [k for _, k in cells] == ["current", "failed", "failed"]
    many = rp.build_session([{"event_type": "step", "data": {"step_index": i, "exit_code": 0}} for i in range(50)])
    cells = rp.scrubber_cells(many.frames, 25, 10)
    assert len(cells) == 10 and any(k == "current" for _, k in cells)
    assert len(rp.scrubber_cells(many.frames, 49, 10)) == 10
    assert rp.scrubber_cells(many.frames, 0, 0) == []


# ---------- untrusted text ----------

def test_sanitize_neutralises_escape_sequences():
    nasty = "ok\x1b[2J\x1b]0;pwned\x07 done\ttab\r\n\x7f\x85"
    clean = rp.sanitize(nasty)
    assert "\x1b" not in clean and "\x07" not in clean and "\r" not in clean and "\x7f" not in clean
    assert "\n" in clean and "    " in clean


def test_plain_render_never_emits_raw_escapes(tmp_path):
    s = _session(tmp_path, odd_text="\x1b[31mred\x1b[0m\x1b]0;title\x07")
    text = rp.render_plain(s, 0, rp.Verdict(rp.VERIFIED))
    assert "\x1b" not in text and "\x07" not in text


# ---------- keys ----------

@pytest.mark.parametrize("ch,action", [(" ", "next"), ("n", "next"), ("p", "prev"), ("v", "verify"),
                                       ("q", "quit"), ("a", "autoplay"), ("\x03", "quit"), ("z", None)])
def test_decode_char(ch, action):
    assert rp.decode_char(ch) == action


@pytest.mark.parametrize("seq,action", [("", "quit"), ("[C", "next"), ("[D", "prev"), ("[H", "home"),
                                        ("[F", "end"), ("OH", "home"), ("[1~", "home"), ("[4~", "end"),
                                        ("[A", None), ("[1;5C", None)])
def test_decode_escape(seq, action):
    assert rp.decode_escape(seq) == action


@pytest.mark.parametrize("prefix,second,action", [("\xe0", "M", "next"), ("\x00", "K", "prev"),
                                                  ("\xe0", "G", "home"), ("\xe0", "O", "end"),
                                                  ("\xe0", "H", None), ("x", "M", None)])
def test_decode_windows_key(prefix, second, action):
    assert rp.decode_windows_key(prefix, lambda: second) == action


@pytest.mark.skipif(sys.platform == "win32", reason="needs a POSIX pty")
def test_key_reader_reads_arrows_and_restores_terminal():
    import pty
    import termios
    master, slave = pty.openpty()
    try:
        before = termios.tcgetattr(slave)
        with rp.KeyReader(fd=slave) as keys:
            assert termios.tcgetattr(slave) != before          # cbreak is on inside
            os.write(master, b"\x1b[C")
            assert keys.read(1.0) == "next"
            os.write(master, b"\x1b[D")
            assert keys.read(1.0) == "prev"
            os.write(master, b"\x1b")
            assert keys.read(1.0) == "quit"
            os.write(master, b"q")
            assert keys.read(1.0) == "quit"
            assert keys.read(0.05) is None
        assert termios.tcgetattr(slave) == before              # restored
    finally:
        os.close(master)
        os.close(slave)


@pytest.mark.skipif(sys.platform == "win32", reason="needs a POSIX pty")
def test_key_reader_restores_terminal_when_the_body_raises():
    import pty
    import termios
    master, slave = pty.openpty()
    try:
        before = termios.tcgetattr(slave)
        with pytest.raises(RuntimeError):
            with rp.KeyReader(fd=slave):
                raise RuntimeError("boom")
        assert termios.tcgetattr(slave) == before
    finally:
        os.close(master)
        os.close(slave)


# ---------- plain rendering ----------

def test_plain_render_shows_the_mockup_sections(tmp_path):
    s = _session(tmp_path)
    text = rp.render_plain(s, 1, rp.Verdict(rp.VERIFIED), width=80)
    for part in ("AGENTBOXX REPLAY", "Step [02/03]", "VERIFIED ✓", "fix-42", "[THOUGHT]", "run tests",
                 "[COMMAND] (exit code: 1 | duration: 1.50s)", "$ pytest -q", "[OUTPUT]", "[stderr] boom",
                 "[ANALYSIS & STATS]", "repeated_failure", "RAM: 142 MB / 512 MB (28%)", "CPU: 12%"):
        assert part in text, part
    assert all(len(line) <= 80 for line in text.split("\n"))


def test_plain_render_flags_crash_and_truncation(tmp_path):
    text = rp.render_plain(_session(tmp_path), 2, rp.Verdict(rp.VERIFIED))
    assert "CRASH: oom (OOM killed)" in text and "5000 bytes in total" in text


def test_plain_render_limits_long_output():
    big = "\n".join(f"line {i}" for i in range(500))
    s = rp.build_session([{"event_type": "step", "data": {"step_index": 1, "command": "x", "exit_code": 0,
                                                          "stdout": big}}])
    text = rp.render_plain(s, 0, rp.Verdict(rp.VERIFIED), max_output_lines=10)
    assert "earlier line(s) not shown" in text and "line 499" in text and "line 0 " not in text
    assert len(text.split("\n")) < 60


def test_banner_for_unverified_logs():
    s = rp.Session()
    assert rp.banner_text(rp.Verdict(rp.VERIFIED), s) == ""
    assert rp.banner_text(rp.Verdict(rp.TAMPERED, ["line 2: content was modified", "b"]), s) \
        == "TAMPERED: line 2: content was modified (+1 more, press v)"
    assert "never closed" in rp.banner_text(rp.Verdict(rp.INCOMPLETE), s)


# ---------- CLI ----------

def _replay(tmp_path, *extra, log=None, keyfile=None):
    if log is None:
        log, keyfile = _write_log(tmp_path)
    return cli.main(["replay", str(log), "--plain", "--key", str(keyfile), *extra])


def test_cli_intact_log_exits_0(tmp_path, capsys):
    assert _replay(tmp_path) == 0
    out = capsys.readouterr().out
    assert "Step [01/03]" in out and "VERIFIED ✓" in out


def test_cli_frame_selects_a_step(tmp_path, capsys):
    assert _replay(tmp_path, "--frame", "3") == 0
    assert "Step [03/03]" in capsys.readouterr().out


def test_cli_frame_out_of_range_is_a_clear_error(tmp_path, capsys):
    assert _replay(tmp_path, "--frame", "9") == cli.EXIT_ERROR
    assert "--frame must be between 1 and 3" in capsys.readouterr().err


def test_cli_tampered_log_still_replays_with_banner_and_exits_1(tmp_path, capsys):
    log, keyfile = _write_log(tmp_path)
    log.write_text(log.read_text(encoding="utf-8").replace('"exit_code": 0', '"exit_code": 9', 1), encoding="utf-8")
    assert _replay(tmp_path, log=log, keyfile=keyfile) == cli.EXIT_TAMPERED
    out = capsys.readouterr().out
    assert "TAMPERED ✗" in out and "content was modified" in out and "$ ls" in out


def test_cli_unreadable_line_is_tampered_but_replayable(tmp_path, capsys):
    log, keyfile = _write_log(tmp_path)
    lines = log.read_text(encoding="utf-8").split("\n")
    lines[2] = "garbage"
    log.write_text("\n".join(lines), encoding="utf-8")
    assert _replay(tmp_path, log=log, keyfile=keyfile) == cli.EXIT_TAMPERED
    assert "TAMPERED" in capsys.readouterr().out


def test_cli_unclosed_log_exits_2(tmp_path, capsys):
    log, keyfile = _write_log(tmp_path, close=False)
    assert _replay(tmp_path, log=log, keyfile=keyfile) == cli.EXIT_INCOMPLETE
    out = capsys.readouterr().out
    assert "INCOMPLETE ⚠" in out and "no session.end record" in out


def test_cli_missing_and_empty_files_exit_3(tmp_path, capsys):
    assert cli.main(["replay", str(tmp_path / "nope.ndjson"), "--plain"]) == cli.EXIT_ERROR
    assert "file not found" in capsys.readouterr().err
    empty = tmp_path / "e.ndjson"
    empty.write_text("")
    assert cli.main(["replay", str(empty), "--plain"]) == cli.EXIT_ERROR


def test_cli_bad_key_file_and_delay(tmp_path, capsys):
    log, keyfile = _write_log(tmp_path)
    assert cli.main(["replay", str(log), "--plain", "--key", str(tmp_path / "nokey")]) == cli.EXIT_ERROR
    assert cli.main(["replay", str(log), "--plain", "--key", str(keyfile), "--delay", "0"]) == cli.EXIT_ERROR


def test_cli_non_terminal_falls_back_to_plain(tmp_path, capsys, monkeypatch):
    log, keyfile = _write_log(tmp_path)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    assert cli.main(["replay", str(log), "--key", str(keyfile)]) == 0      # no --plain, but not a tty
    assert "AGENTBOXX REPLAY" in capsys.readouterr().out


# ---------- rich UI (skipped when rich is not installed) ----------

class Keys:
    """Scripted key source; returns 'quit' when the script runs out. Records whether it was closed."""
    def __init__(self, script):
        self.script, self.closed = list(script), False

    def read(self, timeout):
        return self.script.pop(0) if self.script else "quit"


def _console(width=100, height=40):
    pytest.importorskip("rich")
    from rich.console import Console
    return Console(file=io.StringIO(), force_terminal=True, width=width, height=height, color_system=None)


def test_ui_view_has_all_sections(tmp_path):
    console = _console()
    from agentbox import replay_ui
    s = _session(tmp_path)
    view = replay_ui.build_view(s, rp.ReplayState(3), rp.Verdict(rp.VERIFIED), console)
    with console.capture() as cap:
        console.print(view)
    text = cap.get()
    for part in ("AGENTBOXX REPLAY", "Step [01/03]", "VERIFIED ✓", "fix-42", "THOUGHT", "list files",
                 "COMMAND", "exit code: 0", "OUTPUT", "a.py", "ANALYSIS & STATS", "[a Autoplay]"):
        assert part in text, part


def test_ui_view_tampered_banner_and_escape_safety(tmp_path):
    console = _console()
    from agentbox import replay_ui
    s = _session(tmp_path, odd_text="\x1b[2Jevil")
    v = rp.Verdict(rp.TAMPERED, ["line 2: content was modified"])
    with console.capture() as cap:
        console.print(replay_ui.build_view(s, rp.ReplayState(3), v, console))
    text = cap.get()
    assert "TAMPERED ✗" in text and "line 2: content was modified" in text
    assert "\x1b[2J" not in text


def test_ui_view_survives_narrow_terminals_and_empty_sessions(tmp_path):
    from agentbox import replay_ui
    session = _session(tmp_path)
    for width, height in ((40, 12), (200, 60)):
        console = _console(width, height)
        view = replay_ui.build_view(session, rp.ReplayState(3), rp.Verdict(rp.VERIFIED), console)
        console.print(view)
    console = _console()
    empty = rp.build_session([])
    console.print(replay_ui.build_view(empty, rp.ReplayState(0), rp.Verdict(rp.INCOMPLETE), console))


def test_ui_loop_navigation_and_quit(tmp_path):
    from agentbox import replay_ui
    s = _session(tmp_path)
    st = rp.ReplayState(3)
    keys = Keys(["next", "next", "next", "prev", "home", "end", "quit", "next"])
    replay_ui.run_tui(s, st, rp.Verdict(rp.VERIFIED), keys, lambda: rp.Verdict(rp.VERIFIED), console=_console())
    assert st.index == 2 and keys.script == ["next"]          # quit stopped the loop


def test_ui_stepping_past_the_end_stops_with_a_notice(tmp_path):
    from agentbox import replay_ui
    st = rp.ReplayState(3)
    replay_ui.run_tui(_session(tmp_path), st, rp.Verdict(rp.VERIFIED), Keys(["end", "next", "next"]),
                      lambda: rp.Verdict(rp.VERIFIED), console=_console())
    assert st.index == 2 and st.notice == "End of session"


def test_ui_verify_key_updates_the_verdict(tmp_path):
    from agentbox import replay_ui
    st = rp.ReplayState(3)
    out = replay_ui.run_tui(_session(tmp_path), st, rp.Verdict(rp.VERIFIED), Keys(["verify"]),
                            lambda: rp.Verdict(rp.TAMPERED, ["x"]), console=_console())
    assert out.status == rp.TAMPERED and st.notice == "Re-verified: TAMPERED"


def test_ui_verify_failure_is_shown_not_raised(tmp_path):
    from agentbox import replay_ui

    def boom():
        raise OSError("log vanished")
    st = rp.ReplayState(3)
    out = replay_ui.run_tui(_session(tmp_path), st, rp.Verdict(rp.VERIFIED), Keys(["verify"]), boom,
                            console=_console())
    assert out.status == rp.VERIFIED and "log vanished" in st.notice


def test_ui_autoplay_advances_then_stops_at_the_end(tmp_path):
    from agentbox import replay_ui
    st = rp.ReplayState(3)
    replay_ui.run_tui(_session(tmp_path), st, rp.Verdict(rp.VERIFIED),
                      Keys(["autoplay", None, None, None, None]), lambda: rp.Verdict(rp.VERIFIED),
                      console=_console(), delay=0.0, tick=0.2)
    assert st.index == 2 and st.notice == "End of session"


def test_ui_ctrl_c_exits_cleanly(tmp_path):
    from agentbox import replay_ui

    class Interrupting:
        def read(self, timeout):
            raise KeyboardInterrupt
    v = replay_ui.run_tui(_session(tmp_path), rp.ReplayState(3), rp.Verdict(rp.INCOMPLETE), Interrupting(),
                          lambda: rp.Verdict(rp.VERIFIED), console=_console())
    assert v.status == rp.INCOMPLETE


def test_cli_interactive_path_returns_the_verdict_exit_code(tmp_path, monkeypatch):
    """Drive cmd_replay's interactive branch with a fake terminal and scripted keys."""
    pytest.importorskip("rich")
    from agentbox import replay_ui

    log, keyfile = _write_log(tmp_path, close=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.delenv("TERM", raising=False)

    class FakeKeyReader:
        entered = exited = False

        def __enter__(self):
            FakeKeyReader.entered = True
            return Keys(["next", "quit"])

        def __exit__(self, *exc):
            FakeKeyReader.exited = True
            return False
    monkeypatch.setattr(rp, "KeyReader", FakeKeyReader)
    monkeypatch.setattr(replay_ui, "Console", lambda *a, **k: _console())
    code = cli.main(["replay", str(log), "--key", str(keyfile)])
    assert code == cli.EXIT_INCOMPLETE
    assert FakeKeyReader.entered and FakeKeyReader.exited