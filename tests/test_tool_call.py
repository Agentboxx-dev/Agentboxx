import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

from agentbox import Recorder, cli, replay as rp
from agentbox.contract import TaskContract
from agentbox.redact import redact_value
from agentbox.report import build_report_data, render_html, render_json, render_text
from agentbox.signer import load_or_create_key, verify_log
from agentbox.toolcall import MAX_PAYLOAD_BYTES, as_text, cap_payload, serialize, to_jsonable

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "docs" / "schema.json").read_text())
STANDALONE = ROOT / "examples" / "verify_standalone.py"
GH_TOKEN = "ghp_" + "a1" * 18


def _rec(tmp_path, **kw):
    return Recorder("tc", workspace=str(tmp_path / "ws"), log_dir=str(tmp_path / "runs"),
                    key_path=tmp_path / "key", **kw)


def _events(rec):
    return [json.loads(line)["event"] for line in rec.log_path.read_text(encoding="utf-8").splitlines()]


def _calls(rec):
    return [e["data"] for e in _events(rec) if e["event_type"] == "tool.call"]


def _verify(rec, tmp_path):
    return verify_log(rec.log_path, load_or_create_key(tmp_path / "key"))


# ---------- recording ----------

def test_a_tool_call_is_recorded_signed_and_chained(tmp_path):
    rec = _rec(tmp_path, agent_id="coder-1")
    out = rec.record_tool_call(tool_name="search_issues", tool_source="mcp:github",
                               arguments={"query": "is:open"}, result={"total": 3}, duration_ms=412,
                               thought="look for bugs", usage={"prompt_tokens": 5})
    rec.close()
    (call,) = _calls(rec)
    assert call["tool_name"] == "search_issues" and call["tool_source"] == "mcp:github"
    assert call["arguments"] == {"query": "is:open"} and call["result"] == {"total": 3}
    assert call["duration_ms"] == 412 and call["is_error"] is False
    assert call["thought"] == "look for bugs" and call["agent_id"] == "coder-1"
    assert call["usage"] == {"prompt_tokens": 5} and call["session_id"] == "tc"
    assert out["observation"] == call and out["signals"] == []
    assert _verify(rec, tmp_path) == ([], [])


def test_a_tool_call_shares_the_step_counter_with_commands(tmp_path):
    rec = _rec(tmp_path)
    rec.run("echo hi")
    rec.record_tool_call(tool_name="a", tool_source="builtin")
    rec.record_step(command="ls")
    rec.record_tool_call(tool_name="b", tool_source="builtin", parent_step=1)
    rec.close()
    ev = _events(rec)
    indices = [(e["event_type"], e["data"]["step_index"]) for e in ev if e["event_type"] in ("step", "tool.call")]
    assert indices == [("step", 1), ("tool.call", 2), ("step", 3), ("tool.call", 4)]
    assert ev[-1]["data"]["steps"] == 4
    assert _calls(rec)[1]["parent_step_index"] == 1


def test_arguments_and_result_default_to_null(tmp_path):
    rec = _rec(tmp_path)
    rec.record_tool_call(tool_name="ping", tool_source="function")
    rec.close()
    (call,) = _calls(rec)
    assert call["arguments"] is None and call["result"] is None and call["duration_ms"] == 0


@pytest.mark.parametrize("kw", [{"tool_name": ""}, {"tool_name": "  "}, {"tool_name": 5},
                                {"tool_source": ""}, {"tool_source": None}])
def test_bad_names_are_rejected_without_writing_anything(tmp_path, kw):
    rec = _rec(tmp_path)
    args = {"tool_name": "t", "tool_source": "builtin", **kw}
    with pytest.raises(ValueError):
        rec.record_tool_call(**args)
    assert _calls(rec) == [] and rec.step_index == 0


def test_negative_duration_is_clamped(tmp_path):
    rec = _rec(tmp_path)
    rec.record_tool_call(tool_name="t", tool_source="builtin", duration_ms=-5)
    assert _calls(rec)[0]["duration_ms"] == 0


# ---------- redaction ----------

def test_secrets_never_reach_the_log(tmp_path):
    rec = _rec(tmp_path)
    rec.record_tool_call(
        tool_name="http_get", tool_source="mcp:fetch",
        arguments={"url": "https://u:hunter2hunter2@example.com/x", "api_key": "abcdef123456",
                   "headers": {"Authorization": "Bearer abcdefghijklmnop"}, "max_tokens": 100,
                   "nested": [{"password": "p4ssw0rd!"}]},
        result={"echo": f"token={GH_TOKEN}", "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----"},
        thought="use password=hunter2hunter2")
    rec.close()
    text = rec.log_path.read_text(encoding="utf-8")
    for secret in ("hunter2hunter2", "abcdef123456", "abcdefghijklmnop", "p4ssw0rd!", GH_TOKEN, "MIIB"):
        assert secret not in text, secret
    (call,) = _calls(rec)
    assert call["arguments"]["max_tokens"] == 100                     # numbers are not secrets
    assert call["arguments"]["api_key"] == "[REDACTED:secret_key]"
    assert call["arguments"]["nested"][0]["password"] == "[REDACTED:secret_key]"
    assert sum(call["redactions"].values()) >= 7
    assert call["redactions"]["secret_key"] >= 3
    assert _verify(rec, tmp_path) == ([], [])


def test_secrets_in_names_and_keys_are_redacted(tmp_path):
    rec = _rec(tmp_path)
    rec.record_tool_call(tool_name=f"call {GH_TOKEN}", tool_source="mcp:x", arguments={GH_TOKEN: 1})
    text = rec.log_path.read_text(encoding="utf-8")
    assert GH_TOKEN not in text


def test_redact_value_keeps_structure_and_only_hides_secret_strings():
    clean, counts = redact_value({"a": 1, "b": [True, None, 2.5, "ok"], "token": "x1y2z3",
                                  "empty_secret": "", "secrets": ["one", "two"], "max_tokens": 9})
    assert clean == {"a": 1, "b": [True, None, 2.5, "ok"], "token": "[REDACTED:secret_key]",
                     "empty_secret": "", "secrets": ["[REDACTED:secret_key]"] * 2, "max_tokens": 9}
    assert counts == {"secret_key": 3}


def test_redact_value_does_not_double_redact_or_lose_colliding_keys():
    clean, _ = redact_value({"token": "[REDACTED:github_token]"})
    assert clean == {"token": "[REDACTED:github_token]"}
    clean, _ = redact_value({f"k_{GH_TOKEN}": 1, "k_[REDACTED:github_token]": 2})
    assert len(clean) == 2


def test_redact_value_cuts_off_pathological_nesting():
    deep = cur = {}
    for _ in range(100):
        cur["x"] = {}
        cur = cur["x"]
    clean, counts = redact_value(deep)
    assert counts.get("too_deep") == 1 and len(json.dumps(clean)) < 2000


# ---------- JSON safety ----------

def test_values_are_made_json_safe(tmp_path):
    rec = _rec(tmp_path)
    rec.record_tool_call(tool_name="t", tool_source="builtin",
                         arguments={1: "int key", "t": (1, 2), "s": {3, 1, 2}, "b": b"bytes", "o": object},
                         result=float("nan"))
    rec.record_tool_call(tool_name="t2", tool_source="builtin", result=[float("inf"), -float("inf"), 1.5])
    rec.close()
    text = rec.log_path.read_text(encoding="utf-8")
    assert "NaN" not in text and "Infinity" not in text                      # strict-JSON readers can parse it
    first, second = _calls(rec)
    assert first["arguments"]["1"] == "int key" and first["arguments"]["t"] == [1, 2]
    assert first["arguments"]["s"] == [1, 2, 3] and first["arguments"]["b"] == "bytes"
    assert first["result"] == "nan" and second["result"] == ["inf", "-inf", 1.5]
    assert _verify(rec, tmp_path) == ([], [])


def test_to_jsonable_survives_cycles_and_unknown_objects():
    cyc = {}
    cyc["self"] = cyc
    assert "max depth" in json.dumps(to_jsonable(cyc))
    assert isinstance(to_jsonable(object()), str)


# ---------- the 64 KB cap ----------

def test_small_payloads_are_stored_unchanged():
    value = {"data": "x" * 1000}
    assert cap_payload(value) == (value, False)


def test_the_cap_boundary_is_exact():
    assert MAX_PAYLOAD_BYTES == 65536
    at_limit, cut = cap_payload("x" * (MAX_PAYLOAD_BYTES - 2))              # serialized: 65,536 bytes
    assert not cut and at_limit == "x" * (MAX_PAYLOAD_BYTES - 2)
    over, cut = cap_payload("x" * (MAX_PAYLOAD_BYTES - 1))
    assert cut and over["truncated"] is True and over["total_bytes"] == MAX_PAYLOAD_BYTES + 1


def test_oversized_payloads_keep_head_tail_size_and_full_hash(tmp_path):
    big = {"data": "é" * 40000, "end": "THE-END"}
    rec = _rec(tmp_path)
    rec.record_tool_call(tool_name="read_file", tool_source="mcp:filesystem", arguments={"path": "a"}, result=big)
    rec.close()
    (call,) = _calls(rec)
    stub = call["result"]
    full = serialize(big)
    assert call["result_truncated"] is True and "arguments_truncated" not in call
    assert call["arguments"] == {"path": "a"}
    assert stub["truncated"] is True and stub["total_bytes"] == len(full)
    assert stub["sha256"] == hashlib.sha256(full).hexdigest()
    assert len(stub["text"].encode()) <= MAX_PAYLOAD_BYTES
    assert stub["text"].startswith('{"data":"é') and stub["text"].endswith('THE-END"}')
    assert "bytes omitted" in stub["text"]
    assert _verify(rec, tmp_path) == ([], [])


def test_oversized_arguments_are_cut_too(tmp_path):
    rec = _rec(tmp_path)
    rec.record_tool_call(tool_name="write", tool_source="builtin", arguments="y" * 100_000)
    (call,) = _calls(rec)
    assert call["arguments_truncated"] is True and call["arguments"]["total_bytes"] == 100_002


def test_the_hash_covers_the_redacted_content_never_the_secret(tmp_path):
    secret = GH_TOKEN
    rec = _rec(tmp_path)
    rec.record_tool_call(tool_name="t", tool_source="x", result={"blob": "z" * 70000, "k": secret})
    (call,) = _calls(rec)
    raw_hash = hashlib.sha256(serialize({"blob": "z" * 70000, "k": secret})).hexdigest()
    assert call["result"]["sha256"] != raw_hash
    assert secret not in rec.log_path.read_text(encoding="utf-8")


def test_as_text():
    assert as_text("hi") == "hi" and as_text(None) == "" and as_text({"b": 1, "a": 2}) == '{"a": 2, "b": 1}'
    assert as_text({"text": "head...tail", "truncated": True, "total_bytes": 9, "sha256": "x"}) == "head...tail"


# ---------- tampering ----------

def test_editing_a_recorded_tool_call_is_detected(tmp_path):
    rec = _rec(tmp_path)
    rec.record_tool_call(tool_name="transfer", tool_source="mcp:bank", arguments={"to": "alice"},
                         result={"ok": True})
    rec.close()
    rec.log_path.write_text(rec.log_path.read_text(encoding="utf-8").replace('"to": "alice"', '"to": "mallory"'),
                            encoding="utf-8")
    problems, _ = _verify(rec, tmp_path)
    assert any("content was modified" in p for p in problems)


def test_removing_a_tool_call_is_detected(tmp_path):
    rec = _rec(tmp_path)
    rec.record_tool_call(tool_name="a", tool_source="builtin")
    rec.record_tool_call(tool_name="b", tool_source="builtin")
    rec.close()
    lines = rec.log_path.read_text(encoding="utf-8").splitlines()
    rec.log_path.write_text("\n".join(lines[:1] + lines[2:]) + "\n", encoding="utf-8")
    problems, _ = _verify(rec, tmp_path)
    assert problems


def test_cli_verify_reports_tampering_and_counts_tool_calls(tmp_path, capsys):
    rec = _rec(tmp_path)
    rec.run("echo hi")
    rec.record_tool_call(tool_name="a", tool_source="mcp:x", result="fine")
    rec.record_tool_call(tool_name="b", tool_source="mcp:x", result="Error: boom", is_error=True)
    rec.close()
    key = str(tmp_path / "key")
    assert cli.main(["verify", str(rec.log_path), "--key", key]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "OK: log is intact" in out and "2 tool calls recorded and verified (1 failed)" in out
    rec.log_path.write_text(rec.log_path.read_text(encoding="utf-8").replace("fine", "FINE"), encoding="utf-8")
    assert cli.main(["verify", str(rec.log_path), "--key", key]) == cli.EXIT_TAMPERED
    out = capsys.readouterr().out
    assert "TAMPERED" in out and "recorded and verified" not in out       # no count for a log we cannot trust


def test_cli_verify_stays_quiet_when_there_are_no_tool_calls(tmp_path, capsys):
    rec = _rec(tmp_path)
    rec.run("echo hi")
    rec.close()
    assert cli.main(["verify", str(rec.log_path), "--key", str(tmp_path / "key")]) == cli.EXIT_OK
    assert "tool call" not in capsys.readouterr().out


def test_the_independent_verifier_agrees(tmp_path):
    rec = _rec(tmp_path)
    rec.record_tool_call(tool_name="t", tool_source="mcp:x", arguments={"é": ["ü", 1, 2.5, None, True]},
                         result={"nested": {"a": [1, {"b": "\u2028 \x01 quote\""}]}})
    rec.close()

    def standalone():
        return subprocess.run([sys.executable, str(STANDALONE), str(rec.log_path), "--key-file", str(tmp_path / "key")],
                              capture_output=True, text=True).returncode
    assert standalone() == 0
    rec.log_path.write_text(rec.log_path.read_text(encoding="utf-8").replace('"b"', '"c"', 1), encoding="utf-8")
    assert standalone() == 1


# ---------- detectors and contract ----------

def test_repeating_the_same_tool_call_fires_the_loop_detector(tmp_path):
    rec = _rec(tmp_path)
    signals = []
    for _ in range(3):
        signals = rec.record_tool_call(tool_name="search", tool_source="mcp:web", arguments={"q": "same"})["signals"]
    assert [s["kind"] for s in signals] == ["loop.exact"]
    logged = [e["data"] for e in _events(rec) if e["event_type"] == "analysis.signal"]
    assert logged and logged[0]["step_index"] == 3


def test_different_arguments_are_not_a_repeat(tmp_path):
    rec = _rec(tmp_path)
    for i in range(6):
        out = rec.record_tool_call(tool_name="search", tool_source="mcp:web", arguments={"q": f"query {i}"})
    assert out["signals"] == [] and not [e for e in _events(rec) if e["event_type"] == "analysis.signal"]


def test_repeated_tool_errors_fire_the_error_detector(tmp_path):
    rec = _rec(tmp_path)
    for i in range(3):
        out = rec.record_tool_call(tool_name="deploy", tool_source="mcp:ci", arguments={"attempt": f"n{i}"},
                                   result="DeployError: quota exceeded", is_error=True)
    assert "loop.error_repeat" in [s["kind"] for s in out["signals"]]


def test_tool_calls_and_commands_repeat_independently(tmp_path):
    rec = _rec(tmp_path)
    rec.record_tool_call(tool_name="x", tool_source="b", arguments={"a": 1})
    rec.record_step(command="x")
    rec.record_tool_call(tool_name="x", tool_source="b", arguments={"a": 1})
    assert not [e for e in _events(rec) if e["event_type"] == "analysis.signal"]


def test_tool_calls_count_toward_the_contract_step_budget(tmp_path):
    rec = _rec(tmp_path, contract=TaskContract(max_steps=2))
    rec.record_tool_call(tool_name="a", tool_source="b", arguments={"n": 1})
    rec.record_tool_call(tool_name="a", tool_source="b", arguments={"n": 2})
    assert not rec.closed
    rec.record_tool_call(tool_name="a", tool_source="b", arguments={"n": 3})
    assert rec.closed
    ev = _events(rec)
    assert ev[-1]["data"]["reason"] == "contract_budget_exceeded:max_steps"
    verdict = next(e["data"] for e in ev if e["event_type"] == "contract.verdict")
    assert verdict["passed"] is False
    assert _verify(rec, tmp_path) == ([], [])


def test_pagination_style_calls_are_not_mistaken_for_a_loop(tmp_path):
    rec = _rec(tmp_path)
    for page in range(1, 9):
        out = rec.record_tool_call(tool_name="list", tool_source="mcp:api", arguments={"page": page})
    assert out["signals"] == []


# ---------- report ----------

def _mixed_log(tmp_path):
    rec = _rec(tmp_path)
    rec.run("echo hi")
    rec.record_tool_call(tool_name="search_issues", tool_source="mcp:github",
                         arguments={"query": "<script>alert(1)</script>", "api_key": "abcdef123456"},
                         result={"total": 3}, duration_ms=412, thought="find bugs")
    rec.record_tool_call(tool_name="create_issue", tool_source="mcp:github", arguments={"title": "t"},
                         result="Error: 403", is_error=True, duration_ms=9)
    rec.close()
    return rec


def test_report_data_counts_tool_calls(tmp_path):
    data = build_report_data(cli._read_events(_mixed_log(tmp_path).log_path))
    assert data["summary"]["total_tool_calls"] == 2 and data["summary"]["failed_tool_calls"] == 1
    assert data["summary"]["total_steps"] == 1 and data["summary"]["total_redactions"] == 1
    assert [t["tool_name"] for t in data["tool_calls"]] == ["search_issues", "create_issue"]


def test_text_report_lists_tool_calls_in_step_order(tmp_path):
    data = build_report_data(cli._read_events(_mixed_log(tmp_path).log_path))
    text = render_text(data)
    lines = text.splitlines()
    assert lines[0].startswith("[  1] ok  exit=0")
    assert lines[1].startswith("[  2] ok  tool mcp:github/search_issues (412ms)")
    assert lines[2].startswith("[  3] ERR tool mcp:github/create_issue (9ms)")
    assert "1 steps, 2 tool calls, 0 signals" in text
    assert "abcdef123456" not in text


def test_text_report_without_tool_calls_is_unchanged(tmp_path):
    rec = _rec(tmp_path)
    rec.run("echo hi")
    rec.close()
    text = render_text(build_report_data(cli._read_events(rec.log_path)))
    assert "tool" not in text and "1 steps, 0 signals" in text


def test_text_report_cannot_be_hijacked_by_escape_sequences(tmp_path):
    rec = _rec(tmp_path)
    rec.record_tool_call(tool_name="t\x1b[2J", tool_source="mcp:x", arguments={"a": "\x1b]0;pwned\x07"})
    text = render_text(build_report_data(cli._read_events(rec.log_path)))
    assert "\x1b" not in text and "\x07" not in text


def test_html_report_shows_tool_calls_and_escapes_them(tmp_path):
    html = render_html(build_report_data(cli._read_events(_mixed_log(tmp_path).log_path)))
    assert "Tool calls</div>" in html and "mcp:github/search_issues" in html
    assert "badge-err\">ERROR" in html and "412ms" in html and "find bugs" in html
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    assert "[REDACTED:secret_key]" in html and "abcdef123456" not in html


def test_html_report_marks_truncated_payloads(tmp_path):
    rec = _rec(tmp_path)
    rec.record_tool_call(tool_name="t", tool_source="x", result="r" * 100_000)
    html = render_html(build_report_data(cli._read_events(rec.log_path)))
    assert "truncated, full SHA-256 in the log" in html


def test_json_report_includes_tool_calls(tmp_path):
    data = json.loads(render_json(build_report_data(cli._read_events(_mixed_log(tmp_path).log_path))))
    assert len(data["tool_calls"]) == 2 and data["summary"]["failed_tool_calls"] == 1


def test_cli_report_includes_tool_calls(tmp_path, capsys):
    rec = _mixed_log(tmp_path)
    assert cli.main(["report", str(rec.log_path)]) == 0
    assert "tool mcp:github/search_issues" in capsys.readouterr().out


# ---------- replay ----------

def test_replay_makes_a_frame_for_each_tool_call(tmp_path):
    rec = _mixed_log(tmp_path)
    events, errors = rp.load_events_tolerant(rec.log_path)
    sess = rp.build_session(events, errors)
    assert [f.kind for f in sess.frames] == ["step", "tool", "tool"]
    ok, bad = sess.frames[1], sess.frames[2]
    assert ok.command.startswith("mcp:github/search_issues {") and ok.exit_code == 0 and not ok.failed
    assert ok.stdout == '{"total": 3}' and ok.thought == "find bugs" and ok.duration_ms == 412
    assert bad.failed and bad.stderr == "Error: 403" and bad.stdout == ""
    text = rp.render_plain(sess, 1, rp.Verdict(rp.VERIFIED))
    assert "[TOOL CALL] (exit code: 0 | duration: 0.41s)" in text and "$ mcp:github" not in text
    assert "mcp:github/search_issues" in text
    assert "[COMMAND]" in rp.render_plain(sess, 0, rp.Verdict(rp.VERIFIED))


def test_replay_attaches_signals_to_tool_call_frames(tmp_path):
    rec = _rec(tmp_path)
    for _ in range(3):
        rec.record_tool_call(tool_name="s", tool_source="mcp:web", arguments={"q": "same"})
    rec.close()
    events, errors = rp.load_events_tolerant(rec.log_path)
    sess = rp.build_session(events, errors)
    assert [len(f.signals) for f in sess.frames] == [0, 0, 1]
    assert "loop.exact" in rp.render_plain(sess, 2, rp.Verdict(rp.VERIFIED))


def test_replay_ui_labels_tool_calls(tmp_path):
    pytest.importorskip("rich")
    import io
    from rich.console import Console
    from agentbox import replay_ui
    events, errors = rp.load_events_tolerant(_mixed_log(tmp_path).log_path)
    sess = rp.build_session(events, errors)
    console = Console(file=io.StringIO(), force_terminal=True, width=100, height=40, color_system=None)
    state = rp.ReplayState(len(sess.frames))
    state.index = 1
    with console.capture() as cap:
        console.print(replay_ui.build_view(sess, state, rp.Verdict(rp.VERIFIED), console))
    out = cap.get()
    assert "TOOL CALL" in out and "mcp:github/search_issues" in out and "▸" in out


# ---------- schema ----------

def _record(rec, event_type="tool.call"):
    return next(json.loads(line) for line in rec.log_path.read_text(encoding="utf-8").splitlines()
                if json.loads(line)["event"]["event_type"] == event_type)


def test_tool_call_records_validate_against_the_schema(tmp_path):
    rec = _rec(tmp_path, agent_id="a")
    rec.record_tool_call(tool_name="t", tool_source="mcp:x", arguments={"k": 1}, result="r", usage={"x": 1},
                         parent_step=None)
    rec.record_tool_call(tool_name="big", tool_source="mcp:x", result="r" * 100_000, is_error=True)
    rec.close()
    validator = jsonschema.Draft202012Validator(SCHEMA)
    for line in rec.log_path.read_text(encoding="utf-8").splitlines():
        validator.validate(json.loads(line))


def test_the_schema_rejects_a_malformed_tool_call(tmp_path):
    rec = _rec(tmp_path)
    rec.record_tool_call(tool_name="t", tool_source="mcp:x")
    good = _record(rec)
    validator = jsonschema.Draft202012Validator(SCHEMA)
    assert validator.is_valid(good)
    for field in ("tool_name", "tool_source", "is_error", "duration_ms", "step_index"):
        bad = copy.deepcopy(good)
        del bad["event"]["data"][field]
        assert not validator.is_valid(bad), field
    bad = copy.deepcopy(good)
    bad["event"]["data"]["is_error"] = "no"
    assert not validator.is_valid(bad)
    bad = copy.deepcopy(good)
    bad["event"]["data"]["tool_source"] = 7
    assert not validator.is_valid(bad)
    bad = copy.deepcopy(good)
    bad["event"]["data"]["duration_ms"] = -1
    assert not validator.is_valid(bad)


def test_custom_tool_sources_are_accepted(tmp_path):
    rec = _rec(tmp_path)
    for source in ("mcp:filesystem", "builtin", "langchain", "function", "my-company/internal tool v2"):
        rec.record_tool_call(tool_name="t", tool_source=source)
    validator = jsonschema.Draft202012Validator(SCHEMA)
    for line in rec.log_path.read_text(encoding="utf-8").splitlines():
        validator.validate(json.loads(line))