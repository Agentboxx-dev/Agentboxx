"""Report generation for agentbox runs: text, structured JSON, and self-contained HTML."""
import html
import json
from datetime import datetime
from typing import Any, Dict, List

from .replay import sanitize
from .toolcall import as_text

_RED = "\033[31m"
_YELLOW = "\033[33m"
_RESET = "\033[0m"


def _paint(text: str, color: str, enabled: bool) -> str:
    return f"{color}{text}{_RESET}" if enabled else text


def build_report_data(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate raw log events into a clean structured dictionary."""
    session_info: Dict[str, Any] = {
        "session_id": "unknown",
        "isolation": {},
        "agent_id": None,
        "started_at": None,
        "ended_at": None,
        "duration_s": None,
        "reason": None,
    }

    steps: List[Dict[str, Any]] = []
    tool_calls: List[Dict[str, Any]] = []
    signals: List[Dict[str, Any]] = []
    resources: List[Dict[str, Any]] = []
    crashes: List[Dict[str, Any]] = []

    total_redactions = 0
    contract_info: Any = None

    for ev in events:
        etype = ev.get("event_type")
        ts = ev.get("ts")
        data = ev.get("data") or {}

        if etype == "session.start":
            session_info["session_id"] = data.get("session_id", "unknown")
            session_info["isolation"] = data.get("isolation", {})
            session_info["agent_id"] = data.get("agent_id")
            session_info["started_at"] = ts

            if "contract" in data:
                contract_info = {
                    "contract": data["contract"],
                    "verdict": None,
                }

        elif etype == "session.end":
            session_info["ended_at"] = ts
            session_info["reason"] = data.get("reason")

        elif etype == "step":
            steps.append(data)
            red = data.get("redactions")

            if isinstance(red, dict):
                total_redactions += sum(red.values())

        elif etype in {"tool.call", "tool_call", "tool-call"}:
            tool_calls.append(data)
            red = data.get("redactions")

            if isinstance(red, dict):
                total_redactions += sum(red.values())

        elif etype == "analysis.signal":
            signals.append(data)

        elif etype == "sandbox.resource":
            resources.append(data)

        elif etype == "sandbox.crash":
            crashes.append(data)

        elif etype == "contract.verdict":
            if contract_info is None:
                contract_info = {
                    "contract": None,
                    "verdict": None,
                }

            contract_info["verdict"] = data

    if (
        session_info["started_at"] is not None
        and session_info["ended_at"] is not None
    ):
        session_info["duration_s"] = round(
            session_info["ended_at"] - session_info["started_at"],
            3,
        )

    successful = sum(1 for s in steps if s.get("exit_code") == 0)
    failed = len(steps) - successful
    failed_tools = sum(1 for t in tool_calls if t.get("is_error"))

    return {
        "session": session_info,
        "summary": {
            "total_steps": len(steps),
            "successful_steps": successful,
            "failed_steps": failed,
            "total_tool_calls": len(tool_calls),
            "failed_tool_calls": failed_tools,
            "signals": len(signals),
            "crashes": len(crashes),
            "total_redactions": total_redactions,
        },
        "steps": steps,
        "tool_calls": tool_calls,
        "signals": signals,
        "sandbox_resources": resources,
        "sandbox_crashes": crashes,
        "contract": contract_info,
    }


def _timeline(data: Dict[str, Any]):
    """Steps and tool calls as (kind, entry) in step order."""
    steps = data.get("steps", [])
    tools = data.get("tool_calls", [])

    entries = (
        [("step", d) for d in steps]
        + [("tool", d) for d in tools]
    )

    if tools:
        entries.sort(
            key=lambda entry: entry[1].get("step_index", 0)
        )

    return entries


def _tool_label(d: Dict[str, Any]) -> str:
    return f"{d.get('tool_source', '?')}/{d.get('tool_name', '?')}"


def _preview(value: Any, width: int) -> str:
    return sanitize(" ".join(as_text(value).split()))[:width]


def render_text(data: Dict[str, Any], color: bool = False) -> str:
    """Render the human-readable terminal report matching standard cli format."""
    lines: List[str] = []

    steps = data.get("steps", [])
    tool_calls = data.get("tool_calls", [])
    signals = data.get("signals", [])
    crashes = data.get("sandbox_crashes", [])

    for kind, d in _timeline(data):
        step_idx = d.get("step_index", 0)

        if kind == "tool":
            mark = (
                _paint("ERR", _RED, color)
                if d.get("is_error")
                else "ok "
            )

            lines.append(
                f"[{step_idx:>3}] {mark} tool "
                f"{sanitize(_tool_label(d))} "
                f"({d.get('duration_ms', 0)}ms) "
                f"{_preview(d.get('arguments'), 50)}"
            )
            continue

        ok = d.get("exit_code") == 0
        mark = "ok " if ok else _paint("ERR", _RED, color)

        cmd_str = (d.get("command") or "")[:70]
        exit_code = d.get("exit_code", -1)

        lines.append(
            f"[{step_idx:>3}] {mark} "
            f"exit={exit_code:<3} {cmd_str}"
        )

    if tool_calls:
        lines.append(
            f"\n{len(steps)} steps, "
            f"{len(tool_calls)} tool calls, "
            f"{len(signals)} signals"
        )
    else:
        lines.append(
            f"\n{len(steps)} steps, {len(signals)} signals"
        )

    for s in signals:
        line = (
            f"  step {s['step_index']}: "
            f"[{s['severity']}] {s['kind']} "
            f"(x{s['count']}) - {s['hint']}"
        )

        if s.get("severity") == "critical":
            line = _paint(line, _RED, color)
        elif s.get("severity") == "warn":
            line = _paint(line, _YELLOW, color)

        lines.append(line)

    for c in crashes:
        line = (
            f"  step {c.get('step_index', '?')}: "
            f"crash [{c.get('kind', 'unknown')}] "
            f"exit={c.get('exit_code')} "
            f"(oom={c.get('oom_killed')})"
        )

        line = _paint(line, _RED, color)
        lines.append(line)

    contract = data.get("contract")

    if contract and contract.get("verdict"):
        cv = contract["verdict"]
        passed = cv.get("passed", False)

        status_str = (
            _paint("PASSED", "\033[32m", color)
            if passed
            else _paint("FAILED", _RED, color)
        )

        lines.append(f"\n--- Task Contract: {status_str} ---")
        lines.append(f"  Summary: {cv.get('summary', '')}")

        if cv.get("budget_exceeded"):
            b = cv["budget_exceeded"]

            lines.append(
                _paint(
                    f"  [!] Budget exceeded: {b.get('limit')} "
                    f"({b.get('actual')} > {b.get('budget')})",
                    _RED,
                    color,
                )
            )

        for a in cv.get("assertions", []):
            a_ok = a.get("passed", False)

            mark = (
                _paint("[✓]", "\033[32m", color)
                if a_ok
                else _paint("[✗]", _RED, color)
            )

            lines.append(
                f"  {mark} {a.get('name')}: "
                f"{a.get('details', '')}"
            )

    return "\n".join(lines) + "\n"


def render_json(data: Dict[str, Any]) -> str:
    """Render report as indented JSON."""
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


_HTML_CSS = """
:root {
  --bg: #0d1117; --card-bg: #161b22; --border: #30363d;
  --text: #c9d1d9; --text-muted: #8b949e; --accent: #58a6ff;
  --green: #3fb950; --red: #f85149; --yellow: #d29922; --mono: monospace;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #f6f8fa; --card-bg: #ffffff; --border: #d0d7de;
    --text: #1f2328; --text-muted: #656d76; --accent: #0969da;
    --green: #1a7f37; --red: #cf222e; --yellow: #9a6700;
  }
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg); color: var(--text); padding: 2rem 1rem; line-height: 1.5; }
.container { max-width: 960px; margin: 0 auto; }
header { border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }
h1 { font-size: 1.75rem; margin-bottom: 0.5rem; }
.subtitle { color: var(--text-muted); font-size: 0.9rem; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
.card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; }
.card-label { font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); }
.card-val { font-size: 1.5rem; font-weight: bold; margin-top: 0.25rem; }
.badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }
.badge-ok { background: rgba(63,185,80,0.15); color: var(--green); }
.badge-err { background: rgba(248,81,73,0.15); color: var(--red); }
.badge-warn { background: rgba(210,153,34,0.15); color: var(--yellow); }
section { margin-bottom: 2.5rem; }
h2 { font-size: 1.25rem; margin-bottom: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
.timeline { display: flex; flex-direction: column; gap: 0.75rem; }
.step-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 6px; padding: 0.75rem 1rem; }
.step-header { display: flex; justify-content: space-between; align-items: baseline; gap: 1rem; }
.step-cmd { font-family: var(--mono); font-size: 0.9rem; color: var(--accent); word-break: break-all; }
.step-meta { font-size: 0.8rem; color: var(--text-muted); white-space: nowrap; }
details { margin-top: 0.5rem; border-top: 1px dashed var(--border); padding-top: 0.5rem; font-size: 0.85rem; }
summary { cursor: pointer; color: var(--text-muted); user-select: none; }
summary:hover { color: var(--text); }
pre { font-family: var(--mono); background: rgba(0,0,0,0.15); padding: 0.5rem; border-radius: 4px; overflow-x: auto; margin-top: 0.5rem; }
.signal-box { background: rgba(210,153,34,0.1); border-left: 4px solid var(--yellow); padding: 0.75rem 1rem; margin-bottom: 0.75rem; border-radius: 0 4px 4px 0; }
.signal-box.critical { background: rgba(248,81,73,0.1); border-left-color: var(--red); }
"""


def _html_tool_card(t: Dict[str, Any]) -> str:
    """Render a tool call as an HTML timeline card."""
    ok = not t.get("is_error")

    badge_cls, badge_txt = (
        ("badge-ok", "OK")
        if ok
        else ("badge-err", "ERROR")
    )

    items = []

    if t.get("thought"):
        items.append(
            f'<p><strong>Thought:</strong> '
            f'{html.escape(str(t["thought"]))}</p>'
        )

    for field in ("arguments", "result"):
        if t.get(field) is not None:
            note = (
                " (truncated, full SHA-256 in the log)"
                if t.get(f"{field}_truncated")
                else ""
            )

            items.append(
                f'<p><strong>{field}:</strong>'
                f'{html.escape(note)}'
                f'<pre>{html.escape(sanitize(as_text(t[field])))}</pre></p>'
            )

    if (
        isinstance(t.get("redactions"), dict)
        and sum(t["redactions"].values())
    ):
        items.append(
            f'<p><strong>Secrets removed:</strong> '
            f'{sum(t["redactions"].values())}</p>'
        )

    details = (
        f'<details><summary>Arguments &amp; Result</summary>'
        f'{"".join(items)}</details>'
        if items
        else ""
    )

    return (
        f'<div class="step-card">'
        f'<div class="step-header">'
        f'<div>'
        f'<span class="badge {badge_cls}">{badge_txt}</span> '
        f'<strong>#{t.get("step_index")}</strong> '
        f'<span class="badge badge-warn">tool</span> '
        f'<span class="step-cmd">'
        f'{html.escape(_tool_label(t))}'
        f'</span>'
        f'</div>'
        f'<span class="step-meta">'
        f'{html.escape(str(t.get("duration_ms", 0)))}ms'
        f'</span>'
        f'</div>'
        f'{details}'
        f'</div>'
    )


def render_html(data: Dict[str, Any]) -> str:
    """Render a single, completely self-contained HTML report with zero external assets."""
    sess = data.get("session", {})
    summary = data.get("summary", {})
    signals = data.get("signals", [])
    crashes = data.get("sandbox_crashes", [])

    started_str = (
        datetime.fromtimestamp(sess["started_at"]).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        if sess.get("started_at")
        else "unknown"
    )

    iso = sess.get("isolation", {})
    backend_str = iso.get("backend", "local")

    if iso.get("image"):
        backend_str += f" ({iso.get('image')})"

    out = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">',
        f"<title>agentbox report - {html.escape(str(sess.get('session_id')))}</title>",
        f"<style>{_HTML_CSS}</style>",
        "</head>",
        "<body>",
        '<div class="container">',
        "<header>",
        "<h1>agentbox flight report</h1>",
        (
            f'<div class="subtitle">Session: '
            f'<strong>{html.escape(str(sess.get("session_id")))}</strong> '
            f'&bull; Started: {html.escape(started_str)} '
            f'&bull; Backend: {html.escape(backend_str)}'
            f'{(" &bull; Agent: " + html.escape(str(sess["agent_id"]))) if sess.get("agent_id") else ""}'
            f'</div>'
        ),
        "</header>",
        '<div class="cards">',
        (
            f'<div class="card"><div class="card-label">Steps</div>'
            f'<div class="card-val">{summary.get("total_steps", 0)}</div></div>'
        ),
        (
            f'<div class="card"><div class="card-label">Passed</div>'
            f'<div class="card-val">{summary.get("successful_steps", 0)}</div></div>'
        ),
        (
            f'<div class="card"><div class="card-label">Failed</div>'
            f'<div class="card-val">{summary.get("failed_steps", 0)}</div></div>'
        ),
    ]

    if data.get("tool_calls"):
        out.append(
            f'<div class="card"><div class="card-label">Tool calls</div>'
            f'<div class="card-val">'
            f'{summary.get("total_tool_calls", 0)}'
            f'</div></div>'
        )

    out.extend([
        (
            f'<div class="card"><div class="card-label">Signals</div>'
            f'<div class="card-val">{summary.get("signals", 0)}</div></div>'
        ),
        (
            f'<div class="card"><div class="card-label">Duration</div>'
            f'<div class="card-val">{sess.get("duration_s", 0)}s</div></div>'
        ),
        "</div>",
    ])

    if signals:
        out.append("<section><h2>Detector Signals</h2>")

        for s in signals:
            sev = s.get("severity", "warn")
            cls = "critical" if sev == "critical" else "warn"

            out.append(
                f'<div class="signal-box {cls}">'
                f'<strong>Step {s.get("step_index")}: '
                f'[{html.escape(str(sev))}] '
                f'{html.escape(str(s.get("kind", "")))}</strong> '
                f'(fired {s.get("count")}x)<br>'
                f'{html.escape(str(s.get("hint", "")))}'
                f'</div>'
            )

        out.append("</section>")

    if crashes:
        out.append("<section><h2>Sandbox Crashes</h2>")

        for c in crashes:
            out.append(
                f'<div class="signal-box critical">'
                f'<strong>Step {c.get("step_index", "?")}: '
                f'Crash - {html.escape(str(c.get("kind")))}</strong> '
                f'(exit {c.get("exit_code")}, '
                f'oom={c.get("oom_killed")})'
                f'</div>'
            )

        out.append("</section>")

    contract = data.get("contract")

    if contract and contract.get("verdict"):
        cv = contract["verdict"]
        passed = cv.get("passed", False)

        badge_cls = "badge-ok" if passed else "badge-err"
        badge_txt = "PASSED" if passed else "FAILED"

        out.append(
            f'<section><h2>Task Contract '
            f'<span class="badge {badge_cls}">{badge_txt}</span></h2>'
        )

        out.append(
            f'<p style="margin-bottom: 0.75rem;">'
            f'<strong>Summary:</strong> '
            f'{html.escape(str(cv.get("summary", "")))}</p>'
        )

        if cv.get("budget_exceeded"):
            b = cv["budget_exceeded"]

            out.append(
                f'<div class="signal-box critical" '
                f'style="margin-bottom: 0.75rem;">'
                f'<strong>Budget Exceeded:</strong> '
                f'{html.escape(str(b.get("limit")))} '
                f'({b.get("actual")} &gt; {b.get("budget")})'
                f'</div>'
            )

        if cv.get("assertions"):
            out.append('<div class="timeline">')

            for a in cv["assertions"]:
                a_ok = a.get("passed", False)
                a_badge = "badge-ok" if a_ok else "badge-err"
                a_mark = "✓" if a_ok else "✗"

                out.append(
                    f'<div class="step-card">'
                    f'<div class="step-header">'
                    f'<div><span class="badge {a_badge}">'
                    f'{a_mark}</span> '
                    f'<strong>{html.escape(str(a.get("name", "")))}</strong>'
                    f'</div>'
                    f'<span class="step-meta">'
                    f'{html.escape(str(a.get("details", "")))}'
                    f'</span>'
                    f'</div></div>'
                )

            out.append("</div>")

        out.append("</section>")

    out.append(
        '<section><h2>Step Timeline</h2>'
        '<div class="timeline">'
    )

    for kind, s in _timeline(data):
        if kind == "tool":
            out.append(_html_tool_card(s))
            continue

        ec = s.get("exit_code", 0)
        badge_cls = "badge-ok" if ec == 0 else "badge-err"
        badge_txt = "OK" if ec == 0 else f"ERR ({ec})"

        dur = f"{s.get('duration_ms', 0)}ms"
        cmd = s.get("command", "")

        out.append(
            f'<div class="step-card">'
            f'<div class="step-header">'
            f'<div><span class="badge {badge_cls}">'
            f'{badge_txt}</span> '
            f'<strong>#{s.get("step_index")}</strong> '
            f'<span class="step-cmd">{html.escape(str(cmd))}</span>'
            f'</div>'
            f'<span class="step-meta">{html.escape(dur)}</span>'
            f'</div>'
        )

        details_items = []

        if s.get("thought"):
            details_items.append(
                f'<p><strong>Thought:</strong> '
                f'{html.escape(str(s["thought"]))}</p>'
            )

        if s.get("tool"):
            details_items.append(
                f'<p><strong>Tool:</strong> '
                f'{html.escape(str(s["tool"]))}</p>'
            )
            
        if s.get("error_class"):
            details_items.append(
                f'<p><strong>Error Class:</strong> '
                f'{html.escape(str(s["error_class"]))}</p>'
            )

        if s.get("error_signature"):
            details_items.append(
                f'<p><strong>Error Signature:</strong> '
                f'<code>{html.escape(str(s["error_signature"]))}</code></p>'
            )

        stdout_text = (s.get("stdout") or {}).get("text")

        if stdout_text:
            details_items.append(
                f'<p><strong>stdout:</strong>'
                f'<pre>{html.escape(str(stdout_text))}</pre></p>'
            )

        stderr_text = (s.get("stderr") or {}).get("text")

        if stderr_text:
            details_items.append(
                f'<p><strong>stderr:</strong>'
                f'<pre>{html.escape(str(stderr_text))}</pre></p>'
            )

        if details_items:
            out.append(
                f'<details><summary>Details &amp; Output</summary>'
                f'{"".join(details_items)}</details>'
            )

        out.append("</div>")

    out.append("</div></section>")
    out.append("</div></body></html>\n")

    return "\n".join(out)
