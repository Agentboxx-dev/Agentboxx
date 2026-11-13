"""Replay core: turn a log into frames, navigate them, read keys, render plain text.

Standard library only. The optional rich-based terminal UI lives in `replay_ui.py`;
everything here also backs `agentbox replay --plain`, so it works without rich.
"""
import json
import os
import sys
import textwrap
import time
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from .toolcall import as_text

VERIFIED = "VERIFIED"
TAMPERED = "TAMPERED"
INCOMPLETE = "INCOMPLETE"

_BADGES = {VERIFIED: "VERIFIED ✓", TAMPERED: "TAMPERED ✗", INCOMPLETE: "INCOMPLETE ⚠"}
_EXIT_CODES = {VERIFIED: 0, TAMPERED: 1, INCOMPLETE: 2}


@dataclass
class Verdict:
    status: str = VERIFIED
    problems: List[str] = field(default_factory=list)

    @property
    def badge(self) -> str:
        return _BADGES.get(self.status, self.status)

    @property
    def exit_code(self) -> int:
        return _EXIT_CODES.get(self.status, 1)


@dataclass
class Frame:
    """Everything that happened at one step, gathered from the events that share its step_index."""
    index: int                      # 0-based position in the replay
    step_index: Any                 # the recorder's own step number
    ts: Optional[float]
    thought: str
    command: str
    exit_code: Optional[int]
    timed_out: bool
    duration_ms: Optional[float]
    stdout: str
    stderr: str
    output_truncated: bool
    total_bytes: int
    error_class: Optional[str]
    signals: List[Dict[str, Any]] = field(default_factory=list)
    resource: Optional[Dict[str, Any]] = None
    crash: Optional[Dict[str, Any]] = None
    kind: str = "step"              # "step" (a command) or "tool" (a tool.call)

    @property
    def label(self) -> str:
        return "TOOL CALL" if self.kind == "tool" else "COMMAND"

    @property
    def prompt(self) -> str:
        return "" if self.kind == "tool" else "$ "

    @property
    def failed(self) -> bool:
        return (
            self.timed_out
            or (self.exit_code is not None and self.exit_code != 0)
            or self.crash is not None
        )

@dataclass
class Session:
    session_id: str = "unknown"
    agent_id: Optional[str] = None
    isolation: Dict[str, Any] = field(default_factory=dict)
    started_at: Optional[float] = None
    end_reason: Optional[str] = None
    frames: List[Frame] = field(default_factory=list)
    parse_errors: List[str] = field(default_factory=list)


# ---------- reading the log ----------

def load_events_tolerant(path) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Read every readable event; report unreadable lines instead of stopping at the first.

    A tampered log is exactly the one you want to inspect, so replay must not refuse it.
    """
    events: List[Dict[str, Any]] = []
    errors: List[str] = []
    with open(path, encoding="utf-8", errors="replace") as f:
        data = f.read()
    for n, line in enumerate(data.split("\n"), 1):
        if not line.strip():
            continue
        try:
            ev = json.loads(line)["event"]
            ev["event_type"]
            if not isinstance(ev, dict):
                raise TypeError
        except (ValueError, KeyError, TypeError):
            errors.append(f"line {n}: unreadable record")
            continue
        events.append(ev)
    return events, errors


def _stream(value: Any) -> Tuple[str, bool, int]:
    if isinstance(value, dict):
        text = value.get("text")
        total = value.get("total_bytes")
        return (text if isinstance(text, str) else "",
                bool(value.get("truncated")),
                total if isinstance(total, int) else 0)
    if isinstance(value, str):
        return value, False, len(value.encode("utf-8", "replace"))
    return "", False, 0


def build_session(events: List[Dict[str, Any]], parse_errors: Optional[List[str]] = None) -> Session:
    """Group events into one frame per `step`, attaching signals, resources and crashes by step_index."""
    sess = Session(parse_errors=list(parse_errors or []))
    by_step: Dict[Any, Frame] = {}
    pending: List[Tuple[str, Dict[str, Any]]] = []

    for ev in events:
        etype = ev.get("event_type")
        data = ev.get("data")
        data = data if isinstance(data, dict) else {}
        if etype == "session.start":
            sess.session_id = str(data.get("session_id", sess.session_id))
            sess.agent_id = data.get("agent_id")
            sess.isolation = data.get("isolation") if isinstance(data.get("isolation"), dict) else {}
            ts = ev.get("ts")
            sess.started_at = ts if isinstance(ts, (int, float)) else None
        elif etype == "session.end":
            sess.end_reason = data.get("reason")
        elif etype == "step":
            out, out_trunc, out_total = _stream(data.get("stdout"))
            err, err_trunc, err_total = _stream(data.get("stderr"))
            ts = ev.get("ts")
            code = data.get("exit_code")
            dur = data.get("duration_ms")
            frame = Frame(
                index=len(sess.frames),
                step_index=data.get("step_index", len(sess.frames) + 1),
                ts=ts if isinstance(ts, (int, float)) else None,
                thought=str(data.get("thought") or ""),
                command=str(data.get("command") or ""),
                exit_code=code if isinstance(code, int) else None,
                timed_out=bool(data.get("timed_out")),
                duration_ms=dur if isinstance(dur, (int, float)) else None,
                stdout=out, stderr=err,
                output_truncated=out_trunc or err_trunc or bool(data.get("output_limit_exceeded")),
                total_bytes=out_total + err_total,
                error_class=data.get("error_class"),
            )
            sess.frames.append(frame)
            by_step[frame.step_index] = frame
        elif etype == "tool.call":
            # A tool call is one step (it shares step_index), so it gets a frame like a command does.
            text = as_text(data.get("result"))
            is_err = bool(data.get("is_error"))
            ts = ev.get("ts")
            dur = data.get("duration_ms")
            args = " ".join(as_text(data.get("arguments")).split())
            label = f"{data.get('tool_source', '?')}/{data.get('tool_name', '?')}"
            frame = Frame(
                index=len(sess.frames),
                step_index=data.get("step_index", len(sess.frames) + 1),
                ts=ts if isinstance(ts, (int, float)) else None,
                thought=str(data.get("thought") or ""),
                command=f"{label} {args}".strip(),
                exit_code=1 if is_err else 0,
                timed_out=False,
                duration_ms=dur if isinstance(dur, (int, float)) else None,
                stdout="" if is_err else text,
                stderr=text if is_err else "",
                output_truncated=bool(data.get("result_truncated")),
                total_bytes=len(text.encode("utf-8", "replace")),
                error_class=None,
                kind="tool",
            )
            sess.frames.append(frame)
            by_step[frame.step_index] = frame
        elif etype in ("analysis.signal", "sandbox.resource", "sandbox.crash"):
            pending.append((etype, data))

    # These events follow their step in the log; attach them once every step is known.
    for etype, data in pending:
        target = by_step.get(data.get("step_index"))
        if target is None:
            continue
        if etype == "analysis.signal":
            target.signals.append(data)
        elif etype == "sandbox.resource":
            target.resource = data
        else:
            target.crash = data
    return sess


# ---------- navigation ----------

class ReplayState:
    """Cursor over the frames. Stepping past an end stops with a notice, or wraps if loop=True."""

    def __init__(self, total: int, loop: bool = False):
        self.total = total
        self.loop = loop
        self.index = 0
        self.notice = ""

    @property
    def at_start(self) -> bool:
        return self.index <= 0

    @property
    def at_end(self) -> bool:
        return self.index >= self.total - 1

    def next(self) -> bool:
        if self.total == 0:
            return False
        if self.at_end:
            if self.loop:
                self.index, self.notice = 0, "Wrapped to the first step"
                return True
            self.notice = "End of session"
            return False
        self.index += 1
        self.notice = ""
        return True

    def prev(self) -> bool:
        if self.total == 0:
            return False
        if self.at_start:
            if self.loop:
                self.index, self.notice = self.total - 1, "Wrapped to the last step"
                return True
            self.notice = "Start of session"
            return False
        self.index -= 1
        self.notice = ""
        return True

    def home(self) -> bool:
        moved = self.index != 0
        self.index, self.notice = 0, ""
        return moved

    def end(self) -> bool:
        last = max(self.total - 1, 0)
        moved = self.index != last
        self.index, self.notice = last, ""
        return moved


# ---------- text helpers ----------

def sanitize(text: str) -> str:
    """Make untrusted log text safe to print: control characters (including ESC) become visible.

    Agent output is attacker-controlled; raw escape sequences could rewrite the screen or
    hide the TAMPERED banner. Newlines are kept, tabs become spaces.
    """
    out = []
    for ch in text:
        if ch == "\n":
            out.append(ch)
        elif ch == "\t":
            out.append("    ")
        elif ch == "\r":
            out.append("␍")
        elif ord(ch) < 32:
            out.append(chr(0x2400 + ord(ch)))
        elif ord(ch) == 127:
            out.append("␡")
        elif unicodedata.category(ch) in ("Cc", "Cf") and ch not in ("\u200d", "\u200c"):
            out.append("�")
        else:
            out.append(ch)
    return "".join(out)


def fmt_ts(ts: Optional[float]) -> str:
    if ts is None:
        return "-"
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return "-"


def fmt_duration(ms: Optional[float]) -> str:
    return "-" if ms is None else f"{ms / 1000:.2f}s"


def fmt_stats(frame: Frame) -> str:
    sig = ("; ".join(f"{s.get('kind', '?')} ({s.get('severity', '?')})" for s in frame.signals)
           if frame.signals else "None")
    parts = [f"Signals: {sig}"]
    r = frame.resource
    if r:
        mb = lambda v: f"{v / 1048576:.0f} MB" if isinstance(v, (int, float)) else "?"  # noqa: E731
        pct = f" ({r['mem_pct']:.0f}%)" if isinstance(r.get("mem_pct"), (int, float)) else ""
        parts.append(f"RAM: {mb(r.get('mem_bytes'))} / {mb(r.get('mem_limit_bytes'))}{pct}")
        if isinstance(r.get("cpu_pct"), (int, float)):
            parts.append(f"CPU: {r['cpu_pct']:.0f}%")
        if r.get("pids") is not None:
            parts.append(f"PIDs: {r['pids']}")
    else:
        parts.append("Resources: n/a")
    if frame.crash:
        c = frame.crash
        parts.append("CRASH: " + str(c.get("kind", "unknown")) + (" (OOM killed)" if c.get("oom_killed") else ""))
    return " | ".join(parts)


def scrubber_cells(frames: List[Frame], index: int, max_cells: int) -> List[Tuple[str, str]]:
    """The dot track: (symbol, kind) cells, kind in current/failed/done/todo.

    Longer sessions than max_cells show a window around the current step.
    """
    n = len(frames)
    if n == 0 or max_cells <= 0:
        return []
    lo, hi = 0, n
    if n > max_cells:
        lo = min(max(index - max_cells // 2, 0), n - max_cells)
        hi = lo + max_cells
    cells = []
    for i in range(lo, hi):
        if i == index:
            cells.append(("◉", "current"))
        elif frames[i].failed:
            cells.append(("●", "failed"))
        elif i < index:
            cells.append(("●", "done"))
        else:
            cells.append(("○", "todo"))
    return cells


def banner_text(verdict: Verdict, session: Session) -> str:
    """One line shown prominently when the log is not verified; empty when it is."""
    if verdict.status == VERIFIED and not session.parse_errors:
        return ""
    problems = list(verdict.problems) or (
        ["never closed: no session.end record and no manifest"] if verdict.status == INCOMPLETE else [])
    problems += [p for p in session.parse_errors if p not in problems]
    if not problems:
        return ""
    more = f" (+{len(problems) - 1} more, press v)" if len(problems) > 1 else ""
    return f"{verdict.status}: {sanitize(problems[0])}{more}"


# ---------- plain renderer (stdlib only) ----------

def _wrap(text: str, width: int) -> List[str]:
    lines: List[str] = []
    for raw in sanitize(text).split("\n"):
        lines.extend(textwrap.wrap(raw, width, drop_whitespace=False, replace_whitespace=False,
                                   break_long_words=True) or [""])
    return lines


def output_lines(frame: Frame, width: int, limit: int) -> List[Tuple[str, str]]:
    """Output as (text, stream) pairs, newest lines kept when it does not fit."""
    pairs: List[Tuple[str, str]] = []
    for stream, text in (("stdout", frame.stdout), ("stderr", frame.stderr)):
        if text.strip():
            pairs.extend((ln, stream) for ln in _wrap(text.rstrip("\n"), width))
    if not pairs:
        return [("(no output)", "dim")]
    if len(pairs) > limit:
        pairs = [(f"... {len(pairs) - limit} earlier line(s) not shown ...", "dim")] + pairs[-limit:]
    if frame.output_truncated:
        pairs.append((f"[recorder kept head and tail only; {frame.total_bytes} bytes in total]", "dim"))
    return pairs


def render_plain(session: Session, index: int, verdict: Verdict, width: int = 80,
                 max_output_lines: int = 20) -> str:
    """One frame as a boxed block of plain text (no ANSI), used for --plain and non-terminals."""
    width = max(width, 40)
    inner = width - 4
    bar = "+" + "-" * (width - 2) + "+"

    def row(text: str = "") -> str:
        return "| " + text.ljust(inner)[:inner] + " |"

    total = len(session.frames)
    out = [bar]
    step = f"Step [{index + 1:02d}/{total:02d}]" if total else "Step [00/00]"
    head = f"AGENTBOXX REPLAY  {step}  [{verdict.badge}]"
    out.append(row(head))
    out.append(row(f"Session: {sanitize(session.session_id)}"
                   + (f"   Agent: {sanitize(str(session.agent_id))}" if session.agent_id else "")))
    banner = banner_text(verdict, session)
    for ln in _wrap("!! " + banner, inner) if banner else []:
        out.append(row(ln))
    out.append(bar)
    if not total:
        out.append(row("No steps were recorded in this session."))
        if session.end_reason:
            out.append(row(f"Ended: {sanitize(str(session.end_reason))}"))
        out.append(bar)
        return "\n".join(out)

    f = session.frames[index]
    out.append(row(f"Timestamp: {fmt_ts(f.ts)}"))
    out.append(bar)
    out.append(row("[THOUGHT]"))
    for ln in _wrap(f.thought or "(none)", inner):
        out.append(row(ln))
    out.append(bar)
    code = "timed out" if f.timed_out else ("?" if f.exit_code is None else f.exit_code)
    out.append(row(f"[{f.label}] (exit code: {code} | duration: {fmt_duration(f.duration_ms)})"))
    for ln in _wrap(f.prompt + (f.command or ""), inner):
        out.append(row(ln))
    out.append(bar)
    out.append(row("[OUTPUT]"))
    for text, stream in output_lines(f, inner, max_output_lines):
        out.append(row(("[stderr] " if stream == "stderr" else "") + text))
    out.append(bar)
    out.append(row("[ANALYSIS & STATS]"))
    for ln in _wrap(fmt_stats(f), inner):
        out.append(row(ln))
    out.append(bar)
    return "\n".join(out)


# ---------- keyboard ----------

KEY_NEXT, KEY_PREV, KEY_HOME, KEY_END = "next", "prev", "home", "end"
KEY_VERIFY, KEY_QUIT, KEY_AUTOPLAY = "verify", "quit", "autoplay"

_CHAR_KEYS = {
    " ": KEY_NEXT, "n": KEY_NEXT, "N": KEY_NEXT,
    "p": KEY_PREV, "P": KEY_PREV,
    "v": KEY_VERIFY, "V": KEY_VERIFY,
    "q": KEY_QUIT, "Q": KEY_QUIT, "\x03": KEY_QUIT,
    "a": KEY_AUTOPLAY, "A": KEY_AUTOPLAY,
}
_ESC_KEYS = {
    "[C": KEY_NEXT, "OC": KEY_NEXT, "[D": KEY_PREV, "OD": KEY_PREV,
    "[H": KEY_HOME, "OH": KEY_HOME, "[1~": KEY_HOME, "[7~": KEY_HOME,
    "[F": KEY_END, "OF": KEY_END, "[4~": KEY_END, "[8~": KEY_END,
}
_WIN_KEYS = {"M": KEY_NEXT, "K": KEY_PREV, "G": KEY_HOME, "O": KEY_END}


def decode_char(ch: str) -> Optional[str]:
    return _CHAR_KEYS.get(ch)


def decode_escape(seq: str) -> Optional[str]:
    """A bare Esc quits; known arrow/Home/End sequences map to actions; anything else is ignored."""
    return KEY_QUIT if seq == "" else _ESC_KEYS.get(seq)


def decode_windows_key(prefix: str, get_second: Callable[[], str]) -> Optional[str]:
    """Windows delivers arrows as a \\x00 or \\xe0 prefix followed by a second code."""
    return _WIN_KEYS.get(get_second()) if prefix in ("\x00", "\xe0") else None


class KeyReader:
    """Context manager that reads single keys. Always restores the terminal on exit.

    read(timeout) returns an action name, or None when nothing relevant was pressed in time.
    """

    def __init__(self, fd: Optional[int] = None):
        self._win = sys.platform == "win32"
        self.fd = fd if fd is not None else (None if self._win else sys.stdin.fileno())
        self._saved = None

    def __enter__(self):
        if not self._win:
            import termios
            import tty
            self._saved = termios.tcgetattr(self.fd)
            tty.setcbreak(self.fd)
        return self

    def __exit__(self, *exc):
        if not self._win and self._saved is not None:
            import termios
            termios.tcsetattr(self.fd, termios.TCSADRAIN, self._saved)
            self._saved = None
        return False

    def read(self, timeout: float) -> Optional[str]:
        return self._read_windows(timeout) if self._win else self._read_posix(timeout)

    def _read_posix(self, timeout: float) -> Optional[str]:
        import select
        if not select.select([self.fd], [], [], timeout)[0]:
            return None
        first = os.read(self.fd, 1)
        if first != b"\x1b":
            return decode_char(first.decode("utf-8", "ignore"))
        seq = b""
        while len(seq) < 8 and select.select([self.fd], [], [], 0.03)[0]:
            seq += os.read(self.fd, 1)
            if seq[-1:].isalpha() or seq[-1:] == b"~":
                break
        return decode_escape(seq.decode("ascii", "ignore"))

    def _read_windows(self, timeout: float) -> Optional[str]:
        import msvcrt
        deadline = time.monotonic() + timeout
        while True:
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                if ch in ("\x00", "\xe0"):
                    return decode_windows_key(ch, msvcrt.getwch)
                return KEY_QUIT if ch == "\x1b" else decode_char(ch)
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.01)