"""Interactive terminal UI for `agentbox replay`. Needs the optional `rich` package (agentboxx[ui])."""
from typing import Callable, Optional

from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from .replay import (
    INCOMPLETE,
    KEY_AUTOPLAY,
    KEY_END,
    KEY_HOME,
    KEY_NEXT,
    KEY_PREV,
    KEY_QUIT,
    KEY_VERIFY,
    TAMPERED,
    VERIFIED,
    Frame,
    ReplayState,
    Session,
    Verdict,
    banner_text,
    fmt_duration,
    fmt_stats,
    output_lines,
    sanitize,
    scrubber_cells,
)

AMBER = "#FF6B00"
_BADGE_STYLE = {VERIFIED: "bold green", TAMPERED: "bold white on red", INCOMPLETE: "bold black on yellow"}
_CELL_STYLE = {"current": f"bold {AMBER}", "failed": "bold red", "done": "green", "todo": "dim"}
_HINTS = "[←/p Prev]  [→/Space/n Next]  [Home/End]  [a Autoplay]  [v Verify]  [q Quit]"
# Rows used by everything except the output block: borders, header, banner, thought, command, stats, rules.
_CHROME_ROWS = 17


def _header(session: Session, state: ReplayState, verdict: Verdict, width: int, autoplay: bool) -> RenderableType:
    total = len(session.frames)
    step = f"Step [{state.index + 1:02d}/{total:02d}]" if total else "Step [00/00]"
    track = Text()
    for symbol, kind in scrubber_cells(session.frames, state.index, max(width - 52, 0)):
        track.append(symbol + " ", style=_CELL_STYLE[kind])
    right = Text()
    right.append(step + "  ", style="bold")
    right.append(f" {verdict.badge} ", style=_BADGE_STYLE.get(verdict.status, "bold"))
    if autoplay:
        right.append("  ▶ AUTO", style=f"bold {AMBER}")
    grid = Table.grid(expand=True)
    grid.add_column(ratio=1)
    grid.add_column(justify="right")
    grid.add_row(track, right)
    meta = Text()
    meta.append("Session: ", style="dim")
    meta.append(sanitize(session.session_id), style="bold")
    if session.agent_id:
        meta.append("   Agent: ", style="dim")
        meta.append(sanitize(str(session.agent_id)))
    return Group(grid, meta)


def _section(title: str, body: RenderableType) -> RenderableType:
    return Group(Rule(Text(title, style=f"bold {AMBER}"), align="left", style=AMBER), body)


def _frame_body(frame: Frame, height: int) -> RenderableType:
    thought = Text(sanitize(frame.thought) if frame.thought else "(none)", style="italic")

    code = "timed out" if frame.timed_out else ("?" if frame.exit_code is None else str(frame.exit_code))
    cmd_title = Text("COMMAND  ", style=f"bold {AMBER}")
    cmd_title.append(f"(exit code: {code} | duration: {fmt_duration(frame.duration_ms)})",
                     style="bold red" if frame.failed else "dim")
    cmd = Table.grid(padding=(0, 1))
    cmd.add_column(no_wrap=True)
    cmd.add_column(ratio=1)
    cmd.add_row(Text("$", style=f"bold {AMBER}"),
                Syntax(sanitize(frame.command), "bash", theme="ansi_dark", background_color="default",
                       word_wrap=True))

    limit = max(height - _CHROME_ROWS, 3)
    out = Text()
    for i, (line, stream) in enumerate(output_lines(frame, 200, limit)):
        out.append(("\n" if i else "") + line, style={"stderr": "red", "dim": "dim"}.get(stream, ""))

    stats = Text(fmt_stats(frame), style="bold red" if frame.crash else "")
    return Group(
        _section("THOUGHT", thought),
        Rule(cmd_title, align="left", style=AMBER), cmd,
        _section("OUTPUT", out),
        _section("ANALYSIS & STATS", stats),
    )


def build_view(session: Session, state: ReplayState, verdict: Verdict, console: Console,
               autoplay: bool = False) -> RenderableType:
    parts = [_header(session, state, verdict, console.width, autoplay)]
    banner = banner_text(verdict, session)
    if banner:
        parts.append(Text(" " + banner + " ", style=_BADGE_STYLE.get(verdict.status, "bold white on red")))
    if session.frames:
        parts.append(_frame_body(session.frames[state.index], console.height))
    else:
        parts.append(Text("\nNo steps were recorded in this session.", style="dim"))
        if session.end_reason:
            parts.append(Text(f"Ended: {sanitize(str(session.end_reason))}", style="dim"))
    footer = Text(_HINTS, style="dim")
    if state.notice:
        footer = Text(state.notice + "   ", style=f"bold {AMBER}") + footer
    border = {VERIFIED: AMBER, TAMPERED: "red", INCOMPLETE: "yellow"}.get(verdict.status, AMBER)
    return Panel(Group(*parts), title=Text(" AGENTBOXX REPLAY ", style=f"bold {AMBER}"), title_align="left",
                 subtitle=footer, border_style=border, padding=(0, 1))


def run_tui(session: Session, state: ReplayState, verdict: Verdict, keys, verify: Callable[[], Verdict],
            console: Optional[Console] = None, autoplay: bool = False, delay: float = 1.0,
            tick: float = 0.2) -> Verdict:
    """Draw frames and handle keys until quit. `keys.read(timeout)` yields action names or None.

    The caller owns terminal state (KeyReader restores it); Live(screen=True) restores the screen.
    Returns the latest verdict, so the CLI can mirror it in the exit code.
    """
    console = console or Console()
    size = console.size
    waited = 0.0
    with Live(console=console, screen=True, auto_refresh=False, transient=True) as live:
        def draw():
            live.update(build_view(session, state, verdict, console, autoplay), refresh=True)

        draw()
        try:
            while True:
                key = keys.read(tick)
                if key is None:
                    if autoplay:
                        waited += tick
                        if waited >= delay:
                            waited = 0.0
                            if not state.next():
                                autoplay = False            # reached the end: stop, do not loop forever
                            draw()
                            continue
                    if console.size != size:                # terminal was resized
                        size = console.size
                        draw()
                    continue
                if key == KEY_QUIT:
                    break
                if key == KEY_NEXT:
                    state.next()
                elif key == KEY_PREV:
                    state.prev()
                elif key == KEY_HOME:
                    state.home()
                elif key == KEY_END:
                    state.end()
                elif key == KEY_AUTOPLAY:
                    autoplay, waited = not autoplay, 0.0
                    state.notice = "Autoplay on" if autoplay else "Autoplay off"
                elif key == KEY_VERIFY:
                    try:
                        verdict = verify()
                        state.notice = f"Re-verified: {verdict.status}"
                    except Exception as exc:                # e.g. the log file was removed meanwhile
                        state.notice = f"Verify failed: {exc}"
                draw()
        except KeyboardInterrupt:
            pass
    return verdict