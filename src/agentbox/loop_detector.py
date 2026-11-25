"""Detects an agent that is stuck."""
from collections import deque
from dataclasses import dataclass


@dataclass
class LoopConfig:
    """Configuration thresholds for the LoopDetector engine."""

    window: int = 10
    exact_warn: int = 3
    exact_crit: int = 5
    error_warn: int = 3
    error_crit: int = 5
    no_progress_warn: int = 4

    @classmethod
    def coding_agent(cls) -> "LoopConfig":
        """Calibrated against SWE-bench software engineering trajectories.

        Permits iterative test-driven development (TDD) and multi-step debugging,
        while catching repetitive error loops and oscillating command cycles.
        """
        return cls(
            window=15,
            exact_warn=4,
            exact_crit=6,
            error_warn=4,
            error_crit=6,
            no_progress_warn=6,
        )

    @classmethod
    def conservative(cls) -> "LoopConfig":
        """Permissive profile for exploratory or long-horizon agents."""
        return cls(
            window=20,
            exact_warn=5,
            exact_crit=8,
            error_warn=5,
            error_crit=8,
            no_progress_warn=8,
        )

    @classmethod
    def aggressive(cls) -> "LoopConfig":
        """High-sensitivity profile for strict token and cost budgets."""
        return cls(
            window=8,
            exact_warn=2,
            exact_crit=4,
            error_warn=2,
            error_crit=4,
            no_progress_warn=3,
        )

    @classmethod
    def default(cls) -> "LoopConfig":
        """Standard balanced profile."""
        return cls()


class LoopDetector:
    def __init__(self, cfg: LoopConfig | None = None):
        self.cfg = cfg or LoopConfig()
        self.win: deque = deque(maxlen=self.cfg.window)

    def observe(self, step: dict) -> list[dict]:
        self.win.append(step)
        signals = []
        signals += self._exact(step)
        signals += self._error_repeat(step)
        signals += self._no_progress()
        signals += self._cycle()
        return signals

    @staticmethod
    def _sig(kind, severity, count, hint):
        return {"kind": kind, "severity": severity, "count": count, "hint": hint}

    def _exact(self, s):
        n = sum(1 for x in self.win if x["command_fingerprint"] == s["command_fingerprint"]
                and x["workspace_hash"] == s["workspace_hash"])   # same command on unchanged files
        if n >= self.cfg.exact_crit:
            return [self._sig("loop.exact", "critical", n, "Same command repeated. Stop and change approach.")]
        if n >= self.cfg.exact_warn:
            return [self._sig("loop.exact", "warn", n, "Same command repeated. Try something different.")]
        return []

    def _error_repeat(self, s):
        if not s.get("error_signature"):
            return []
        n = sum(1 for x in self.win if x.get("error_signature") == s["error_signature"])
        if n >= self.cfg.error_crit:
            return [self._sig("loop.error_repeat", "critical", n, "Same error again and again. Re-plan.")]
        if n >= self.cfg.error_warn:
            return [self._sig("loop.error_repeat", "warn", n, "Same error recurring. Form a new hypothesis.")]
        return []

    def _no_progress(self):
        steps = list(self.win)
        run = 0
        for x in reversed(steps):
            if x["workspace_hash"] == steps[-1]["workspace_hash"]:
                run += 1
            else:
                break
        failing = sum(1 for x in steps[-run:] if x["exit_code"] != 0)
        if run >= self.cfg.no_progress_warn and failing >= max(1, int(run * 0.8)):
            return [self._sig("loop.no_progress", "warn", run, "No files changed across several failing steps.")]
        return []

    def _cycle(self):
        seq = [x["command_fingerprint"] for x in self.win]
        for L in (2, 3):
            if len(seq) >= 2 * L and seq[-L:] == seq[-2 * L : -L] and len(set(seq[-L:])) > 1:
                return [self._sig("loop.cycle", "warn", 2, f"Repeating a cycle of {L} commands.")]
        return []
