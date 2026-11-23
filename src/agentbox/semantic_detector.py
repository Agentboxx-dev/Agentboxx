"""Semantic drift and circular reasoning detector for agent thoughts."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import math
import re
from typing import Callable, Optional
import warnings


@dataclass
class SemanticDriftConfig:
    drift_threshold: float = 0.40
    repetition_threshold: float = 0.88
    window_size: int = 5
    drift_warn: int = 3
    repetition_warn: int = 3
    repetition_crit: int = 5


def cosine_similarity(v1: list[float], v2: list[float]) -> float:
    """Calculate cosine similarity between two numeric vectors."""
    if not v1 or not v2 or len(v1) != len(v2):
        return 0.0
    dot = sum(a * b for a, b in zip(v1, v2))
    norm1 = math.sqrt(sum(a * a for a in v1))
    norm2 = math.sqrt(sum(b * b for b in v2))
    if norm1 == 0.0 or norm2 == 0.0:
        return 0.0
    sim = dot / (norm1 * norm2)
    return max(-1.0, min(1.0, sim))


def stdlib_embed(text: str, dim: int = 256) -> list[float]:
    """Default standard-library bag-of-words and character n-gram hashing vectorizer.

    Produces a fixed-size L2-normalized vector using only Python stdlib.
    Zero external dependencies.
    """
    cleaned = (text or "").strip().lower()
    if not cleaned:
        return [0.0] * dim

    vec = [0.0] * dim

    # Word unigrams and bigrams
    words = re.findall(r"\w+", cleaned)
    for w in words:
        h = int(hashlib.md5(w.encode("utf-8"), usedforsecurity=False).hexdigest(), 16) % dim
        vec[h] += 1.0

    for i in range(len(words) - 1):
        bg = f"{words[i]}_{words[i+1]}"
        h = int(hashlib.md5(bg.encode("utf-8")).hexdigest(), 16) % dim
        vec[h] += 1.5

    # Character trigrams for morphological and rephrasing similarity
    for i in range(len(cleaned) - 2):
        tri = cleaned[i : i + 3]
        h = int(hashlib.md5(tri.encode("utf-8")).hexdigest(), 16) % dim
        vec[h] += 0.5

    # L2 normalize
    norm = math.sqrt(sum(x * x for x in vec))
    if norm > 0:
        vec = [x / norm for x in vec]
    return vec


def get_default_embedder() -> Callable[[str], list[float]]:
    """Return default embedding function.

    Attempts to use fastembed if installed; falls back to stdlib_embed with a warning.
    """
    try:
        from fastembed import TextEmbedding  # type: ignore

        model = TextEmbedding()

        def _fastembed_fn(text: str) -> list[float]:
            gen = model.embed([text])
            return list(next(gen))

        return _fastembed_fn
    except ImportError:
        warnings.warn(
            "fastembed is not installed; falling back to stdlib n-gram embedder. "
            "Install agentboxx[embeddings] for neural embeddings.",
            UserWarning,
            stacklevel=2,
        )
        return stdlib_embed


class SemanticDriftDetector:
    """Detects semantic repetition (circular reasoning) and goal drift in agent thoughts."""

    def __init__(
        self,
        goal: Optional[str] = None,
        cfg: Optional[SemanticDriftConfig] = None,
        embed_fn: Optional[Callable[[str], list[float]]] = None,
    ):
        self.cfg = cfg or SemanticDriftConfig()
        self.embed_fn = embed_fn or stdlib_embed
        self.win: deque[dict] = deque(maxlen=self.cfg.window_size)
        self._repetition_count: int = 0
        self._drift_count: int = 0
        self.goal: Optional[str] = None
        self.goal_embedding: Optional[list[float]] = None
        self.set_goal(goal)

    def set_goal(self, goal: Optional[str]) -> None:
        """Update or initialize the task goal and its cached embedding."""
        if goal is not None and goal.strip():
            self.goal = goal.strip()
            self.goal_embedding = self.embed_fn(self.goal)
        else:
            self.goal = None
            self.goal_embedding = None
        self._drift_count = 0

    @staticmethod
    def _sig(kind: str, severity: str, count: int, hint: str, step_index: int) -> dict:
        return {
            "step_index": step_index,
            "kind": kind,
            "severity": severity,
            "count": count,
            "hint": hint,
        }

    def observe(self, thought: str, step_index: int = 1) -> list[dict]:
        """Observe an agent thought for the given step index and return any analysis signals."""
        cleaned = (thought or "").strip()
        if not cleaned:
            return []

        emb = self.embed_fn(cleaned)
        signals: list[dict] = []

        # 1. semantic_loop detection across consecutive steps
        if self.win:
            prev_emb = self.win[-1]["embedding"]
            sim = cosine_similarity(emb, prev_emb)
            if sim >= self.cfg.repetition_threshold:
                self._repetition_count += 1
            else:
                self._repetition_count = 1
        else:
            self._repetition_count = 1

        if self._repetition_count >= self.cfg.repetition_crit:
            signals.append(
                self._sig(
                    kind="semantic_loop",
                    severity="critical",
                    count=self._repetition_count,
                    hint="Thought repetition detected. You appear to be rephrasing the same plan; try a fundamentally different approach.",
                    step_index=step_index,
                )
            )
        elif self._repetition_count >= self.cfg.repetition_warn:
            signals.append(
                self._sig(
                    kind="semantic_loop",
                    severity="warn",
                    count=self._repetition_count,
                    hint="Thought repetition detected. You appear to be rephrasing the same plan; try a fundamentally different approach.",
                    step_index=step_index,
                )
            )

        # 2. goal_drift detection: only if goal is configured
        if self.goal is not None and self.goal_embedding is not None:
            goal_sim = cosine_similarity(emb, self.goal_embedding)
            if goal_sim < self.cfg.drift_threshold:
                self._drift_count += 1
            else:
                self._drift_count = 0

            if self._drift_count >= self.cfg.drift_warn:
                signals.append(
                    self._sig(
                        kind="goal_drift",
                        severity="warn",
                        count=self._drift_count,
                        hint=f"Goal drift detected. Actions are diverging from the initial objective: '{self.goal}'. Re-align with the original task.",
                        step_index=step_index,
                    )
                )

        self.win.append({"thought": cleaned, "embedding": emb, "step_index": step_index})
        return signals
