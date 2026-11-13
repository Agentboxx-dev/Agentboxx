"""Redact secrets from text before it is logged and signed.

Once a record is signed it cannot be edited, so secrets must be removed first.
Only a count per pattern is recorded, never the value. Patterns are heuristics:
they will miss some secrets and occasionally hide harmless values. Add your own
with add_pattern().
"""
import re

_NAME = (r"[A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|"
         r"access[_-]?key|private[_-]?key)[A-Za-z0-9_.-]*")
_NOT_DONE = r"(?!\[REDACTED:)"   # do not re-redact text a specific pattern already replaced

# (name, compiled regex, replacement). Specific token formats come first,
# context-based patterns (headers, URLs, KEY=value) last.
PATTERNS = [
    ("private_key", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S),
     "[REDACTED:private_key]"),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED:aws_key]"),
    ("github_token", re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})\b"),
     "[REDACTED:github_token]"),
    ("api_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"), "[REDACTED:api_key]"),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "[REDACTED:slack_token]"),
    ("google_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "[REDACTED:google_key]"),
    ("jwt", re.compile(
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
     "[REDACTED:jwt]"),
    ("auth_header", re.compile(
        r"(?i)(\bauthorization\s*[:=]\s*(?:bearer|basic|token)\s+)" + _NOT_DONE + r"[^\s'\"]+"),
     r"\1[REDACTED:auth_header]"),
    ("url_password", re.compile(
        r"(?i)\b([a-z][a-z0-9+.-]*://[^\s:/@]+:)" + _NOT_DONE + r"[^\s@/]+(@)"),
     r"\1[REDACTED:url_password]\2"),
    ("secret_assignment", re.compile(
        r"(?i)(\b" + _NAME + r"\s*[:=]\s*)(['\"]?)" + _NOT_DONE + r"[^\s'\";&]{6,}(\2)"),
     r"\1\2[REDACTED:secret_assignment]\3"),
]


def add_pattern(name: str, regex: str, replacement: str | None = None):
    """Register an extra pattern, e.g. add_pattern('internal_id', r'INT-[0-9]{8}')."""
    PATTERNS.append((name, re.compile(regex), replacement or f"[REDACTED:{name}]"))


def redact(text: str):
    """Return (clean_text, counts) where counts maps pattern name to matches."""
    counts: dict[str, int] = {}
    if not text:
        return text, counts
    for name, rx, repl in PATTERNS:
        text, n = rx.subn(repl, text)
        if n:
            counts[name] = counts.get(name, 0) + n
    return text, counts


def merge_counts(*parts: dict) -> dict:
    total: dict[str, int] = {}
    for part in parts:
        for k, v in part.items():
            total[k] = total.get(k, 0) + v
    return total


def redact_all(cmd: str, out: str, err: str):
    cmd, c1 = redact(cmd)
    out, c2 = redact(out)
    err, c3 = redact(err)
    return cmd, out, err, merge_counts(c1, c2, c3)

_SECRET_KEY = re.compile(r"(?i)password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
                         r"authorization|credential")
_MAX_DEPTH = 32


def redact_value(obj, _under_secret_key: bool = False, _depth: int = 0):
    """Recursively redact secrets in JSON-like data, including 
    sensitive values under secret-named keys, while preserving 
    numbers and booleans and enforcing a 32-level nesting limit."""
    
    counts: dict[str, int] = {}
    if _depth > _MAX_DEPTH:
        return "[REDACTED:too_deep]", {"too_deep": 1}
    if isinstance(obj, str):
        if _under_secret_key and obj and not obj.startswith("[REDACTED:"):
            return "[REDACTED:secret_key]", {"secret_key": 1}
        return redact(obj)
    if isinstance(obj, dict):
        clean: dict = {}
        for k, v in obj.items():
            key, kc = redact(str(k))
            val, vc = redact_value(v, bool(_SECRET_KEY.search(str(k))), _depth + 1)
            counts = merge_counts(counts, kc, vc)
            base, n = key, 2
            while key in clean:                      # two keys that redact to the same text
                key, n = f"{base}#{n}", n + 1
            clean[key] = val
        return clean, counts
    if isinstance(obj, list):
        out = []
        for item in obj:
            val, c = redact_value(item, _under_secret_key, _depth + 1)
            out.append(val)
            counts = merge_counts(counts, c)
        return out, counts
    return obj, counts