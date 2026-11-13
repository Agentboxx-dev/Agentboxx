"""Helpers for `tool.call` events: make arguments/results JSON-safe and cap their size."""
import hashlib
import json
import math
from typing import Any, Tuple

MAX_PAYLOAD_BYTES = 65536          # per field (arguments, result), serialized
_MAX_DEPTH = 32
_MARKER = "\n...[{n} bytes omitted]...\n"


def to_jsonable(obj: Any, _depth: int = 0) -> Any:
    """Turn anything a framework might pass into plain JSON data.

    Keys become strings, tuples and sets become lists, bytes are decoded, and non-finite floats
    (which are not valid JSON) and unknown objects become strings, so the log stays readable by
    any verifier.
    """
    if _depth > _MAX_DEPTH:
        return "[max depth]"
    if obj is None or isinstance(obj, (bool, int, str)):
        return obj
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else str(obj)
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj).decode("utf-8", "replace")
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v, _depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v, _depth + 1) for v in obj]
    if isinstance(obj, (set, frozenset)):
        return sorted((to_jsonable(v, _depth + 1) for v in obj), key=lambda v: json.dumps(v, sort_keys=True))
    return str(obj)


def serialize(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def cap_payload(value: Any, limit: int = MAX_PAYLOAD_BYTES) -> Tuple[Any, bool]:
    """Return (stored_value, truncated).

    A payload whose serialized form fits in `limit` bytes is stored unchanged. A larger one is
    replaced by {text, total_bytes, truncated: true, sha256}: the head and tail of its serialized
    form, its full size, and the SHA-256 of the whole (already redacted) serialization, so the
    complete payload can still be checked against the log later.
    """
    data = serialize(value)
    if len(data) <= limit:
        return value, False
    marker = _MARKER.format(n=len(data) - (limit - 64))
    keep = (limit - len(marker.encode())) // 2
    head = data[:keep].decode("utf-8", "ignore")
    tail = data[-keep:].decode("utf-8", "ignore")
    return {
        "text": head + marker + tail,
        "total_bytes": len(data),
        "truncated": True,
        "sha256": hashlib.sha256(data).hexdigest(),
    }, True


def as_text(value: Any) -> str:
    """A value as readable text: strings as they are, anything else as compact JSON."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and value.get("truncated") is True and isinstance(value.get("text"), str):
        return value["text"]
    return json.dumps(value, sort_keys=True, ensure_ascii=False) if value is not None else ""