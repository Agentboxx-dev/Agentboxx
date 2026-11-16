"""Language-specific error extractors for error signatures.

Each extractor returns (error_class, key_message) or None when the text does not
look like that language's error output. Only the stable part of an error is
returned (class + message), never stack frames, so the same failure produces the
same signature even when line numbers, paths or versions change.
"""
import re

# --- Go -------------------------------------------------------------------
_GO_PANIC = re.compile(r"^panic: (.+)$", re.M)
_GO_FATAL = re.compile(r"^fatal error: (.+)$", re.M)
_GO_COMPILE = re.compile(r"^\S*\.go:\d+(?::\d+)?: (.+)$", re.M)

# --- Node.js --------------------------------------------------------------
_NODE_HEADER = re.compile(
    r"^(?:Uncaught\s+)?((?:[A-Za-z_$][\w$]*)?(?:Error|Exception))(?:\s+\[([A-Z0-9_]+)\])?:\s*(.*)$",
    re.M,
)
_NODE_FRAME = re.compile(r"^\s+at \S", re.M)
_NODE_VERSION = re.compile(r"^Node\.js v\d+", re.M)

# --- Rust -----------------------------------------------------------------
_RUST_PANIC_OLD = re.compile(r"^thread '[^']+' panicked at '([^']+)'(?:, \S+)?", re.M)
_RUST_PANIC_NEW = re.compile(r"^thread '[^']+' panicked at \S+:\d+(?::\d+)?:\s*\n?([^\n]+)", re.M)
_RUST_COMPILE = re.compile(r"^error\[(E\d+)\]:\s*(.+)$", re.M)

# --- Java -----------------------------------------------------------------
_JAVA_THREAD_EX = re.compile(
    r"^Exception in thread \"[^\"]+\"\s+([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)(?::\s*(.*))?$",
    re.M,
)
_JAVA_CAUSED_BY = re.compile(
    r"^Caused by:\s+([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)(?::\s*(.*))?$",
    re.M,
)
_JAVA_COMPILE = re.compile(r"^\S*\.java:\d+(?::\d+)?: error: (.+)$", re.M)

# --- Ruby -----------------------------------------------------------------
_RUBY_ERROR = re.compile(
    r"^\S*\.rb:\d+(?::\d+)?(?::in [`'][^']+['])?:\s*(.*?)\s*\(([A-Z][\w:]*(?:Error|Exception))\)$",
    re.M,
)


def extract_go(text: str):
    m = _GO_PANIC.search(text)
    if m:
        return "GoPanic", m.group(1)
    m = _GO_FATAL.search(text)
    if m:
        return "GoFatalError", m.group(1)
    m = _GO_COMPILE.search(text)
    if m:
        return "GoCompileError", m.group(1)
    return None


def extract_node(text: str):
    # Require Node-style stack frames or the version footer, so a bare
    # "Error: ..." line from some other tool is not misclassified.
    if not (_NODE_FRAME.search(text) or _NODE_VERSION.search(text)):
        return None
    m = _NODE_HEADER.search(text)
    if not m:
        return None
    cls, code, msg = m.groups()
    return (f"{cls}[{code}]" if code else cls), msg


def extract_rust(text: str):
    m = _RUST_PANIC_OLD.search(text)
    if m:
        return "RustPanic", m.group(1).strip()
    m = _RUST_PANIC_NEW.search(text)
    if m:
        return "RustPanic", m.group(1).strip()
    m = _RUST_COMPILE.search(text)
    if m:
        code, msg = m.groups()
        return f"RustCompileError[{code}]", msg.strip()
    return None


def extract_java(text: str):
    m = _JAVA_COMPILE.search(text)
    if m:
        err_type = m.group(1).strip()
        return f"JavaCompileError[{err_type}]", err_type

    # Runtime exception: require 'Exception in thread ...' header to avoid false positives
    m_thread = _JAVA_THREAD_EX.search(text)
    if not m_thread:
        return None

    # For 'Caused by:' chains:
    # We choose the innermost (last) 'Caused by:' exception because in Java,
    # top-level exceptions are frequently generic wrappers (e.g. RuntimeException,
    # ExecutionException) while the root cause reflects the actual failure condition.
    caused_matches = list(_JAVA_CAUSED_BY.finditer(text))
    if caused_matches:
        cls, msg = caused_matches[-1].groups()
        return cls, (msg or "").strip()

    cls, msg = m_thread.groups()
    return cls, (msg or "").strip()


def extract_ruby(text: str):
    m = _RUBY_ERROR.search(text)
    if not m:
        return None
    msg, cls = m.groups()
    # Normalize backticks in error messages to single quotes so Ruby < 3.4 (`foo')
    # and Ruby >= 3.4 ('foo') yield identical error signatures for the same error.
    norm_msg = msg.strip().replace("`", "'")
    return cls, norm_msg
