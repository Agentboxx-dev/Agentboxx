"""Pre-execution security policy for commands an agent asks to run.

A SecurityPolicy inspects a command *before* it reaches the sandbox or the host shell and
answers ALLOW, DENY or REQUIRE_APPROVAL. It is a guardrail against accidents (``rm -rf /``,
``git push --force``, touching ``.env`` or CI files), NOT a security boundary: pattern
matching on shell text can always be bypassed (encodings, scripts, shell expansion). The
Docker sandbox remains the real containment layer.
"""
import fnmatch
import os
import posixpath
import re
import shlex
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Sequence


class PolicyAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


_STRENGTH = {
    PolicyAction.ALLOW: 0,
    PolicyAction.REQUIRE_APPROVAL: 1,
    PolicyAction.DENY: 2,
}

_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_WRAPPERS = frozenset({"sudo", "env", "command", "nohup", "time", "exec", "nice", "xargs", "builtin"})
_SEGMENT_SPLIT = re.compile(r"&&|\|\||[;|&\n`()]")
_PATH_SPLIT = re.compile(r"[\s<>=:,;|&()`]+")
_GLOB_CHARS = re.compile(r"[*?\[\]]")
_MAX_MATCHED = 200


def _posix(p: str) -> str:
    """Commands run under bash even on Windows, so compare paths in POSIX form."""
    return p.replace(os.sep, "/") if os.sep != "/" else p


def _is_abs(p: str) -> bool:
    return p.startswith("/") or bool(re.match(r"^[A-Za-z]:/", p))


def _raw_tokens(text: str) -> list[str]:
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        return text.split()


def _segments(command: str) -> list[str]:
    """Split on shell separators so `echo hi; rm -rf /` is judged piece by piece."""
    return [s.strip() for s in _SEGMENT_SPLIT.split(command) if s.strip()]


def _command_tokens(segment: str) -> list[str]:
    """Tokens of one segment with leading VAR=x and wrappers (sudo, env, ...) removed."""
    toks = _raw_tokens(segment)
    i = 0
    while i < len(toks):
        if _ASSIGN.match(toks[i]):
            i += 1
        elif os.path.basename(toks[i]) in _WRAPPERS:
            i += 1
            while i < len(toks) and toks[i].startswith("-"):
                i += 1
        else:
            break
    toks = toks[i:]
    if toks:
        toks[0] = os.path.basename(toks[0])
    return toks


@dataclass(frozen=True)
class PolicyDecision:
    action: PolicyAction
    rule: str = ""
    reason: str = ""
    matched: str | None = None

    @property
    def allowed(self) -> bool:
        return self.action is PolicyAction.ALLOW

    def to_dict(self) -> dict:
        return {"action": self.action.value, "rule": self.rule,
                "reason": self.reason, "matched": self.matched}


@dataclass(frozen=True)
class CommandRule:
    """One command rule: either a command `prefix` ("git push") or a regex `pattern`."""

    action: PolicyAction
    prefix: str | None = None
    pattern: str | None = None
    name: str = ""
    reason: str = ""

    def __post_init__(self):
        object.__setattr__(self, "action", PolicyAction(self.action))
        if (self.prefix is None) == (self.pattern is None):
            raise ValueError("CommandRule needs exactly one of prefix or pattern")
        if self.prefix is not None and not self.prefix.split():
            raise ValueError("CommandRule prefix must not be empty")
        if self.pattern is not None:
            re.compile(self.pattern)  # fail at construction, not mid-run
        if not self.name:
            object.__setattr__(self, "name", (self.prefix or self.pattern or "")[:60])

    def match(self, command: str, segments: Sequence[str]) -> str | None:
        """Return the matching text, or None."""
        if self.pattern is not None:
            for text in (command, *segments):
                m = re.search(self.pattern, text)
                if m:
                    return m.group(0)
            return None
        want = self.prefix.split()
        for seg in segments:
            if _command_tokens(seg)[: len(want)] == want:
                return seg
        return None


# --- default rule set ---------------------------------------------------------------------

_END = r"(?=\s|$|;|&|\|)"
_RECURSIVE = r"(?:-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)"
_ROOT = r"""["']?(?:/\*?|~/?|\$HOME/?|\$\{HOME\}/?)["']?"""

_STRICT_RULES: tuple[CommandRule, ...] = (
    CommandRule(
        PolicyAction.DENY, name="rm-recursive-root",
        reason="recursive delete of /, ~ or $HOME",
        pattern=r"\brm\b(?=[^;&|]*\s" + _RECURSIVE + _END + r")[^;&|]*\s" + _ROOT + _END),
    CommandRule(PolicyAction.DENY, name="rm-no-preserve-root",
                reason="disables the safeguard for deleting /", pattern=r"--no-preserve-root"),
    CommandRule(
        PolicyAction.DENY, name="git-force-push", reason="force push can destroy remote history",
        pattern=(r"\bgit\b[^;&|]*\bpush\b[^;&|]*"
                 r"(?:\s--force(?!-)|\s-[a-zA-Z]*f[a-zA-Z]*(?=\s|$)|\s\+\S)")),
    CommandRule(PolicyAction.DENY, name="disk-format", reason="formats or overwrites a block device",
                pattern=r"\bmkfs(?:\.\w+)?\b|\bdd\b[^;&|]*\bof=/dev/|>\s*/dev/(?:sd|nvme|hd|vd|xvd)"),
    CommandRule(PolicyAction.DENY, name="fork-bomb", reason="fork bomb", pattern=r":\(\)\s*\{"),
    CommandRule(PolicyAction.DENY, name="recursive-chmod-root",
                reason="recursive chmod/chown on /",
                pattern=r"\b(?:chmod|chown)\b[^;&|]*\s-\w*R\w*[^;&|]*\s/" + _END),
    CommandRule(PolicyAction.DENY, name="pipe-to-shell",
                reason="runs downloaded or generated code without inspection",
                pattern=(r"\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b"
                         r"|\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b")),
    *(CommandRule(PolicyAction.DENY, prefix=cmd, name="power:" + cmd,
                  reason="host power control")
      for cmd in ("shutdown", "reboot", "halt", "poweroff")),
    CommandRule(PolicyAction.REQUIRE_APPROVAL, name="git-force-with-lease",
                reason="force push (with lease) needs approval",
                pattern=r"\bgit\b[^;&|]*\bpush\b[^;&|]*--force-with-lease"),
    CommandRule(PolicyAction.REQUIRE_APPROVAL, name="git-push-delete",
                reason="deleting a remote ref needs approval",
                pattern=r"\bgit\b[^;&|]*\bpush\b[^;&|]*(?:\s--delete\b|\s:\S)"),
    CommandRule(PolicyAction.REQUIRE_APPROVAL, name="git-destructive",
                reason="discards local work",
                pattern=r"\bgit\s+(?:reset\s+--hard|clean\s+-\w*f|branch\s+-D\b)"),
    CommandRule(PolicyAction.REQUIRE_APPROVAL, name="rm-recursive",
                reason="recursive delete needs approval",
                pattern=r"\brm\b[^;&|]*\s" + _RECURSIVE + _END),
    CommandRule(PolicyAction.REQUIRE_APPROVAL, name="sudo", reason="privilege escalation",
                pattern=r"(?:^|[;&|(\s])sudo\b"),
)

DEFAULT_BLOCKED_PATHS: tuple[str, ...] = (
    ".env", ".env.*", "*.pem", "*.key", "id_rsa*", "id_ed25519*", ".npmrc", ".pypirc", ".netrc",
    ".git/config", ".git/hooks/*",
    ".github/workflows", ".github/workflows/*", ".gitlab-ci.yml", ".circleci/*", "Jenkinsfile",
    "azure-pipelines.yml",
    "~/.ssh", "~/.ssh/*", "~/.aws", "~/.aws/*", "~/.agentbox", "~/.agentbox/*",
    "/etc/shadow", "/etc/sudoers", "/proc/*/environ",
)

# Templates meant to be committed; reading them is fine.
_PATH_EXCEPTIONS = frozenset({".env.example", ".env.sample", ".env.template", ".env.dist"})

_ENV_PATTERNS = (
    ("env:proc-environ", re.compile(r"/proc/(?:self|\d+|\*)/environ")),
    ("env:secret-variable", re.compile(
        r"\$\{?[A-Za-z0-9_]*(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_?KEY)"
        r"[A-Za-z0-9_]*\}?", re.I)),
)
_ENV_LISTERS = frozenset({"-p", "-x", "-px", "-xp"})


def _path_candidates(command: str) -> list[str]:
    """Every word and every sub-part of a word (split on = : , ; | & ( ) < > and spaces)."""
    out: list[str] = []
    for tok in _raw_tokens(command):
        out.append(tok)
        out.extend(p for p in _PATH_SPLIT.split(tok) if p and p != tok)
    return [c.strip("'\"") for c in out if c.strip("'\"")]


def _path_matches(pat: str, absp: str, rel: str, base: str) -> bool:
    if "/" not in pat:
        return fnmatch.fnmatchcase(base, pat)
    if _is_abs(pat):
        return fnmatch.fnmatchcase(absp, pat)
    return fnmatch.fnmatchcase(rel, pat) or fnmatch.fnmatchcase(absp, "*/" + pat)


Approver = Callable[[str, PolicyDecision], bool]


class SecurityPolicy:
    """Decides, before execution, whether a command may run.

    Args:
        rules: CommandRule list. The strongest matching action wins (DENY > REQUIRE_APPROVAL > ALLOW).
        blocked_paths: Glob patterns for files/dirs no command may reference.
        protect_env: Block commands that dump the environment or read secret-looking variables.
        default_action: Used when no rule matches. Set to DENY for allowlist mode: every
            segment of a command must then match an ALLOW rule.
        approver: Called as approver(command, decision) for REQUIRE_APPROVAL. Only an exact
            True approves. No approver, an exception, or any other value means blocked.
    """

    def __init__(
        self,
        rules: Sequence[CommandRule] = (),
        blocked_paths: Sequence[str] = (),
        protect_env: bool = False,
        default_action: PolicyAction = PolicyAction.ALLOW,
        approver: Approver | None = None,
    ) -> None:
        self.rules = tuple(rules)
        self.blocked_paths = tuple(blocked_paths)
        self.protect_env = protect_env
        self.default_action = PolicyAction(default_action)
        self.approver = approver
        self._patterns = [_posix(os.path.expanduser(p)) if p.startswith("~") else p
                          for p in self.blocked_paths]
        self._literals = [p for p in self._patterns
                          if "/" not in p and not _GLOB_CHARS.search(p)]

    @classmethod
    def default_strict(
        cls,
        approver: Approver | None = None,
        extra_rules: Sequence[CommandRule] = (),
        extra_blocked_paths: Sequence[str] = (),
    ) -> "SecurityPolicy":
        """Destructive commands, secrets, CI files and the signing key are off limits."""
        return cls(
            rules=[*_STRICT_RULES, *extra_rules],
            blocked_paths=[*DEFAULT_BLOCKED_PATHS, *extra_blocked_paths],
            protect_env=True,
            approver=approver,
        )

    def describe(self) -> dict:
        """Static summary written into session.start so the log says which policy was active."""
        return {
            "default_action": self.default_action.value,
            "protect_env": self.protect_env,
            "approval": self.approver is not None,
            "rules": [{"name": r.name, "action": r.action.value} for r in self.rules],
            "blocked_paths": list(self.blocked_paths),
        }

    def evaluate(self, command: str, workspace: str | None = None) -> PolicyDecision:
        segments = _segments(command)
        hits: list[PolicyDecision] = []

        if self.protect_env:
            hit = self._check_env(command, segments)
            if hit:
                hits.append(hit)
        if self._patterns:
            hit = self._check_paths(command, workspace)
            if hit:
                hits.append(hit)
        for rule in self.rules:
            if rule.action is PolicyAction.ALLOW:
                continue
            matched = rule.match(command, segments)
            if matched is not None:
                hits.append(PolicyDecision(rule.action, rule.name,
                                           rule.reason or f"matched rule {rule.name}",
                                           matched[:_MAX_MATCHED]))
        if hits:
            return max(hits, key=lambda d: _STRENGTH[d.action])

        if self.default_action is not PolicyAction.ALLOW:
            if not all(self._segment_allowed(s) for s in segments):
                return PolicyDecision(self.default_action, "default",
                                      "no ALLOW rule matched this command")
        return PolicyDecision(PolicyAction.ALLOW)

    def request_approval(self, command: str, decision: PolicyDecision) -> str:
        """Returns 'approved', 'denied', 'not_configured' or 'error'. Fails closed."""
        if self.approver is None:
            return "not_configured"
        try:
            return "approved" if self.approver(command, decision) is True else "denied"
        except Exception:
            return "error"

    # ---- checks ----

    def _segment_allowed(self, segment: str) -> bool:
        return any(r.action is PolicyAction.ALLOW and r.match(segment, [segment]) is not None
                   for r in self.rules)

    def _check_env(self, command: str, segments: Sequence[str]) -> PolicyDecision | None:
        for seg in segments:
            toks = _raw_tokens(seg)
            if not toks:
                continue
            head, rest = os.path.basename(toks[0]), toks[1:]
            dumps = (
                head == "printenv"
                or (head == "env" and not [t for t in rest
                                           if not t.startswith("-") and not _ASSIGN.match(t)])
                or (head in ("export", "declare", "typeset") and set(rest) <= _ENV_LISTERS)
                or (head == "set" and not rest)
            )
            if dumps:
                return PolicyDecision(PolicyAction.DENY, "env:dump",
                                      "command would print the environment", seg[:_MAX_MATCHED])
        for name, rx in _ENV_PATTERNS:
            m = rx.search(command)
            if m:
                return PolicyDecision(PolicyAction.DENY, name,
                                      "command reads secret-looking environment data", m.group(0))
        return None

    def _check_paths(self, command: str, workspace: str | None) -> PolicyDecision | None:
        ws = _posix(os.path.abspath(workspace or os.getcwd()))
        home = _posix(os.path.expanduser("~"))
        for raw in _path_candidates(command):
            cand = raw.replace("${HOME}", home).replace("$HOME", home)
            if cand.startswith("~"):
                cand = _posix(os.path.expanduser(cand))
            absp = posixpath.normpath(cand if _is_abs(cand) else posixpath.join(ws, cand))
            base = posixpath.basename(absp)
            if base in _PATH_EXCEPTIONS:
                continue
            rel = absp[len(ws) + 1:] if absp.startswith(ws + "/") else absp
            for pat in self._patterns:
                if _path_matches(pat, absp, rel, base):
                    return PolicyDecision(PolicyAction.DENY, "path:" + pat,
                                          "command references a protected path", raw)
            # A glob such as `.en*` could expand to a protected file name.
            if _GLOB_CHARS.search(base) and _GLOB_CHARS.sub("", base):
                for lit in self._literals:
                    if fnmatch.fnmatchcase(lit, base):
                        return PolicyDecision(PolicyAction.DENY, "path:" + lit,
                                              "glob could expand to a protected path", raw)
        return None
