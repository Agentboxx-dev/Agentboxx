# Security policy (pre-execution guardrails)

`Recorder(policy=...)` checks every command passed to `Recorder.run` **before** it reaches the sandbox or host shell.

~~~python
from agentbox import Recorder, SecurityPolicy

rec = Recorder("s1", policy=SecurityPolicy.default_strict())
out = rec.run("git push --force origin main")
out["blocked"]                       # True: the command never ran
out["observation"]["exit_code"]      # 126, with an explanation in stderr
~~~

`policy=None` (the default) changes nothing.

## What happens on a block

1. A signed `policy.blocked` event is appended to the hash chain (command redacted, rule name, reason).
2. The command is not executed.
3. `run()` returns a normal-shaped observation with exit code 126 and the reason in `stderr`, so the agent loop can react.
4. The attempt still takes a step index and feeds the loop detector.

## Rules

- `CommandRule(action, prefix="git push")` matches the start of any command segment (`;`, `&&`, `||`, `|` split a command; `sudo`, `env`, `VAR=x` are skipped).
- `CommandRule(action, pattern=r"...")` is a regex searched in the whole command and in each segment.
- The strongest match wins: `DENY` > `REQUIRE_APPROVAL` > `ALLOW`. `ALLOW` rules only matter in allowlist mode (`default_action=PolicyAction.DENY`), where every segment must match an `ALLOW` rule.
- `blocked_paths` are globs. Any command mentioning a matching path is denied (`.env`, CI files, `~/.ssh`, `~/.agentbox` and so on). Templates such as `.env.example` are allowed.
- `protect_env=True` denies `printenv`, bare `env`, `/proc/*/environ` and `$SOMETHING_TOKEN`-style variables.

## Approval

`REQUIRE_APPROVAL` calls `policy.approver(command, decision)`. Only an exact `True` approves. No approver, an exception, or any other return value blocks the command. An approved command is recorded as `policy.approved`, then runs and is logged as a normal `step`.

## Limits

This is a guardrail against accidents, not a boundary. Regex filtering of shell text cannot stop a determined or obfuscated command (encodings, scripts, shell expansion). Matching is deliberately conservative, so false positives are possible (for example a quoted `.env` in a commit message). The Docker container remains the ultimate boundary.

Only `Recorder.run` is gated. `record_step` and `record_tool_call` record actions that already happened.
