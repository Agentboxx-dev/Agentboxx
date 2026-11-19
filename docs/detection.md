# Detection in Agentboxx

Agentboxx inspects agent actions and reasoning from the outside to catch loops, stuck states, and goal divergence before token budgets are exhausted.

Detection is split into two complementary engines:
1. **`LoopDetector`** (`src/agentbox/loop_detector.py`): Command- and workspace-state-aware analysis. It checks whether commands, exit codes, and file tree hashes indicate repeating or unproductive cycles.
2. **`SemanticDriftDetector`** (`src/agentbox/semantic_detector.py`): Thought- and objective-aware analysis. It computes vector embeddings of the model's thoughts to catch circular rephrasing and divergence from the prompt goal.

When a detector fires, it emits a signed `analysis.signal` event into the log. If the session is run via the agent loop (`run_agent`), the signal's `hint` is injected into the agent's observation on the next step so the model can course-correct.

---

## Signal Reference

### 1. `loop.exact`

Fires when the agent repeats the exact same command while the workspace hash remains identical. Retrying a command after editing a file does not trigger this signal because the workspace state changed.

- **Severity:** `warn` after 3 identical repetitions; `critical` at 5 (terminates the run).
- **Default Hint:** `"Repeated command on unchanged workspace. The command produced no changes last time; try a different approach."`
- **Example Log Record:**
```json
{
  "event_type": "analysis.signal",
  "ts": 1700000000.0,
  "data": {
    "step_index": 3,
    "kind": "loop.exact",
    "severity": "warn",
    "count": 3,
    "hint": "Repeated command on unchanged workspace. The command produced no changes last time; try a different approach."
  }
}
```

---

### 2. `loop.error_repeat`

Fires when commands produce the same normalized error signature repeatedly, even if command syntax or line numbers vary slightly. Error signatures normalize tracebacks across Python, Node.js, Go, Rust, Java, and Ruby.

- **Severity:** `warn` after 3 recurring errors; `critical` at 5 (terminates the run).
- **Default Hint:** `"Command failed with the same error as previous attempts. Fix the root cause before retrying."`
- **Example Log Record:**
```json
{
  "event_type": "analysis.signal",
  "ts": 1700000005.0,
  "data": {
    "step_index": 4,
    "kind": "loop.error_repeat",
    "severity": "warn",
    "count": 3,
    "hint": "Command failed with the same error as previous attempts. Fix the root cause before retrying."
  }
}
```

---

### 3. `loop.no_progress`

Fires when multiple consecutive steps fail (non-zero exit code) and no files are modified in the workspace.

- **Severity:** `warn` after 4 consecutive non-progress steps; `critical` at 7.
- **Default Hint:** `"Multiple consecutive commands failed without modifying workspace files. Step back and re-evaluate."`
- **Example Log Record:**
```json
{
  "event_type": "analysis.signal",
  "ts": 1700000010.0,
  "data": {
    "step_index": 5,
    "kind": "loop.no_progress",
    "severity": "warn",
    "count": 4,
    "hint": "Multiple consecutive commands failed without modifying workspace files. Step back and re-evaluate."
  }
}
```

---

### 4. `loop.cycle`

Fires when the agent alternates between a repeated sequence of commands (e.g. `A -> B -> A -> B`) without making forward progress.

- **Severity:** `warn` after 2 complete cycles.
- **Default Hint:** `"Command cycle detected. You are alternating between the same set of commands; break the cycle."`
- **Example Log Record:**
```json
{
  "event_type": "analysis.signal",
  "ts": 1700000015.0,
  "data": {
    "step_index": 6,
    "kind": "loop.cycle",
    "severity": "warn",
    "count": 2,
    "hint": "Command cycle detected. You are alternating between the same set of commands; break the cycle."
  }
}
```

---

### 5. `semantic_loop`

Fires when the model's thoughts exhibit high cosine similarity across consecutive steps ($\ge 0.88$), indicating that the model is repeatedly phrasing the same reasoning or plan under different wording.

- **Severity:** `warn` after 3 repetitions; `critical` at 5 (terminates the run).
- **Default Hint:** `"Thought repetition detected. You appear to be rephrasing the same plan; try a fundamentally different approach."`
- **Example Log Record:**
```json
{
  "event_type": "analysis.signal",
  "ts": 1700000020.0,
  "data": {
    "step_index": 4,
    "kind": "semantic_loop",
    "severity": "warn",
    "count": 3,
    "hint": "Thought repetition detected. You appear to be rephrasing the same plan; try a fundamentally different approach."
  }
}
```

---

### 6. `goal_drift`

Fires when the cosine similarity between the agent's recent thoughts and the initial goal drops below $0.40$ for 3 consecutive steps. Disabled if no goal or contract description is provided.

- **Severity:** `warn` after 3 consecutive low-similarity steps.
- **Default Hint:** `"Goal drift detected. Actions are diverging from the initial objective: '<goal>'. Re-align with the original task."`
- **Example Log Record:**
```json
{
  "event_type": "analysis.signal",
  "ts": 1700000025.0,
  "data": {
    "step_index": 4,
    "kind": "goal_drift",
    "severity": "warn",
    "count": 3,
    "hint": "Goal drift detected. Actions are diverging from the initial objective: 'Write prime_sum.py'. Re-align with the original task."
  }
}
```

---

## Thresholds Summary

| Signal | Metric | Trigger Window | Warn Threshold | Critical Threshold |
|---|---|---|---|---|
| `loop.exact` | Exact command match + unchanged workspace hash | Rolling history | 3 repeats | 5 repeats |
| `loop.error_repeat` | Normalized error signature match | Rolling history | 3 repeats | 5 repeats |
| `loop.no_progress` | Consecutive exit code $\neq 0$ + unchanged workspace | Consecutive steps | 4 steps | 7 steps |
| `loop.cycle` | Repeated command sequence cycle | Window of 10 steps | 2 cycles | — |
| `semantic_loop` | Thought cosine similarity $\ge 0.88$ | Consecutive steps | 3 repeats | 5 repeats |
| `goal_drift` | Thought-to-goal cosine similarity $< 0.40$ | 3 consecutive steps | 3 steps | — |

> [!NOTE]
> Threshold values are initial uncalibrated defaults. They can be customized programmatically via `LoopConfig` and `SemanticDriftConfig`.

---

## Security: Static Hints & Prompt Injection Prevention

All detector hints are static string templates defined on the host. Under no circumstances is raw text from the model's thoughts, outputs, or error streams echoed back into a hint.

The only variable interpolation permitted is the initial, trusted `goal` string configured at session start:
```python
hint = f"Goal drift detected. Actions are diverging from the initial objective: '{goal}'. Re-align with the original task."
```
This invariant prevents prompt injection: untrusted code execution or malicious model thoughts cannot manipulate the feedback channel.
