#!/usr/bin/env python3
"""Synthetic Loop Detection Scenario Test Harness (Issue #65).

Runs LoopDetector against five hand-written synthetic command sequences
(2 normal iterative workflows and 3 stuck failure loops). This is a deterministic
scenario test, not a measurement on real agent traces.

Run:
    python examples/benchmark_detector.py
"""
import sys
from typing import Any, Dict, List

from agentbox.loop_detector import LoopConfig, LoopDetector


def make_step(cmd_fp: str, ws_hash: str, exit_code: int = 0, error_sig: str = "") -> Dict[str, Any]:
    return {
        "command_fingerprint": cmd_fp,
        "workspace_hash": ws_hash,
        "exit_code": exit_code,
        "error_signature": error_sig,
    }


# ---------------------------------------------------------------------------
# Hand-Written Synthetic Scenarios (5 cases)
# ---------------------------------------------------------------------------

# Scenario 1: Hand-written Test-Driven Development (TDD) edit-test sequence
TDD_SCENARIO = {
    "name": "Scenario: Test-Driven Development (edit-test cycle)",
    "category": "benign",
    "description": "Synthetic iterative sequence: edit code -> test -> edit code -> test",
    "expected_loop": False,
    "steps": [
        make_step("fp:git_status", "ws_hash_0", 0),
        make_step("fp:pytest_models", "ws_hash_0", 1, "TypeError: missing argument"),
        make_step("fp:cat_models_py", "ws_hash_0", 0),
        make_step("fp:pytest_models", "ws_hash_1", 1, "AttributeError: 'NoneType' has no attribute 'clean'"),
        make_step("fp:git_diff", "ws_hash_1", 0),
        make_step("fp:pytest_models", "ws_hash_2", 0),
        make_step("fp:git_commit", "ws_hash_3", 0),
    ],
}

# Scenario 2: Hand-written Multi-Step Exploration & Codebase Inspection
EXPLORATION_SCENARIO = {
    "name": "Scenario: Codebase Navigation & Inspection",
    "category": "benign",
    "description": "Synthetic read-only sequence inspecting files and git history before editing",
    "expected_loop": False,
    "steps": [
        make_step("fp:grep_auth", "ws_hash_0", 0),
        make_step("fp:find_py_files", "ws_hash_0", 0),
        make_step("fp:git_log", "ws_hash_0", 0),
        make_step("fp:cat_views_py", "ws_hash_0", 0),
        make_step("fp:cat_urls_py", "ws_hash_0", 0),
        make_step("fp:git_branch", "ws_hash_0", 0),
    ],
}

# Trajectory 3: Infinite Exact Repeat Loop (Stuck Agent)
RUNAWAY_EXACT_REPEAT_TRAJECTORY = {
    "name": "Runaway Loop: Exact Command Repeat on Unchanged Files",
    "category": "stuck",
    "description": "Agent repeats identical failing command without modifying workspace",
    "expected_loop": True,
    "steps": [
        make_step("fp:curl_auth", "ws_hash_0", 1, "ConnectionRefusedError"),
        make_step("fp:curl_auth", "ws_hash_0", 1, "ConnectionRefusedError"),
        make_step("fp:curl_auth", "ws_hash_0", 1, "ConnectionRefusedError"),
        make_step("fp:curl_auth", "ws_hash_0", 1, "ConnectionRefusedError"),
        make_step("fp:curl_auth", "ws_hash_0", 1, "ConnectionRefusedError"),
    ],
}

# Trajectory 4: Cyclic Command Oscillation (A -> B -> A -> B)
RUNAWAY_CYCLIC_LOOP_TRAJECTORY = {
    "name": "Runaway Loop: Cyclic Oscillation (A -> B -> A -> B)",
    "category": "stuck",
    "description": "Agent alternates between cleaning build and retrying failed build",
    "expected_loop": True,
    "steps": [
        make_step("fp:clean_build", "ws_hash_0", 0),
        make_step("fp:compile_ext", "ws_hash_0", 1, "CompilerError: undefined symbol"),
        make_step("fp:clean_build", "ws_hash_0", 0),
        make_step("fp:compile_ext", "ws_hash_0", 1, "CompilerError: undefined symbol"),
    ],
}

# Trajectory 5: Failing Dead-End Without File Progress
RUNAWAY_NO_PROGRESS_TRAJECTORY = {
    "name": "Runaway Loop: Unproductive Failing Commands (No Workspace Progress)",
    "category": "stuck",
    "description": "Agent issues continuous failing commands without writing any fixes",
    "expected_loop": True,
    "steps": [
        make_step("fp:cmd_1", "ws_hash_0", 1, "ErrorA"),
        make_step("fp:cmd_2", "ws_hash_0", 1, "ErrorB"),
        make_step("fp:cmd_3", "ws_hash_0", 1, "ErrorC"),
        make_step("fp:cmd_4", "ws_hash_0", 1, "ErrorD"),
        make_step("fp:cmd_5", "ws_hash_0", 1, "ErrorE"),
        make_step("fp:cmd_6", "ws_hash_0", 1, "ErrorF"),
    ],
}

ALL_TRAJECTORIES = [
    TDD_SCENARIO,
    EXPLORATION_SCENARIO,
    RUNAWAY_EXACT_REPEAT_TRAJECTORY,
    RUNAWAY_CYCLIC_LOOP_TRAJECTORY,
    RUNAWAY_NO_PROGRESS_TRAJECTORY,
]


def evaluate_trajectory(trajectory: Dict[str, Any], config: LoopConfig) -> Dict[str, Any]:
    detector = LoopDetector(cfg=config)
    signals_detected: List[Dict[str, Any]] = []
    first_detected_step = None

    for idx, step in enumerate(trajectory["steps"], start=1):
        sigs = detector.observe(step)
        if sigs:
            signals_detected.extend(sigs)
            if first_detected_step is None:
                first_detected_step = idx

    is_flagged = len(signals_detected) > 0
    passed = is_flagged == trajectory["expected_loop"]

    return {
        "name": trajectory["name"],
        "category": trajectory["category"],
        "expected_loop": trajectory["expected_loop"],
        "is_flagged": is_flagged,
        "passed": passed,
        "first_detected_step": first_detected_step,
        "signal_count": len(signals_detected),
        "kinds": list({s["kind"] for s in signals_detected}),
    }


def run_scenarios() -> int:
    config = LoopConfig.coding_agent()
    print("=" * 80)
    print("Agentboxx Loop Detector Synthetic Scenario Test")
    print(f"Profile: LoopConfig.coding_agent() (window={config.window}, exact_warn={config.exact_warn}, error_warn={config.error_warn})")
    print("=" * 80)

    results = []
    benign_unexpected = 0
    stuck_missed = 0
    stuck_flagged = 0
    benign_clean = 0

    for traj in ALL_TRAJECTORIES:
        res = evaluate_trajectory(traj, config)
        results.append(res)

        if traj["category"] == "benign":
            if res["is_flagged"]:
                benign_unexpected += 1
            else:
                benign_clean += 1
        elif traj["category"] == "stuck":
            if res["is_flagged"]:
                stuck_flagged += 1
            else:
                stuck_missed += 1

        status = "[PASS]" if res["passed"] else "[FAIL]"
        detection_info = f"step {res['first_detected_step']} ({', '.join(res['kinds'])})" if res["is_flagged"] else "no signals"
        print(f"{status:<7} {res['name']}")
        print(f"        Expected: {'LOOP' if res['expected_loop'] else 'CLEAN'} | Result: {'FLAGGED' if res['is_flagged'] else 'CLEAN'} | {detection_info}")

    total_benign = benign_clean + benign_unexpected
    total_stuck = stuck_flagged + stuck_missed
    passed_count = sum(1 for r in results if r["passed"])

    print("-" * 80)
    print("Scenario Summary (5 hand-written cases; regression check, not rate data):")
    print(f"  Passed: {passed_count}/{len(results)} (normal clean: {benign_clean}/{total_benign}, stuck flagged: {stuck_flagged}/{total_stuck})")
    print("=" * 80)

    if benign_unexpected == 0 and stuck_missed == 0:
        print("ALL SCENARIOS BEHAVED AS EXPECTED (synthetic regression check passed).")
        return 0
    else:
        print("SCENARIO CHECK FAILED: one or more scenarios did not match expectations.")
        return 1


if __name__ == "__main__":
    sys.exit(run_scenarios())
