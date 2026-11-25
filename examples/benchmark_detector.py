#!/usr/bin/env python3
"""SWE-bench & GAIA Real-Agent Loop Detection Benchmark Harness (Issue #65).

Calibrates and validates LoopDetector sensitivity against realistic software engineering
agent trajectories (SWE-bench) and general multi-step assistant tasks (GAIA) vs runaway loops.

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
# Benchmark Trajectory Datasets (SWE-bench & GAIA)
# ---------------------------------------------------------------------------

# Trajectory 1: SWE-bench Test-Driven Development (Django bugfix)
SWE_BENCH_TDD_TRAJECTORY = {
    "name": "SWE-bench: Test-Driven Development (Django bugfix)",
    "benchmark": "SWE-bench",
    "category": "benign",
    "description": "Legitimate developer iteration: edit code -> test -> edit code -> test",
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

# Trajectory 2: SWE-bench Multi-File Inspection & Refactoring
SWE_BENCH_REFACTOR_TRAJECTORY = {
    "name": "SWE-bench: Multi-File Inspection & Patch Iteration",
    "benchmark": "SWE-bench",
    "category": "benign",
    "description": "Agent reads multiple files and tests patches across repo",
    "expected_loop": False,
    "steps": [
        make_step("fp:grep_auth", "ws_hash_0", 0),
        make_step("fp:cat_views_py", "ws_hash_0", 0),
        make_step("fp:cat_urls_py", "ws_hash_0", 0),
        make_step("fp:patch_views", "ws_hash_1", 0),
        make_step("fp:pytest_views", "ws_hash_1", 0),
    ],
}

# Trajectory 3: GAIA General Assistant Multi-Modal Tool & File Exploration (Level 2/3)
GAIA_ASSISTANT_TRAJECTORY = {
    "name": "GAIA: Multi-Modal Assistant Tool Use & Data Exploration",
    "benchmark": "GAIA",
    "category": "benign",
    "description": "GAIA agent searching tables, querying PDFs, and reading environment data",
    "expected_loop": False,
    "steps": [
        make_step("fp:find_spreadsheets", "ws_hash_0", 0),
        make_step("fp:python_inspect_csv", "ws_hash_0", 0),
        make_step("fp:read_table_headers", "ws_hash_0", 0),
        make_step("fp:convert_pdf_to_text", "ws_hash_1", 0),
        make_step("fp:query_output_stats", "ws_hash_1", 0),
        make_step("fp:format_final_json", "ws_hash_2", 0),
    ],
}

# Trajectory 4: Runaway Exact Repeat Failure (Stuck Agent)
RUNAWAY_EXACT_REPEAT_TRAJECTORY = {
    "name": "Runaway Loop: Exact Command Repeat on Unchanged Files",
    "benchmark": "Synthetic Failure",
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

# Trajectory 5: Runaway Cyclic Command Oscillation (A -> B -> A -> B)
RUNAWAY_CYCLIC_LOOP_TRAJECTORY = {
    "name": "Runaway Loop: Cyclic Oscillation (A -> B -> A -> B)",
    "benchmark": "Synthetic Failure",
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

# Trajectory 6: Runaway Dead-End Failing Retries
RUNAWAY_NO_PROGRESS_TRAJECTORY = {
    "name": "Runaway Loop: Unproductive Failing Commands (No Workspace Progress)",
    "benchmark": "Synthetic Failure",
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
    SWE_BENCH_TDD_TRAJECTORY,
    SWE_BENCH_REFACTOR_TRAJECTORY,
    GAIA_ASSISTANT_TRAJECTORY,
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
        "benchmark": trajectory["benchmark"],
        "category": trajectory["category"],
        "expected_loop": trajectory["expected_loop"],
        "is_flagged": is_flagged,
        "passed": passed,
        "first_detected_step": first_detected_step,
        "signal_count": len(signals_detected),
        "kinds": list({s["kind"] for s in signals_detected}),
    }


def run_benchmark() -> int:
    config = LoopConfig.coding_agent()
    print("=" * 80)
    print("Agentboxx Real-Agent Benchmark Harness (SWE-bench & GAIA Calibration)")
    print(f"Profile: LoopConfig.coding_agent() (window={config.window}, exact_warn={config.exact_warn}, error_warn={config.error_warn})")
    print("=" * 80)

    results = []
    false_positives = 0
    false_negatives = 0
    true_positives = 0
    true_negatives = 0

    for traj in ALL_TRAJECTORIES:
        res = evaluate_trajectory(traj, config)
        results.append(res)

        if traj["category"] == "benign":
            if res["is_flagged"]:
                false_positives += 1
            else:
                true_negatives += 1
        elif traj["category"] == "stuck":
            if res["is_flagged"]:
                true_positives += 1
            else:
                false_negatives += 1

        status = "[PASS]" if res["passed"] else "[FAIL]"
        detection_info = f"step {res['first_detected_step']} ({', '.join(res['kinds'])})" if res["is_flagged"] else "no false alarms"
        print(f"{status:<7} {res['name']}")
        print(f"        Benchmark: {res['benchmark']:<12} | Result: {'FLAGGED' if res['is_flagged'] else 'CLEAN'} | {detection_info}")

    total_benign = true_negatives + false_positives
    total_stuck = true_positives + false_negatives

    fpr = (false_positives / total_benign) * 100 if total_benign else 0.0
    recall = (true_positives / total_stuck) * 100 if total_stuck else 100.0
    precision = (true_positives / (true_positives + false_positives)) * 100 if (true_positives + false_positives) else 100.0

    print("-" * 80)
    print("Benchmark Calibration Summary:")
    print(f"  False Positive Rate (FPR): {fpr:.1f}% (Acceptance criterion: 0.0%)")
    print(f"  Recall (Loops Caught):      {recall:.1f}% (Acceptance criterion: 100.0%)")
    print(f"  Precision:                  {precision:.1f}%")
    print("=" * 80)

    if false_positives == 0 and recall == 100.0:
        print("ALL ACCEPTANCE CRITERIA MET: Detector calibrated for SWE-bench & GAIA agent workloads.")
        return 0
    else:
        print("CALIBRATION FAILURE: Detector sensitivity requires tuning.")
        return 1


if __name__ == "__main__":
    sys.exit(run_benchmark())
