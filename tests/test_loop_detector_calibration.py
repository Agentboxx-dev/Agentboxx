"""Tests for LoopConfig preset profiles and synthetic scenario script (Issue #65)."""
import subprocess
import sys
from pathlib import Path

from agentbox import LoopConfig, LoopDetector

BENCHMARK_SCRIPT = Path(__file__).resolve().parents[1] / "examples" / "benchmark_detector.py"


def test_loop_config_profiles():
    """Verify preconfigured LoopConfig preset profiles have expected field values."""
    coding = LoopConfig.coding_agent()
    assert coding.window == 15
    assert coding.exact_warn == 4
    assert coding.exact_crit == 6
    assert coding.error_warn == 4
    assert coding.no_progress_warn == 6

    cons = LoopConfig.conservative()
    assert cons.window == 20
    assert cons.exact_warn == 5
    assert cons.exact_crit == 8
    assert cons.no_progress_warn == 8

    aggr = LoopConfig.aggressive()
    assert aggr.window == 8
    assert aggr.exact_warn == 2
    assert aggr.exact_crit == 4
    assert aggr.no_progress_warn == 3

    default = LoopConfig.default()
    assert default.window == 10
    assert default.exact_warn == 3


def test_tdd_scenario_raises_no_signals():
    """Verify coding_agent profile raises zero signals on synthetic test/edit steps."""
    detector = LoopDetector(cfg=LoopConfig.coding_agent())
    tdd_steps = [
        {"command_fingerprint": "fp:git_status", "workspace_hash": "ws_0", "exit_code": 0, "error_signature": ""},
        {"command_fingerprint": "fp:pytest", "workspace_hash": "ws_0", "exit_code": 1, "error_signature": "TypeError"},
        {"command_fingerprint": "fp:cat", "workspace_hash": "ws_0", "exit_code": 0, "error_signature": ""},
        {"command_fingerprint": "fp:pytest", "workspace_hash": "ws_1", "exit_code": 1, "error_signature": "AttributeError"},
        {"command_fingerprint": "fp:git_diff", "workspace_hash": "ws_1", "exit_code": 0, "error_signature": ""},
        {"command_fingerprint": "fp:pytest", "workspace_hash": "ws_2", "exit_code": 0, "error_signature": ""},
    ]
    signals = []
    for s in tdd_steps:
        sigs = detector.observe(s)
        if sigs:
            signals.extend(sigs)

    assert len(signals) == 0, f"Expected 0 signals during TDD, got: {signals}"


def test_cyclic_loop_detected_within_four_iterations():
    """Verify cyclic command oscillations (A->B->A->B) are caught within 4 steps."""
    detector = LoopDetector(cfg=LoopConfig.coding_agent())
    steps = [
        {"command_fingerprint": "fp:make", "workspace_hash": "ws_0", "exit_code": 0, "error_signature": ""},
        {"command_fingerprint": "fp:clean", "workspace_hash": "ws_0", "exit_code": 0, "error_signature": ""},
        {"command_fingerprint": "fp:make", "workspace_hash": "ws_0", "exit_code": 0, "error_signature": ""},
        {"command_fingerprint": "fp:clean", "workspace_hash": "ws_0", "exit_code": 0, "error_signature": ""},
    ]
    signals = []
    for s in steps:
        sigs = detector.observe(s)
        if sigs:
            signals.extend(sigs)

    assert len(signals) >= 1
    assert any(s["kind"] == "loop.cycle" for s in signals)


def test_scenario_script_passes():
    """Verify python examples/benchmark_detector.py executes and passes all 5 scenarios."""
    res = subprocess.run([sys.executable, str(BENCHMARK_SCRIPT)], capture_output=True, text=True)
    assert res.returncode == 0
    assert "ALL SCENARIOS BEHAVED AS EXPECTED" in res.stdout
    assert "Passed: 5/5 (normal clean: 2/2, stuck flagged: 3/3)" in res.stdout
