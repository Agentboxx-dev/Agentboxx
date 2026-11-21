from pathlib import Path

def test_action_file_exists():
    action = Path(".github/actions/verify/action.yml")
    assert action.is_file(), "action.yml must exist"
    txt = action.read_text(encoding="utf-8")
    assert "log-path" in txt
    assert "agentbox verify" in txt
    assert "GITHUB_STEP_SUMMARY" in txt
