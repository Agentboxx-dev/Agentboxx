from agentbox.executor import error_signature
from agentbox.loop_detector import LoopDetector


def step(cmd="x", err="E:1", ws="a", code=1):
    return {"command_fingerprint": cmd, "error_signature": err, "workspace_hash": ws, "exit_code": code}


def test_exact_repeat_flags():
    d = LoopDetector()
    out = []
    for _ in range(3):
        out = d.observe(step())
    assert any(s["kind"] == "loop.exact" for s in out)


def test_varied_progress_is_quiet():
    d = LoopDetector()
    for i in range(6):
        out = d.observe(step(cmd=f"c{i}", err=None, ws=f"w{i}", code=0))
    assert out == []


def test_error_repeat_fires_the_same_for_lf_and_crlf_output():
    traceback_lf = (
        "Traceback (most recent call last):\n"
        '  File "main.py", line 1, in <module>\n'
        "    print(1/0)\n"
        "ZeroDivisionError: division by zero\n"
    )
    ruby_lf = "main.rb:2:in 'divide': divided by 0 (ZeroDivisionError)\n\tfrom main.rb:5:in '<main>'\n"

    def kinds_per_step(stderr):
        d = LoopDetector()
        out = []
        for i in range(3):
            sig, _cls = error_signature(stderr, 1)
            out.append(d.observe(step(cmd=f"c{i}", err=sig, ws=f"w{i}")))
        return [[(s["kind"], s["severity"], s["count"]) for s in signals] for signals in out]

    for text in (traceback_lf, ruby_lf):
        lf = kinds_per_step(text)
        crlf = kinds_per_step(text.replace("\n", "\r\n"))
        assert crlf == lf
        assert ("loop.error_repeat", "warn", 3) in lf[2]
