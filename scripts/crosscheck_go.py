#!/usr/bin/env python3
"""Cross-verify Python and Go verifiers on generated logs (used by CI).

Usage: python scripts/crosscheck_go.py PATH_TO_agentbox-verify_BINARY
Needs `cryptography` (only to *create* Ed25519 receipts; verification uses no third-party code).
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agentbox.signer import ChainWriter, canon  # noqa: E402

PY_VERIFIER = ROOT / "examples" / "verify_standalone.py"
GO_PATH = Path(sys.argv[1])
GO = str((ROOT / GO_PATH).resolve() if not GO_PATH.is_absolute() else GO_PATH.resolve())
failures = []


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True).returncode


def expect(name, got, want):
    ok = got == want
    print(f"{'ok  ' if ok else 'FAIL'} {name}: exit {got} (want {want})")
    if not ok:
        failures.append(name)


def main():
    tmp = Path(tempfile.mkdtemp())
    key = os.urandom(32)
    keyfile = tmp / "key"
    keyfile.write_text(key.hex())

    log = tmp / "s.ndjson"
    w = ChainWriter(log, key)
    w.append("session.start", {"session_id": "s", "isolation": {"backend": "local"}})
    # awkward content: unicode, control chars, quotes, big/small floats
    w.append("step", {"command": "echo 'héllo ✓ \u2028 \x01 <&> \"q\" \\'", "exit_code": 0,
                      "usage": {"cost": 1e-05, "big": 1.5e20, "f": 0.1, "i": 12}})
    w.append("session.end", {"reason": "done", "steps": 1})
    w.write_manifest()

    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    payload = {"log": log.name, "record_count": w.seq, "final_hash": w.prev}
    receipt = tmp / "receipt.json"
    receipt.write_text(json.dumps({"payload": payload, "sig": priv.sign(canon(payload)).hex()}))
    pubfile = tmp / "pub.hex"
    pubfile.write_text(pub_hex)

    py = [sys.executable, str(PY_VERIFIER), str(log), "--key-file", str(keyfile)]
    go = [GO, str(log), "--receipt", str(receipt), "--pubkey", pub_hex]
    expect("python valid", run(py), 0)
    expect("go valid (hex pubkey)", run(go), 0)
    expect("go valid (pubkey file)", run(go[:-1] + [str(pubfile)]), 0)
    expect("go valid (+hmac key)", run(go + ["--key-file", str(keyfile)]), 0)

    # tampering cases: both verifiers must reject
    lines = log.read_text(encoding="utf-8").split("\n")[:-1]

    def variant(name, new_lines):
        p = tmp / f"{name}.ndjson"
        p.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        return p

    rec = json.loads(lines[1]); rec["event"]["data"]["exit_code"] = 1
    mod = variant("modified", [lines[0], json.dumps(rec, ensure_ascii=False), lines[2]])
    rec = json.loads(lines[1]); rec["hash"] = "f" * 64
    alt = variant("althash", [lines[0], json.dumps(rec, ensure_ascii=False), lines[2]])
    for n, p in (("modified record", mod), ("altered hash", alt)):
        expect(f"python {n}", run([sys.executable, str(PY_VERIFIER), str(p), "--key-file", str(keyfile)]), 1)
        expect(f"go {n}", run([GO, str(p), "--receipt", str(receipt), "--pubkey", pub_hex]), 1)

    forged = tmp / "forged.json"
    other = Ed25519PrivateKey.generate()
    forged.write_text(json.dumps({"payload": payload, "sig": other.sign(canon(payload)).hex()}))
    expect("go forged receipt", run([GO, str(log), "--receipt", str(forged), "--pubkey", pub_hex]), 1)

    bad = dict(payload, final_hash="a" * 64)
    mism = tmp / "mismatch.json"
    mism.write_text(json.dumps({"payload": bad, "sig": priv.sign(canon(bad)).hex()}))
    expect("go receipt/log mismatch", run([GO, str(log), "--receipt", str(mism), "--pubkey", pub_hex]), 1)

    trunc = variant("trunc", lines[:2])
    expect("go truncated, no receipt -> incomplete", run([GO, str(trunc)]), 2)
    expect("go truncated vs receipt -> tampered", run([GO, str(trunc), "--receipt", str(receipt), "--pubkey", pub_hex]), 1)
    expect("go missing file", run([GO, str(tmp / "nope.ndjson")]), 3)
    expect("go bad pubkey", run([GO, str(log), "--receipt", str(receipt), "--pubkey", "zz"]), 3)

    if failures:
        print("FAILED:", failures)
        return 1
    return 0


sys.exit(main())