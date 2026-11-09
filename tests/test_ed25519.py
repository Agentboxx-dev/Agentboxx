"""Tests for Ed25519 public-key run receipts and third-party verification."""
import json
import subprocess
import sys

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from agentbox.cli import main as cli_main
from agentbox.recorder import Recorder
from agentbox.signer import (
    generate_ed25519_keypair,
    is_small_order_public_key,
    load_ed25519_private_key,
    load_ed25519_public_key,
    receipt_path,
    verify_receipt,
)


@pytest.fixture
def keypair(tmp_path):
    key_path = tmp_path / "ed25519.key"
    pub_path = tmp_path / "ed25519.pub"
    generate_ed25519_keypair(key_path=key_path, pub_path=pub_path)
    return key_path, pub_path


def test_keygen_and_loading(keypair):
    key_path, pub_path = keypair
    assert key_path.exists() and pub_path.exists()

    priv = load_ed25519_private_key(key_path)
    assert isinstance(priv, ed25519.Ed25519PrivateKey)

    pub_from_file = load_ed25519_public_key(pub_path)
    assert isinstance(pub_from_file, ed25519.Ed25519PublicKey)

    pub_hex = pub_path.read_text().strip()
    pub_from_hex = load_ed25519_public_key(pub_hex)
    assert isinstance(pub_from_hex, ed25519.Ed25519PublicKey)

    raw_bytes = bytes.fromhex(pub_hex)
    pub_from_bytes = load_ed25519_public_key(raw_bytes)
    assert isinstance(pub_from_bytes, ed25519.Ed25519PublicKey)


def test_recorder_generates_valid_receipt(tmp_path, keypair):
    key_path, pub_path = keypair
    rec = Recorder(
        "session-ed25519",
        workspace=str(tmp_path / "ws"),
        log_dir=str(tmp_path / "runs"),
        ed25519_key_path=key_path,
    )
    rec.run("echo hello", thought="say hello")
    rec.close("test completed")

    rp = receipt_path(rec.log_path)
    assert rp.exists(), "receipt file was not generated"

    receipt = json.loads(rp.read_text(encoding="utf-8"))
    payload = receipt["payload"]
    assert payload["version"] == 1
    assert payload["session_id"] == "session-ed25519"
    assert payload["record_count"] == 3  # session.start, step, session.end
    assert len(payload["final_hash"]) == 64
    assert "public_key" in payload
    assert "key_id" in payload

    problems, verified_payload = verify_receipt(rec.log_path, rp, pub_path)
    assert problems == [], f"verification failed: {problems}"
    assert verified_payload["final_hash"] == payload["final_hash"]


def test_tampered_record_detected_by_receipt(tmp_path, keypair):
    key_path, pub_path = keypair
    rec = Recorder(
        "session-tamper",
        workspace=str(tmp_path / "ws"),
        log_dir=str(tmp_path / "runs"),
        ed25519_key_path=key_path,
    )
    rec.run("echo clean", thought="clean run")
    rec.close()

    rp = receipt_path(rec.log_path)
    lines = rec.log_path.read_text(encoding="utf-8").splitlines()
    step_record = json.loads(lines[1])
    step_record["event"]["data"]["thought"] = "MALICIOUS INJECTION"
    lines[1] = json.dumps(step_record)
    rec.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    problems, _ = verify_receipt(rec.log_path, rp, pub_path)
    assert any("content was modified" in p for p in problems)


def test_truncated_log_detected_by_receipt(tmp_path, keypair):
    key_path, pub_path = keypair
    rec = Recorder(
        "session-truncate",
        workspace=str(tmp_path / "ws"),
        log_dir=str(tmp_path / "runs"),
        ed25519_key_path=key_path,
    )
    rec.run("echo step 1", thought="step 1")
    rec.run("echo step 2", thought="step 2")
    rec.close()

    rp = receipt_path(rec.log_path)
    lines = rec.log_path.read_text(encoding="utf-8").splitlines()
    rec.log_path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

    problems, _ = verify_receipt(rec.log_path, rp, pub_path)
    assert any("log does not match signed receipt" in p for p in problems)


def test_tampered_receipt_payload_detected(tmp_path, keypair):
    key_path, pub_path = keypair
    rec = Recorder(
        "session-tamper-receipt",
        workspace=str(tmp_path / "ws"),
        log_dir=str(tmp_path / "runs"),
        ed25519_key_path=key_path,
    )
    rec.run("echo ok")
    rec.close()

    rp = receipt_path(rec.log_path)
    receipt = json.loads(rp.read_text(encoding="utf-8"))
    receipt["payload"]["final_hash"] = "0" * 64
    rp.write_text(json.dumps(receipt), encoding="utf-8")

    problems, _ = verify_receipt(rec.log_path, rp, pub_path)
    assert any("receipt signature is invalid" in p for p in problems)


def test_wrong_public_key_fails_verification(tmp_path, keypair):
    key_path, _ = keypair
    rec = Recorder(
        "session-wrong-key",
        workspace=str(tmp_path / "ws"),
        log_dir=str(tmp_path / "runs"),
        ed25519_key_path=key_path,
    )
    rec.run("echo ok")
    rec.close()

    other_priv = ed25519.Ed25519PrivateKey.generate()
    other_pub = other_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()

    rp = receipt_path(rec.log_path)
    problems, _ = verify_receipt(rec.log_path, rp, other_pub)
    assert any("signature is invalid" in p or "does not match" in p for p in problems)


def test_cli_keygen_and_verify(tmp_path, monkeypatch, capsys):
    key_dir = tmp_path / "keys"
    code = cli_main(["keygen", "--dir", str(key_dir)])
    assert code == 0
    assert (key_dir / "ed25519.key").exists()
    assert (key_dir / "ed25519.pub").exists()

    rec = Recorder(
        "session-cli",
        workspace=str(tmp_path / "ws"),
        log_dir=str(tmp_path / "runs"),
        ed25519_key_path=key_dir / "ed25519.key",
    )
    rec.run("echo cli test")
    rec.close()

    rp = receipt_path(rec.log_path)
    code = cli_main([
        "verify",
        str(rec.log_path),
        "--receipt",
        str(rp),
        "--pubkey",
        str(key_dir / "ed25519.pub"),
    ])
    assert code == 0

    lines = rec.log_path.read_text(encoding="utf-8").splitlines()
    rec.log_path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    code = cli_main([
        "verify",
        str(rec.log_path),
        "--receipt",
        str(rp),
        "--pubkey",
        str(key_dir / "ed25519.pub"),
    ])
    assert code == 1


def test_standalone_verifier_agrees_with_agentbox(tmp_path, keypair):
    key_path, pub_path = keypair
    rec = Recorder(
        "session-standalone",
        workspace=str(tmp_path / "ws"),
        log_dir=str(tmp_path / "runs"),
        ed25519_key_path=key_path,
    )
    rec.run("echo standalone")
    rec.close()

    rp = receipt_path(rec.log_path)
    res = subprocess.run(
        [
            sys.executable,
            "examples/verify_standalone.py",
            str(rec.log_path),
            "--receipt",
            str(rp),
            "--pubkey",
            str(pub_path),
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "OK: Ed25519 receipt and log hash chain are valid" in res.stdout

    # Tamper with log
    lines = rec.log_path.read_text(encoding="utf-8").splitlines()
    rec.log_path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    res_tamper = subprocess.run(
        [
            sys.executable,
            "examples/verify_standalone.py",
            str(rec.log_path),
            "--receipt",
            str(rp),
            "--pubkey",
            str(pub_path),
        ],
        capture_output=True,
        text=True,
    )
    assert res_tamper.returncode == 1
    assert "TAMPERED OR CORRUPT" in res_tamper.stdout

# --- RFC 8032 section 7.1 test vectors ---------------------------------------------------
RFC8032_VECTORS = [
    (
        "TEST 1",
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "TEST 2",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "TEST 3",
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
    (
        "TEST SHA(abc)",
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    ),
]
_VECTOR_IDS = [v[0] for v in RFC8032_VECTORS]


def _flip_bit(data: bytes, bit: int) -> bytes:
    buf = bytearray(data)
    buf[bit // 8] ^= 1 << (bit % 8)
    return bytes(buf)


def _raw_pub(priv) -> bytes:
    return priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


@pytest.mark.parametrize("name,sk,pk,msg,sig", RFC8032_VECTORS, ids=_VECTOR_IDS)
def test_rfc8032_positive(name, sk, pk, msg, sig):
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sk))
    msg_b, sig_b = bytes.fromhex(msg), bytes.fromhex(sig)
    assert _raw_pub(priv).hex() == pk
    assert priv.sign(msg_b).hex() == sig
    load_ed25519_public_key(pk).verify(sig_b, msg_b)
    load_ed25519_public_key(bytes.fromhex(pk)).verify(sig_b, msg_b)


@pytest.mark.parametrize("name,sk,pk,msg,sig", RFC8032_VECTORS, ids=_VECTOR_IDS)
def test_rfc8032_flipped_bits_fail(name, sk, pk, msg, sig):
    pk_b, msg_b, sig_b = bytes.fromhex(pk), bytes.fromhex(msg), bytes.fromhex(sig)

    msg_bits = range(len(msg_b) * 8) if len(msg_b) <= 8 else range(0, len(msg_b) * 8, 7)
    for bit in msg_bits:
        with pytest.raises(InvalidSignature):
            load_ed25519_public_key(pk_b).verify(sig_b, _flip_bit(msg_b, bit))
    if not msg_b:
        with pytest.raises(InvalidSignature):
            load_ed25519_public_key(pk_b).verify(sig_b, b"\x00")

    for bit in range(0, 512, 3):
        with pytest.raises(InvalidSignature):
            load_ed25519_public_key(pk_b).verify(_flip_bit(sig_b, bit), msg_b)

    for bit in range(0, 256, 3):
        bad_pk = _flip_bit(pk_b, bit)
        try:
            key = ed25519.Ed25519PublicKey.from_public_bytes(bad_pk)
        except ValueError:
            continue  # not a valid curve point
        with pytest.raises(InvalidSignature):
            key.verify(sig_b, msg_b)


LOW_ORDER_POINTS = [
    "0100000000000000000000000000000000000000000000000000000000000000",  # identity
    "0000000000000000000000000000000000000000000000000000000000000000",  # order 4
    "0000000000000000000000000000000000000000000000000000000000000080",  # order 4
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # order 2
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",  # order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",  # order 8
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",  # order 8
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",  # order 8
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # non-canonical
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # non-canonical
]


@pytest.mark.parametrize("point", LOW_ORDER_POINTS)
def test_low_order_public_key_detected(point):
    assert is_small_order_public_key(bytes.fromhex(point))


def test_valid_rfc8032_keys_are_not_low_order():
    for _, _, pk, _, _ in RFC8032_VECTORS:
        assert not is_small_order_public_key(bytes.fromhex(pk))


@pytest.mark.parametrize("point", LOW_ORDER_POINTS)
def test_receipt_with_low_order_pubkey_rejected(tmp_path, point):
    """A forged receipt signed 'by' a low-order key must never verify."""
    log = tmp_path / "forged.ndjson"
    log.write_text("", encoding="utf-8")
    payload = {
        "version": 1,
        "session_id": "forged",
        "log": log.name,
        "record_count": 0,
        "final_hash": "0" * 64,
        "public_key": point,
    }
    forged_sig = bytes.fromhex(LOW_ORDER_POINTS[0]) + bytes(32)
    rp = receipt_path(log)
    rp.write_text(
        json.dumps({"payload": payload, "signature": forged_sig.hex()}), encoding="utf-8"
    )
    problems, _ = verify_receipt(log, rp, point)
    assert any("low-order" in p for p in problems), problems


def test_noncanonical_s_signature_rejected():
    """Malleability: S' = S + L must be rejected (RFC 8032 section 5.1.7)."""
    L = 2**252 + 27742317777372353535851937790883648493
    _, sk, pk, msg, sig = RFC8032_VECTORS[1]
    sig_b = bytes.fromhex(sig)
    s_malleated = (int.from_bytes(sig_b[32:], "little") + L).to_bytes(32, "little")
    with pytest.raises(InvalidSignature):
        load_ed25519_public_key(pk).verify(sig_b[:32] + s_malleated, bytes.fromhex(msg))