"""Create self-contained signed evidence bundles for offline audits."""
import json
import shutil
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .report import build_report_data, render_html

_FORBIDDEN_NAMES = frozenset({"key", "hmac.key", "ed25519.key"})


def _manifest_for(log_path):
    """Derive manifest path from a log path (matches signer convention)."""
    p = Path(log_path)
    return p.with_name(p.stem + ".manifest.json")


def _receipt_for(log_path):
    """Derive receipt path from a log path (matches signer convention)."""
    p = Path(log_path)
    return p.with_name(p.stem + ".receipt.json")


def _read_events(log_path):
    """Read all events from a log, skipping malformed lines."""
    events = []
    with open(log_path, encoding="utf-8") as f:
        for line in f:
            try:
                events.append(json.loads(line)["event"])
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
    return events


def _extract_contract_info(log_path):
    """Pull contract definition and verdict from the log, if present."""
    contract_def, verdict = None, None
    with open(log_path, encoding="utf-8") as f:
        for line in f:
            try:
                ev = json.loads(line)["event"]
                etype = ev["event_type"]
                data = ev.get("data") or {}
                if etype == "session.start" and "contract" in data:
                    contract_def = data["contract"]
                elif etype == "contract.verdict":
                    verdict = data
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
    if contract_def is None and verdict is None:
        return None
    result = {}
    if contract_def:
        result["definition"] = contract_def
    if verdict:
        result["verdict"] = verdict
    return result


def _audit_instructions(session_id, has_receipt, has_pubkey):
    """Generate the AUDIT_INSTRUCTIONS.md content."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# Audit Instructions\n",
        f"**Session:** `{session_id}`  ",
        f"**Exported:** {ts}\n",
        "## Contents\n",
        "| File | Description |",
        "|------|-------------|",
        "| `audit.ndjson` | Raw canonical log with hash chain and HMAC signatures |",
    ]
    if has_receipt:
        lines.append(
            "| `receipt.json` | Ed25519-signed receipt (run summary + final hash) |"
        )
    lines.append(
        "| `manifest.json` | HMAC-signed session manifest (present if session completed) |"
    )
    if has_pubkey:
        lines.append(
            "| `public.key` | Ed25519 public key (hex) for receipt verification |"
        )
    lines += [
        "| `contract.json` | Host-evaluated task contract verdict (if contract was set) |",
        "| `viewer.html` | Self-contained HTML flight report — open in any browser |",
        "| `verify.py` | Standalone verifier (Python >= 3.10, zero dependencies) |\n",
        "## Quick Verification\n",
    ]
    if has_receipt and has_pubkey:
        lines += [
            "### Receipt mode (recommended for third-party audits)\n",
            "```bash",
            "python verify.py audit.ndjson --pubkey public.key --receipt receipt.json",
            "```\n",
        ]
    lines += [
        "### With agentbox CLI\n",
        "```bash",
        "agentbox verify ./evidence.zip --pubkey ed25519.pub",
        "```\n",
        "### Visual inspection\n",
        "Open `viewer.html` in any browser — no server required.\n",
        "## Security Notes\n",
        "- The HMAC symmetric key is **never** included in this bundle.",
        "- Receipt verification uses only the Ed25519 **public** key.",
        "- The hash chain can be verified independently of any signature scheme.",
        "- `verify.py` has zero external dependencies (uses only Python stdlib,",
        "  with optional `cryptography` for faster Ed25519 verification).\n",
    ]
    return "\n".join(lines)


def _find_verify_script():
    """Locate examples/verify_standalone.py relative to the package."""
    for candidate in [
        Path(__file__).resolve().parent.parent.parent / "examples" / "verify_standalone.py",
        Path(__file__).resolve().parent.parent / "examples" / "verify_standalone.py",
        Path(__file__).resolve().parent / "verify_standalone.py",
    ]:
        if candidate.is_file():
            return candidate
    return None


def create_bundle(log_path, output=None, pubkey_path=None, fmt="zip"):
    """Package a log and its artifacts into a self-contained evidence bundle.

    Args:
        log_path: Path to the .ndjson log file.
        output: Output archive path.  Auto-generated if *None*.
        pubkey_path: Ed25519 **public** key file (hex) to embed.
                     The HMAC symmetric key must NEVER be passed here.
        fmt: ``"zip"`` (default, Windows-friendly) or ``"tar.gz"`` (POSIX).

    Returns:
        Path to the created archive.

    Raises:
        FileNotFoundError: log does not exist.
        ValueError: bad format or an attempt to bundle a private/HMAC key.
    """
    log_path = Path(log_path)
    if not log_path.is_file():
        raise FileNotFoundError(f"log file not found: {log_path}")
    if fmt not in ("zip", "tar.gz"):
        raise ValueError(f"unsupported format: {fmt!r} (use 'zip' or 'tar.gz')")

    # --- safety: never bundle a private or HMAC key ---
    if pubkey_path is not None:
        pk = Path(pubkey_path)
        if pk.name.lower() in _FORBIDDEN_NAMES:
            raise ValueError(
                f"refusing to bundle {pk.name!r} — looks like a private or HMAC key"
            )
        if pk.is_file():
            try:
                head = pk.read_text(encoding="utf-8", errors="replace")[:256].upper()
                if "PRIVATE" in head:
                    raise ValueError(
                        f"refusing to bundle {pk.name!r} — contains a private key marker"
                    )
            except OSError:
                pass

    session_id = log_path.stem

    if output is None:
        ext = ".zip" if fmt == "zip" else ".tar.gz"
        output = log_path.parent / f"evidence-{session_id}{ext}"
    output = Path(output)

    # --- gather source artefacts ---
    receipt_file = _receipt_for(log_path)
    manifest_file = _manifest_for(log_path)
    has_receipt = receipt_file.is_file()
    has_pubkey = pubkey_path is not None and Path(pubkey_path).is_file()

    events = _read_events(log_path)
    report_data = build_report_data(events)
    html_content = render_html(report_data)
    contract = _extract_contract_info(log_path)
    instructions = _audit_instructions(session_id, has_receipt, has_pubkey)
    verify_script = _find_verify_script()

    # --- stage everything in a temp directory, then archive ---
    with tempfile.TemporaryDirectory(prefix="agentbox-bundle-") as tmp:
        staging = Path(tmp)

        shutil.copy2(log_path, staging / "audit.ndjson")
        if manifest_file.is_file():
            shutil.copy2(manifest_file, staging / "manifest.json")
        if has_receipt:
            shutil.copy2(receipt_file, staging / "receipt.json")
        if has_pubkey:
            shutil.copy2(Path(pubkey_path), staging / "public.key")
        if contract is not None:
            (staging / "contract.json").write_text(
                json.dumps(contract, indent=2), encoding="utf-8"
            )
        (staging / "viewer.html").write_text(html_content, encoding="utf-8")
        if verify_script is not None:
            shutil.copy2(verify_script, staging / "verify.py")
        (staging / "AUDIT_INSTRUCTIONS.md").write_text(instructions, encoding="utf-8")

        if fmt == "zip":
            with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
                for item in sorted(staging.iterdir()):
                    if item.is_file():
                        zf.write(item, item.name)
        else:
            with tarfile.open(output, "w:gz") as tf:
                for item in sorted(staging.iterdir()):
                    if item.is_file():
                        tf.add(item, arcname=item.name)

    return output


def extract_bundle(bundle_path, dest=None):
    """Extract a bundle archive and return the directory with the files.

    The caller must clean up *dest* (or the auto-created temp dir) when done.
    """
    bundle_path = Path(bundle_path)
    if not bundle_path.is_file():
        raise FileNotFoundError(f"bundle not found: {bundle_path}")

    if dest is None:
        dest = Path(tempfile.mkdtemp(prefix="agentbox-evidence-"))
    else:
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)

    name = bundle_path.name.lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(bundle_path, "r") as zf:
            for info in zf.infolist():
                if info.filename.startswith("/") or ".." in info.filename:
                    raise ValueError(f"path traversal in archive: {info.filename}")
            zf.extractall(dest)
    elif name.endswith(".tar.gz") or name.endswith(".tgz"):
        with tarfile.open(bundle_path, "r:gz") as tf:
            for member in tf.getmembers():
                if member.name.startswith("/") or ".." in member.name:
                    raise ValueError(f"path traversal in archive: {member.name}")
                if not member.isfile():
                    raise ValueError(f"non-file member in archive: {member.name}")
            try:
                tf.extractall(dest, filter="data")
            except TypeError:
                tf.extractall(dest)
    else:
        raise ValueError(
            f"unsupported archive: {bundle_path.name} (expected .zip or .tar.gz)"
        )

    return dest


def is_bundle(path):
    """True when *path* looks like an evidence bundle by extension."""
    name = str(path).lower()
    return name.endswith(".zip") or name.endswith(".tar.gz") or name.endswith(".tgz")
