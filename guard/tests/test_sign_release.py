# SPDX-License-Identifier: GPL-3.0-only
"""scripts/sign-release.py: what it writes is what pax-guard accepts, and it
refuses to sign with a key pax-guard wouldn't trust or to write unsigned."""
import base64
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "guard"))
import ed25519  # noqa: E402
import pax_signing  # noqa: E402
import pax_update  # noqa: E402

spec = importlib.util.spec_from_file_location("sign_release", ROOT / "scripts" / "sign-release.py")
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)

SEED = b"\x09" * 32


@pytest.fixture
def pinned(monkeypatch):
    monkeypatch.setattr(pax_signing, "PUBLIC_KEYS_HEX", [ed25519.public_key(SEED).hex()])


def test_signed_manifest_is_accepted_by_guard(tmp_path, monkeypatch, pinned):
    z = tmp_path / "Pax-0.8.1.zip"
    z.write_bytes(b"PK" + b"x" * 1000)
    monkeypatch.setenv("PAX_UPDATE_SIGNING_KEY", base64.b64encode(SEED).decode())
    out = tmp_path / "pax-update.json"
    assert sr.main(["sign", "--zip", str(z), "--version", "0.8.1", "--minimum-version", "0.8.0",
                    "--out", str(out)]) == 0
    doc = json.loads(out.read_text())
    payload = pax_signing.verify_document(doc)
    assert pax_update.validate_manifest(payload)["version"] == "0.8.1"
    assert payload["url"] == "https://github.com/paxtechnologies/pax-apple/releases/download/v0.8.1/Pax-0.8.1.zip"
    assert payload["size"] == 1002
    assert sr.main(["verify", str(out), "--zip", str(z)]) == 0
    z.write_bytes(b"tampered")
    assert sr.main(["verify", str(out), "--zip", str(z)]) == 1
    assert base64.b64encode(SEED).decode() not in out.read_text()


def test_refuses_unpinned_key_and_missing_key(tmp_path, monkeypatch, pinned):
    z = tmp_path / "Pax-0.8.1.zip"
    z.write_bytes(b"PK")
    monkeypatch.setenv("PAX_UPDATE_SIGNING_KEY", base64.b64encode(b"\x01" * 32).decode())
    with pytest.raises(SystemExit, match="isn't pinned"):
        sr.main(["sign", "--zip", str(z), "--version", "0.8.1", "--out", str(tmp_path / "m.json")])
    monkeypatch.setenv("PAX_UPDATE_SIGNING_KEY", "")
    with pytest.raises(SystemExit, match="no signing key"):
        sr.main(["sign", "--zip", str(z), "--version", "0.8.1", "--out", str(tmp_path / "m.json")])
    assert not (tmp_path / "m.json").exists()


def test_keygen_never_overwrites(tmp_path, capsys):
    k = tmp_path / "key.txt"
    assert sr.main(["keygen", "--out", str(k)]) == 0
    pub = capsys.readouterr().out.strip()
    assert ed25519.public_key(pax_signing.seed_from_text(k.read_text())).hex() == pub
    assert (k.stat().st_mode & 0o777) == 0o600
    with pytest.raises(SystemExit):
        sr.main(["keygen", "--out", str(k)])


def test_v086_sign_with_parts_and_verify(tmp_path, monkeypatch, pinned):
    """The release step: parts under 20 MB in the signed payload; verify joins them."""
    z = tmp_path / "Pax-0.8.6.zip"
    z.write_bytes(bytes(range(256)) * 400)                       # 102400 bytes
    monkeypatch.setenv("PAX_UPDATE_SIGNING_KEY", base64.b64encode(SEED).decode())
    out, parts = tmp_path / "pax-update.json", tmp_path / "parts"
    base = "https://cdn.jsdelivr.net/gh/paxtechnologies/pax-apple@releases/parts/0.8.6/"
    assert sr.main(["sign", "--zip", str(z), "--version", "0.8.6", "--minimum-version", "0.8.0",
                    "--parts-dir", str(parts), "--part-base", base, "--part-size", "40000",
                    "--out", str(out)]) == 0
    payload = pax_signing.verify_document(json.loads(out.read_text()))
    assert pax_update.validate_manifest(payload)["parts"]["base_urls"] == [base]
    assert [p["size"] for p in payload["parts"]["files"]] == [40000, 40000, 22400]
    assert payload["mirrors"] == [] and payload["size"] == 102400
    assert sr.main(["verify", str(out), "--zip", str(z), "--parts-dir", str(parts)]) == 0
    (parts / "Pax-0.8.6.zip.part-001").write_bytes(b"\0" * 40000)
    assert sr.main(["verify", str(out), "--parts-dir", str(parts)]) == 1
    with pytest.raises(SystemExit, match="part-base"):
        sr.main(["sign", "--zip", str(z), "--version", "0.8.6", "--parts-dir", str(tmp_path / "p2"),
                 "--part-base", "http://insecure/", "--out", str(tmp_path / "m.json")])
