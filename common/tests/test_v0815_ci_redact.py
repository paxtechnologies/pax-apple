# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.15: the published CI build log never shows the signing certificate's name
(mac-app/scripts/redact-log.py, used by the Build DMG workflow)."""
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "mac-app" / "scripts" / "redact-log.py"
spec = importlib.util.spec_from_file_location("redact_log", SCRIPT)
rl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rl)

NAME = "EXAMPLE SIGNER CO"   # a stand-in; the real name never appears in the repo
LOG = f"""==> Signing (Developer ID Application: {NAME} (ABCDE12345))
Authority=Developer ID Application: {NAME} (ABCDE12345)
Authority=Developer ID Certification Authority
TeamIdentifier=ABCDE12345
/tmp/Pax.app: accepted
source=Notarized Developer ID
origin=Developer ID Application: {NAME} (ABCDE12345)
SIGN_IDENTITY="Developer ID Application: {NAME}"
notary: submitted by {NAME.title()}
"""


def test_every_identity_line_is_masked():
    out = rl.redact(LOG, [NAME])
    assert NAME.lower() not in out.lower()
    assert out.count("[signing identity]") == 5
    assert "Developer ID Application: [signing identity] (ABCDE12345)" in out
    assert "Authority=Developer ID Certification Authority" in out        # untouched
    assert "source=Notarized Developer ID" in out


def test_without_the_name_file_the_pattern_still_masks(tmp_path):
    src, dst = tmp_path / "in.log", tmp_path / "out.log"
    src.write_text(LOG)
    env = {k: v for k, v in os.environ.items() if k != "PAX_SIGNER_NAME_FILE"}
    subprocess.run([sys.executable, str(SCRIPT), str(src), str(dst)], check=True, env=env)
    out = dst.read_text()
    assert f"Application: {NAME}" not in out and "Authority=Developer ID Application: [signing identity]" in out


def test_name_file_covers_other_lines(tmp_path):
    src, dst, nf = tmp_path / "in.log", tmp_path / "out.log", tmp_path / "name"
    src.write_text(LOG)
    nf.write_text(NAME)
    subprocess.run([sys.executable, str(SCRIPT), str(src), str(dst)], check=True,
                   env={**os.environ, "PAX_SIGNER_NAME_FILE": str(nf)})
    assert NAME.lower() not in dst.read_text().lower()


def test_workflow_publishes_only_the_redacted_log():
    wf = (REPO / ".github" / "workflows" / "build-dmg.yml").read_text()
    assert 'python3 mac-app/scripts/redact-log.py "$RUNNER_TEMP/build.log" "$LOGDIR/build.log"' in wf
    assert 'cp "$RUNNER_TEMP/build.log" "$LOGDIR/build.log"' not in wf
    assert 'echo "Signing as: $ID"' not in wf
