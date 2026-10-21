# SPDX-License-Identifier: GPL-3.0-only
"""The Windows workflow runs only for the windows-setup branch; the existing workflows
skip that branch but still run for every other branch and every tag (releases)."""
from pathlib import Path

import yaml

WF = Path(__file__).resolve().parents[2] / ".github" / "workflows"


def triggers(name):
    doc = yaml.safe_load((WF / name).read_text())
    return doc.get("on", doc.get(True))


def test_windows_workflow_only_on_its_branch():
    on = triggers("windows-setup.yml")
    assert on["push"] == {"branches": ["windows-setup"]}
    assert "workflow_dispatch" in on and "schedule" not in on and "pull_request" not in on
    text = (WF / "windows-setup.yml").read_text()
    assert "contents: read" in text
    for word in ("ci-logs", "git push", "gh release", "signtool"):
        assert word not in text.replace("ci-logs* branches", ""), word


def test_existing_workflows_skip_the_branch_and_keep_tags():
    for name in ("ci.yml", "build-dmg.yml"):
        push = triggers(name)["push"]
        assert push["branches-ignore"] == ["windows-setup"], name
        assert push["tags"] == ["**"], name          # without it, tag (release) pushes would stop


def test_spec_builds_both_programs():
    spec = (Path(__file__).resolve().parents[1] / "pax_setup.spec").read_text()
    assert 'name="PaxSetup"' in spec and 'name="pax-helper"' in spec
    assert "console=False" in spec and "console=True" in spec


def test_dependencies_doc_lists_the_windows_extras():
    import sys
    from pathlib import Path as P
    repo = P(__file__).resolve().parents[2]
    sys.path.insert(0, str(repo / "device"))
    import lock_bundle
    doc = (repo / "docs" / "DEPENDENCIES.md").read_text()
    mac = dict(lock_bundle.pins((repo / "device" / "requirements-bundle.in").read_text()))
    for name, version in lock_bundle.pins((repo / "windows" / "requirements-windows.in").read_text()):
        if mac.get(name) != version:
            assert f"[{name}](https://pypi.org/project/{name}/{version}/) {version}" in doc, name
