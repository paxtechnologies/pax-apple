# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.10: other administrators made standard at set-up stay standard. pax-guard
re-demotes one that becomes an administrator again (logged, tamper-chained), never
touches the everyday account's own entry, paxadmin or odd names, and does nothing
unless paxadmin is an administrator (the Mac is never left without one). The
uninstaller makes exactly the recorded accounts administrators again."""
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import pax_guard as pg  # noqa: E402
from test_guard import FakeSystem  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


class AdminSystem(FakeSystem):
    def __init__(self, tmp, admins):
        super().__init__(tmp)
        self.admins = set(admins)
        self.refuse_demote = False

    def run(self, args, stdin=None, timeout=30):
        if args[:1] == ["/usr/sbin/dseditgroup"]:
            self.commands.append(args)
            if "checkmember" in args:
                u = args[args.index("-m") + 1]
                return 0, (f"yes {u} is a member of admin\n" if u in self.admins
                           else f"no {u} is NOT a member of admin\n")
            if "-d" in args and not self.refuse_demote:
                self.admins.discard(args[args.index("-d") + 1])
            return 0, ""
        return super().run(args, stdin, timeout)


def guard(tmp_path, admins, demoted):
    s = AdminSystem(tmp_path, admins)
    c = pg.GuardConfig(profile_identifier="org.paxpeace.pax.macos-selflock.abc", user="alex",
                       escrow_mode="local", demoted_admins=demoted)
    g = pg.Guard(c, s, state_dir=tmp_path / "PaxGuard" / "state", quarantine_dir=tmp_path / "q")
    g.notify = lambda text: s.commands.append(["notify", text])
    return g, s


def kinds(g):
    return [e["kind"] for e in g.tamper_log.entries(50)]


def test_config_field_loads_and_defaults_empty(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"user": "alex", "demoted_admins": ["rmsvc"], "unknown": 1}))
    assert pg.GuardConfig.load(p).demoted_admins == ["rmsvc"]
    assert pg.GuardConfig().demoted_admins == []


def test_recorded_once_and_re_demoted_when_promoted_again(tmp_path):
    g, s = guard(tmp_path, ["root", "paxadmin"], ["rmsvc", "spare"])
    assert g.enforce_standard_accounts() == []
    assert kinds(g) == ["accounts:made_standard"]
    assert g.tamper_log.entries(5)[0]["detail"] == {"accounts": ["rmsvc", "spare"]}
    g.enforce_standard_accounts()
    assert kinds(g) == ["accounts:made_standard"]          # not logged twice
    s.admins.add("rmsvc")                                    # someone re-promoted it
    assert g.enforce_standard_accounts() == ["rmsvc"]
    assert "rmsvc" not in s.admins
    assert kinds(g)[-1] == "admin:made_standard_again"
    assert g.tamper_log.verify()[0]
    assert any(c[0] == "notify" and "rmsvc" in c[1] for c in s.commands)


def test_failed_re_demotion_is_logged_not_hidden(tmp_path):
    g, s = guard(tmp_path, ["root", "paxadmin", "rmsvc"], ["rmsvc"])
    s.refuse_demote = True
    assert g.enforce_standard_accounts() == []
    e = g.tamper_log.entries(5)[-1]
    assert e["kind"] == "admin:made_standard_again" and e["detail"] == {"user": "rmsvc", "ok": False}


def test_never_without_paxadmin_and_never_protected_names(tmp_path):
    g, s = guard(tmp_path, ["root", "rmsvc"], ["rmsvc"])     # paxadmin isn't an admin
    assert g.enforce_standard_accounts() == []
    assert "rmsvc" in s.admins
    g, s = guard(tmp_path / "b", ["root", "paxadmin", "alex"], ["alex", "paxadmin", "root", "-x", "a b", "_svc"])
    assert g.standard_accounts() == []
    assert g.enforce_standard_accounts() == []
    assert not [c for c in s.commands if c[:1] == ["/usr/sbin/dseditgroup"] and "-d" in c]


def test_nothing_configured_runs_nothing(tmp_path):
    g, s = guard(tmp_path, ["root", "paxadmin", "rmsvc"], [])
    assert g.enforce_standard_accounts() == []
    assert not [c for c in s.commands if c[:1] == ["/usr/sbin/dseditgroup"]] and kinds(g) == []


def test_uninstaller_restores_recorded_accounts_after_stopping_the_guard():
    src = (ROOT / "scripts" / "pax-uninstall-emergency.sh").read_text()
    stop = src.index('launchctl bootout "system/${LABEL}"')
    restore = src.index('plutil -extract "demoted_admins.$i" raw')
    remove = src.index('rm -rf "$DEST"')
    assert stop < restore < remove
    assert "dseditgroup -o edit -a \"$other\" -t user admin" in src
    assert subprocess.run(["bash", "-n", str(ROOT / "scripts" / "pax-uninstall-emergency.sh")]).returncode == 0
