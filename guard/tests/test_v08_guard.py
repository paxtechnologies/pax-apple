# SPDX-License-Identifier: GPL-3.0-only
"""v0.8.0 pax-guard wiring: local escrow mode end to end through the app
socket handler, DNS settings pointed at 127.0.0.1 (and restored on removal),
the local-DNS pf rules (root-only upstreams, with the fallback), and selftest."""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import guard_config as gc  # noqa: E402
import pax_guard as pg  # noqa: E402
from test_guard import FakeSystem  # noqa: E402


class NetSystem(FakeSystem):
    def __init__(self, tmp):
        super().__init__(tmp)
        self.dns = {"Wi-Fi": "There aren't any DNS Servers set on Wi-Fi.", "USB 10/100/1000 LAN": "192.168.1.1\n"}
        self.refuse_user_rule = False

    def run(self, args, stdin=None, timeout=30):
        if args[:2] == ["/usr/sbin/networksetup", "-listallnetworkservices"]:
            self.commands.append(args)
            return 0, ("An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n"
                       "USB 10/100/1000 LAN\n*Thunderbolt Bridge\n")
        if args[:2] == ["/usr/sbin/networksetup", "-getdnsservers"]:
            self.commands.append(args)
            return 0, self.dns[args[2]]
        if args[:2] == ["/usr/sbin/networksetup", "-setdnsservers"]:
            self.commands.append(args)
            self.dns[args[2]] = "\n".join(a for a in args[3:] if a != "Empty") or "There aren't any"
            return 0, ""
        if args[:1] == ["/sbin/pfctl"] and "-f" in args and self.refuse_user_rule and "user root" in (stdin or ""):
            self.commands.append(args)
            return 1, "syntax error"
        return super().run(args, stdin, timeout)

    def run_split(self, args, stdin=None, timeout=30):
        return 0, "", ""


def local_guard(tmp_path, **cfg):
    s = NetSystem(tmp_path)
    c = pg.GuardConfig(profile_identifier="org.paxpeace.pax.macos-selflock.abc", user="alex",
                       escrow_mode="local", **cfg)
    g = pg.Guard(c, s, state_dir=tmp_path / "PaxGuard" / "state", quarantine_dir=tmp_path / "q")
    g.escrow.require_root = False
    return g, s


def test_auto_mode_picks_server_with_token_else_local():
    assert pg.GuardConfig().local_escrow is True
    assert pg.GuardConfig(guard_token="t" * 30).local_escrow is False
    assert pg.GuardConfig(guard_token="t" * 30, escrow_mode="local").local_escrow is True


def test_local_mode_cycle_points_dns_at_forwarder_and_loads_local_pf(tmp_path):
    g, s = local_guard(tmp_path)
    res = g.cycle()
    assert sorted(res["dns_settings"]) == ["USB 10/100/1000 LAN", "Wi-Fi"]
    assert s.dns["Wi-Fi"] == "127.0.0.1" and s.dns["USB 10/100/1000 LAN"] == "127.0.0.1"
    assert ["/usr/sbin/networksetup", "-setdnsservers", "Thunderbolt Bridge", "127.0.0.1"] not in s.commands
    assert "user root" in s.pf_loaded and "pass quick on lo0 all" in s.pf_loaded
    assert "94.140.14.15" in s.pf_loaded.split("<pax_upstream>")[1].split("}")[0]
    assert "port 53" in s.pf_loaded and "pax_sysdns" not in s.pf_loaded
    # second cycle: nothing to re-point
    assert g.cycle()["dns_settings"] == []
    # removal restores what was there before
    done = g.uninstall()
    assert any("DNS settings restored" in d for d in done)
    assert s.dns["USB 10/100/1000 LAN"] == "192.168.1.1" and s.dns["Wi-Fi"] == "There aren't any"


def test_pf_without_user_matching_still_only_filtered_upstreams(tmp_path):
    g, s = local_guard(tmp_path)
    s.refuse_user_rule = True
    assert g.enforce_pf()
    assert "user root" not in s.pf_loaded and "pass out quick proto tcp from any to <pax_upstream> port 443" in s.pf_loaded
    assert "block drop out quick proto { tcp udp } from any to any port 53" in s.pf_loaded
    assert g._load_json("pf.json", {})["no_user_match"] is True


def test_socket_handler_local_escrow_and_blocklist(tmp_path):
    g, s = local_guard(tmp_path)
    r = g.handle_request({"cmd": "escrow.status"}, 501)
    assert not r["ok"] and r["code"] == "PAX-ESCROW-009"
    s.t -= 30 * 86400
    g.escrow.deposit("paxadmin", "pw-held-by-guard", wait_seconds=24 * 3600)
    s.t += 30 * 86400
    g.escrow.heartbeat()
    import guard_ipc
    g._reveal_rate = guard_ipc.RateLimit(10)
    r = g.handle_request({"cmd": "escrow.request", "reason": "remove"}, 501)
    assert r["ok"] and r["device"]["removal_request"]["seconds_remaining"] == 24 * 3600
    r = g.handle_request({"cmd": "escrow.reveal"}, 501)
    assert not r["ok"] and r["code"] == "PAX-ESCROW-007" and "pw-held" not in json.dumps(r)
    r = g.handle_request({"cmd": "blocklist.add", "domain": "example.com"}, 501)
    assert r["ok"] and r["created"]
    assert "0.0.0.0 example.com" in s.files[gc.HOSTS_PATH]
    r = g.handle_request({"cmd": "blocklist.unblock", "domain": "example.com"}, 501)
    assert r["request"]["seconds_remaining"] == 24 * 3600
    assert g.handle_request({"cmd": "nope"}, 501)["code"] == "PAX-GUARD-012"
    summary = g.handle_request({"cmd": "status"}, 501)
    assert summary["ok"] and summary["escrow_mode"] == "local" and summary["version"] == "0.8.16"
    # after the wait, the released flag pauses enforcement (removal does the rest)
    for _ in range(49):
        s.t += 1800
        g.escrow.mono = (lambda base=s.t: float(base))
        g.cycle()
    r = g.handle_request({"cmd": "escrow.reveal"}, 501)
    assert r["ok"] and r["released"]["removal_password"] == "pw-held-by-guard"
    assert g.cycle() == {"released": True}


def test_server_mode_refuses_local_escrow_requests(tmp_path):
    s = NetSystem(tmp_path)
    c = pg.GuardConfig(server_url="https://pax.example.org/", guard_token="g" * 30, escrow_mode="server")
    g = pg.Guard(c, s, state_dir=tmp_path / "state", quarantine_dir=tmp_path / "q")
    assert g.handle_request({"cmd": "escrow.reveal"}, 501)["code"] == "PAX-ESCROW-009"
    assert g.handle_request({"cmd": "blocklist.get"}, 501)["code"] == "PAX-ESCROW-009"


def test_forwarder_policy_includes_categories_and_exceptions(tmp_path):
    g, s = local_guard(tmp_path)
    g.remote = {"blocked": ["mine.example"], "allowed": ["anydesk.com"]}
    pol = g.forwarder_policy()
    # v0.8.13: X / Bluesky media are restricted (no exception frees them), not categories.
    assert "mine.example" in pol.blocked and "pbs.twimg.com" in pol.restricted
    assert "cdn.bsky.app" in pol.restricted and "anydesk.com" not in pol.categories
    assert "sensepc.com" in pol.categories


def test_selftest_passes_on_the_repo():
    r = subprocess.run([sys.executable, str(Path(pg.__file__)), "selftest"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(r.stdout)["ok"] is True
