#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""How fast is the Mac's DNS path? (v0.8.36). Runs pax-guard's forwarder from a guard/
folder (this checkout's by default, or an older one with --guard to compare) on a high
local port with the real upstreams and the real bundled lists, then replays page loads.

  python3 tools/dns-bench.py browse [--guard DIR] [--gap 12] [--json out.json]
      Each page: its own name plus the names its HTML pulls in (tools/dns-bench-pages.json,
      12 popular UK/US pages, 213 names), A + AAAA asked together over UDP like macOS does.
      Pass "cold": empty cache, --gap seconds between pages (a reader; Quad9 drops an idle
      DoT connection after ~10 s). Pass "revisit-30min": the same pages, the forwarder's
      clock moved 30 minutes on (most answers have expired). Pass "warm": straight away.
      Reports per page (slowest name = what the page waits for) and per lookup.
  python3 tools/dns-bench.py faults [--guard DIR]
      Fake upstreams, no network: the first upstream silent (a dead kept-alive connection
      after sleep or a network change), and the first upstream down (2 addresses timing out).
  python3 tools/dns-bench.py gil [--guard DIR] [--ads FILE]
      DNS answer time while pax-guard works out its /etc/hosts block (it shares the Python
      interpreter with the forwarder), and the CPU that takes per 30-second cycle.

On a protected Mac you can also time the real thing (HARDWARE_TEST 32-37):
  dig @127.0.0.1 www.bbc.co.uk | grep 'Query time'
"""
from __future__ import annotations

import argparse
import json
import random
import socket
import statistics
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load_guard(guard: Path):
    sys.path.insert(0, str(guard))
    sys.path.insert(0, str(guard.parent / "common"))
    import dns_forwarder as d  # noqa: E402
    return d


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))] if xs else float("nan")


def summary(xs):
    return {"n": len(xs), "median_ms": round(statistics.median(xs), 1) if xs else None,
            "p90_ms": round(pct(xs, 0.9), 1), "p99_ms": round(pct(xs, 0.99), 1), "max_ms": round(max(xs), 1)}


def ask_many(port, names, qtypes=(1, 28), timeout=5.0):
    """Ask every (name, type) at once over UDP; returns {(name, type): ms or None}."""
    socks, out = [], {}
    t0 = {}
    for n in names:
        for t in qtypes:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setblocking(False)
            qid = random.getrandbits(16)
            msg = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
            for lab in n.split("."):
                msg += bytes([len(lab)]) + lab.encode()
            msg += b"\x00" + struct.pack("!HH", t, 1)
            t0[(n, t)] = time.perf_counter()
            s.sendto(msg, ("127.0.0.1", port))
            socks.append((s, (n, t)))
    import select
    pending = dict(socks)
    end = time.perf_counter() + timeout
    while pending and time.perf_counter() < end:
        r, _, _ = select.select(list(pending), [], [], max(0, end - time.perf_counter()))
        now = time.perf_counter()
        for s in r:
            try:
                s.recv(4096)
            except OSError:
                continue
            key = pending.pop(s)
            out[key] = (now - t0[key]) * 1000
    for s, key in socks:
        out.setdefault(key, None)
        s.close()
    return out


def browse(args):
    d = load_guard(Path(args.guard))
    import filter_lists as fl
    pages = json.loads((HERE / "dns-bench-pages.json").read_text())
    t = time.time()
    fs = fl.FilterStore(Path(tempfile.mkdtemp()), log=lambda m: None).load()
    print(f"lists loaded in {time.time() - t:.1f} s ({fs.entries} entries)", flush=True)
    offset = {"s": 0.0}
    real = d.monotonic_continuous
    d.monotonic_continuous = lambda: real() + offset["s"]
    fam = d.default_upstreams()
    fwd = d.Forwarder(fam, None, log=lambda m: None, youtube_upstreams=d.youtube_upstreams(fam),
                      primary_upstreams=d.primary_upstreams())
    fwd.set_filters(fs)
    assert fwd.status()["filter_mode"] == "pax", fwd.status()["filter_mode"]
    srv = d.DNSServer(fwd, host="127.0.0.1", port=0, log=lambda m: None)
    srv.start()
    if hasattr(fwd, "start_background"):
        fwd.start_background(warm=False)      # 0.8.36+: keep-warm runs as in pax-guard (no warm-up list)
    report = {"guard": str(args.guard), "version": getattr(d, "STALE_MAX", None) and "0.8.36+" or "pre-0.8.36",
              "gap_s": args.gap, "passes": {}}
    for pass_name, shift, gap in (("cold", 0, args.gap), ("revisit-30min", 1800, args.gap), ("warm", 0, 1.0)):
        offset["s"] += shift
        page_ms, all_ms, fails = [], [], 0
        for i, (page, names) in enumerate(sorted(pages.items())):
            if i:
                time.sleep(gap)
            res = ask_many(srv.port, [page] + names)
            vals = [v for v in res.values() if v is not None]
            fails += sum(1 for v in res.values() if v is None)
            all_ms += vals
            page_ms.append(max(vals) if vals else 5000.0)
            print(f"  {pass_name:13s} {page:24s} {len(res):3d} lookups  slowest {page_ms[-1]:7.1f} ms", flush=True)
        report["passes"][pass_name] = {"page_wait": summary(page_ms), "lookup": summary(all_ms),
                                       "page_wait_total_ms": round(sum(page_ms), 1), "timeouts": fails}
        print(pass_name, json.dumps(report["passes"][pass_name]), flush=True)
    report["stats"] = {k: v for k, v in fwd.stats.items() if k != "upstream"}
    report["upstream_counts"] = fwd.stats["upstream"]
    report["handshakes"] = {u.name: getattr(u, "handshakes", None) for u in fwd.all_upstreams()}
    srv.stop()
    out = json.dumps(report, indent=1)
    print(out)
    if args.json:
        Path(args.json).write_text(out)


class FakeUp:
    """`silent_first`: the first query hangs for `timeout` then fails (a dead kept-alive
    socket); `down`: every query fails after `timeout` per address."""

    def __init__(self, d, name, latency=0.02, silent_first=False, down=False, timeout=2.5, addresses=2):
        self.d, self.name, self.url, self.host = d, name, f"https://{name}/", name
        self.latency, self.silent_first, self.down, self.timeout, self.addresses = (
            latency, silent_first, down, timeout, addresses)
        self.healthy, self.last_error, self.ips, self.trusted_time = True, "", ["192.0.2.1"], None
        self.n = 0

    def query(self, wire):
        self.n += 1
        if self.down:
            time.sleep(self.timeout * self.addresses)
            raise self.d.DNSError("down")
        if self.silent_first and self.n == 1:
            time.sleep(self.timeout)
            raise TimeoutError("silent")
        time.sleep(self.latency)
        q = self.d.Query(wire)
        hdr = struct.pack("!HHHHHH", struct.unpack("!H", wire[:2])[0], 0x8180, 1, 1, 0, 0)
        return hdr + q.question + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + b"\x01\x02\x03\x04"


def faults(args):
    d = load_guard(Path(args.guard))
    import filter_lists as fl
    from domain_matcher import SmallSuffixSet
    out = {}
    for case in ("dead-connection", "first-upstream-down"):
        ms = []
        for i in range(5):
            if case == "dead-connection":
                q9 = FakeUp(d, "Quad9", latency=0.015, silent_first=True)
            else:
                q9 = FakeUp(d, "Quad9", down=True)
            cf = FakeUp(d, "Cloudflare", latency=0.06)
            fwd = d.Forwarder([FakeUp(d, "CleanBrowsing", latency=0.08)],
                              fl.FilterSet([], SmallSuffixSet([]), {}), log=lambda m: None)
            fwd.primary_upstreams = [q9, cf]       # Pax's route without the canary (no real lists here)
            fwd.fallback_reason = None
            t = time.perf_counter()
            fwd.handle(d.build_query(f"page{i}.example", 1, 7))
            ms.append((time.perf_counter() - t) * 1000)
        out[case] = summary(ms)
        print(case, json.dumps(out[case]), flush=True)
    if args.json:
        Path(args.json).write_text(json.dumps(out, indent=1))


def gil(args):
    d = load_guard(Path(args.guard))
    import guard_config as gc
    if args.ads:
        ads = gc.parse_domain_list(Path(args.ads).read_text())
    else:
        ads = [f"ads{i}.tracker{i % 977}.example" for i in range(160_000)]
    byp = [f"vpn{i}.example" for i in range(16_000)]
    kw = dict(ads=ads, allowlist=gc.ADS_ALLOWLIST, bypass_list=byp, protected=["api.paxpeace.com"])
    gc.hosts_domains([], **kw)                    # what the daemon already did last cycle
    cycle = []
    for _ in range(3):
        t = time.process_time()
        gc.hosts_domains([], **kw)
        cycle.append(time.process_time() - t)
    fwd = d.Forwarder([FakeUp(d, "fake", latency=0.010)], None, log=lambda m: None)
    fwd.ready = True
    srv = d.DNSServer(fwd, host="127.0.0.1", port=0, log=lambda m: None)
    srv.start()

    def measure(n=200):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        out = []
        for i in range(n):
            w = d.build_query(f"n{i}-{random.random()}.example", 1, random.getrandbits(16))
            t = time.perf_counter()
            s.sendto(w, ("127.0.0.1", srv.port))
            s.recvfrom(4096)
            out.append((time.perf_counter() - t) * 1000)
        return out
    idle = measure()
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            gc.hosts_domains([], **kw)
    th = threading.Thread(target=loop, daemon=True)
    th.start()
    busy = measure()
    stop.set()
    srv.stop()
    rep = {"hosts_cycle_cpu_s": round(statistics.median(cycle), 3),
           "share_of_each_30s_cycle": f"{100 * statistics.median(cycle) / 30:.1f}%",
           "dns_idle": summary(idle), "dns_while_hosts_work": summary(busy)}
    print(json.dumps(rep, indent=1))
    if args.json:
        Path(args.json).write_text(json.dumps(rep, indent=1))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["browse", "faults", "gil"])
    ap.add_argument("--guard", default=str(HERE.parent / "guard"))
    ap.add_argument("--gap", type=float, default=12.0)
    ap.add_argument("--ads")
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    {"browse": browse, "faults": faults, "gil": gil}[a.mode](a)


if __name__ == "__main__":
    main()
