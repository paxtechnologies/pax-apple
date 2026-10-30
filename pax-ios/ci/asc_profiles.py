# SPDX-License-Identifier: GPL-3.0-only
"""App Store provisioning profiles for ios-upload (App Store Connect API, ASC key from the env).

  refresh   before the export: print the bundle IDs' capabilities, require Family Controls
            (Distribution) on all four, then delete their existing IOS_APP_STORE profiles so the
            export's automatic signing makes new ones from today's capabilities. Only profiles are
            deleted; certificates are never touched.
  check DIR after the export: read embedded.mobileprovision of the app and each extension in the
            unpacked IPA at DIR and require an App Store profile (no device list, get-task-allow
            false, beta-reports-active) for the right bundle ID whose Entitlements include
            com.apple.developer.family-controls = true.

env: ASC_KEY_ID, ASC_ISSUER_ID, KEY.  usage (from pax-ios/): python3 ci/asc_profiles.py refresh|check DIR"""
import glob, os, plistlib, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

TEAM = "Z94GSK7JA8"
IDS = ["org.paxpeace.pax", "org.paxpeace.pax.shield-configuration", "org.paxpeace.pax.shield-action",
       "org.paxpeace.pax.monitor"]
FC = "com.apple.developer.family-controls"


def refresh():
    import asc_metadata as m
    bad = []
    for ident in IDS:
        d = [b for b in m.call("GET", f"/v1/bundleIds?filter[identifier]={ident}&limit=20")["data"]
             if b["attributes"].get("identifier") == ident]
        if len(d) != 1:
            bad.append(f"{ident}: {len(d)} bundle IDs")
            continue
        bid = d[0]["id"]
        caps = sorted(c["attributes"].get("capabilityType") for c in
                      m.call("GET", f"/v1/bundleIds/{bid}/bundleIdCapabilities")["data"])
        print(f"{ident} ({bid}) capabilities: {', '.join(caps)}")
        if "FAMILY_CONTROLS_DISTRIBUTION" not in caps:
            bad.append(f"{ident}: no Family Controls (Distribution) capability")
        for p in m.call("GET", f"/v1/bundleIds/{bid}/profiles?limit=50")["data"]:
            a = p["attributes"]
            if a.get("profileType") != "IOS_APP_STORE":
                continue
            m.call("DELETE", f"/v1/profiles/{p['id']}")
            print(f"  deleted App Store profile {p['id']} {a.get('name')!r} ({a.get('profileState')}, uuid {a.get('uuid')})")
    if bad:
        print("::error::" + "; ".join(bad))
        sys.exit(1)


def profile(path):
    xml = subprocess.run(["security", "cms", "-D", "-i", path], capture_output=True, check=True).stdout
    return plistlib.loads(xml)


def check(root):
    app = os.path.join(root, "Payload", "Pax.app")
    bundles = [app] + sorted(glob.glob(os.path.join(app, "PlugIns", "*.appex")))
    bad = []
    seen = set()
    for b in bundles:
        info = plistlib.load(open(os.path.join(b, "Info.plist"), "rb"))
        ident = info["CFBundleIdentifier"]
        seen.add(ident)
        prof_path = os.path.join(b, "embedded.mobileprovision")
        if not os.path.exists(prof_path):
            bad.append(f"{ident}: no embedded.mobileprovision")
            continue
        p = profile(prof_path)
        e = p.get("Entitlements", {})
        problems = []
        if e.get(FC) is not True:
            problems.append("profile lacks Family Controls")
        if e.get("application-identifier") != f"{TEAM}.{ident}":
            problems.append(f"profile is for {e.get('application-identifier')}")
        if p.get("ProvisionedDevices") or p.get("ProvisionsAllDevices"):
            problems.append("not an App Store profile (device list)")
        if e.get("get-task-allow") is not False:
            problems.append("get-task-allow is not false")
        if e.get("beta-reports-active") is not True:
            problems.append("beta-reports-active missing")
        print(f"{ident}: profile {p.get('Name')!r} uuid {p.get('UUID')} created {p.get('CreationDate')} "
              f"family-controls={e.get(FC)} {'OK' if not problems else 'BAD: ' + '; '.join(problems)}")
        bad += [f"{ident}: {x}" for x in problems]
    missing = set(IDS) - seen
    if missing:
        bad.append(f"bundles missing from the IPA: {sorted(missing)}")
    if bad:
        print("::error::" + "; ".join(bad))
        sys.exit(1)


if __name__ == "__main__":
    if sys.argv[1] == "refresh":
        refresh()
    elif sys.argv[1] == "check":
        check(sys.argv[2])
    else:
        sys.exit(f"unknown command {sys.argv[1]}")
