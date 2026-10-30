# SPDX-License-Identifier: GPL-3.0-only
"""Read-only signing report for Pax on iOS (App Store Connect API).

Prints, for the app and its three extensions: bundle ID capabilities, provisioning profiles (type,
state, dates, and whether the profile's own Entitlements include Family Controls), certificates
(type, name, ID, expiry), the builds of VERSION with the entitlements Apple recorded for each bundle,
the version's state and attached build, and review submissions. Writes nothing.

env: ASC_KEY_ID, ASC_ISSUER_ID, KEY, APP_ID, VERSION.  usage (from pax-ios/): python3 ci/asc_signing.py"""
import base64, json, os, plistlib, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import asc_metadata as m  # noqa: E402

IDS = ["org.paxpeace.pax", "org.paxpeace.pax.shield-configuration", "org.paxpeace.pax.shield-action",
       "org.paxpeace.pax.monitor"]
FC = "com.apple.developer.family-controls"


def get(path):
    try:
        return m.call("GET", path)
    except Exception as e:  # keep going; print what refused
        print(f"  (GET {path.split('?')[0]} refused: {str(e)[:300]})")
        return {"data": []}


def profile_entitlements(content_b64):
    der = base64.b64decode(content_b64)
    i = der.find(b"<?xml")
    j = der.find(b"</plist>", i)
    if i < 0 or j < 0:
        return {}
    return plistlib.loads(der[i:j + 8])


def main():
    app, ver = os.environ["APP_ID"], os.environ["VERSION"]
    print("== bundle IDs and capabilities")
    bids = {}
    for ident in IDS:
        d = get(f"/v1/bundleIds?filter[identifier]={ident}&limit=20")["data"]
        for b in d:
            a = b["attributes"]
            if a.get("identifier") != ident:
                continue
            bids[b["id"]] = ident
            print(f"{ident} id={b['id']} platform={a.get('platform')} seedId={a.get('seedId')}")
            caps = get(f"/v1/bundleIds/{b['id']}/bundleIdCapabilities?limit=50")["data"]
            for c in caps:
                ca = c["attributes"]
                st = json.dumps(ca.get("settings")) if ca.get("settings") else ""
                print(f"   cap {ca.get('capabilityType')} {st}")
    print("\n== profiles")
    profs = get("/v1/profiles?limit=200&include=bundleId,certificates")
    for p in profs["data"]:
        a = p["attributes"]
        bid = ((p.get("relationships") or {}).get("bundleId") or {}).get("data") or {}
        certs = ((p.get("relationships") or {}).get("certificates") or {}).get("data") or []
        ent = {}
        if a.get("profileContent"):
            try:
                pl = profile_entitlements(a["profileContent"])
                ent = pl.get("Entitlements", {})
                created = pl.get("CreationDate")
            except Exception as e:
                created = f"unreadable {e}"
        print(f"{p['id']} {a.get('profileType')} state={a.get('profileState')} name={a.get('name')!r} "
              f"bundle={bids.get(bid.get('id'), bid.get('id'))} uuid={a.get('uuid')} created={a.get('createdDate') or created} "
              f"expires={a.get('expirationDate')} certs={[c['id'] for c in certs]} familyControls={ent.get(FC)}")
    print("\n== certificates")
    for c in get("/v1/certificates?limit=200")["data"]:
        a = c["attributes"]
        print(f"{c['id']} {a.get('certificateType')} {a.get('name')!r} {a.get('displayName')!r} "
              f"expires={a.get('expirationDate')} serial={a.get('serialNumber')}")
    print("\n== builds of " + ver)
    bl = get(f"/v1/builds?filter[app]={app}&filter[preReleaseVersion.version]={ver}"
             f"&filter[preReleaseVersion.platform]=IOS&sort=-uploadedDate&limit=20")["data"]
    for b in bl:
        a = b["attributes"]
        print(f"build ({a.get('version')}) {b['id']} uploaded={a.get('uploadedDate')} "
              f"processing={a.get('processingState')} expired={a.get('expired')}")
        bb = get(f"/v1/builds/{b['id']}?include=buildBundles&limit[buildBundles]=20")
        for x in [i for i in bb.get("included", []) if i.get("type") == "buildBundles"]:
            xa = x["attributes"]
            ents = xa.get("entitlements")
            flat = json.dumps(ents)[:1500] if ents is not None else None
            print(f"   bundle {xa.get('bundleId')} type={xa.get('bundleType')} entitlements={flat}")
    print("\n== version")
    for v in get(f"/v1/apps/{app}/appStoreVersions?filter[platform]=IOS&limit=50")["data"]:
        a = v["attributes"]
        att = (get(f"/v1/appStoreVersions/{v['id']}/build") or {}).get("data")
        print(f"{a.get('versionString')} {v['id']} appStoreState={a.get('appStoreState')} "
              f"appVersionState={a.get('appVersionState')} releaseType={a.get('releaseType')} "
              f"build={att and att['attributes'].get('version')}")
    print("\n== review submissions")
    for s in get(f"/v1/reviewSubmissions?filter[app]={app}&filter[platform]=IOS&limit=50")["data"]:
        a = s["attributes"]
        print(f"{s['id']} state={a.get('state')} submitted={a.get('submittedDate')}")
        for it in get(f"/v1/reviewSubmissions/{s['id']}/items?limit=20")["data"]:
            print(f"   item {it['id']} state={it['attributes'].get('state')}")


if __name__ == "__main__":
    main()
