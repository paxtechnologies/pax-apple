# SPDX-License-Identifier: GPL-3.0-only
"""Write the App Store listing for one iOS version from pax-ios/appstore/ (App Store Connect API).

Never submits anything for App Review. Writes, then reads every field back and prints a match
table. Prints lengths, hashes and short public values only; never the key, a token, or the review
contact fields (those are kept as they are in App Store Connect and only read to fill the
{contact_name} / {contact_phone} placeholders in review_notes.txt).

env: ASC_KEY_ID, ASC_ISSUER_ID, KEY (path to the .p8), APP_ID, VERSION, BUILD, MODE (apply|read),
     OTHER_SETS (keep|clear: what to do with screenshot sets of other display types).
usage (from pax-ios/): python3 ci/asc_metadata.py"""
import base64, hashlib, json, os, subprocess, sys, time, urllib.error, urllib.request

API = "https://api.appstoreconnect.apple.com"
HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "appstore")
EDITABLE = {"PREPARE_FOR_SUBMISSION", "DEVELOPER_REJECTED", "REJECTED", "METADATA_REJECTED", "INVALID_BINARY"}
SETS = {"iphone69": "APP_IPHONE_67", "ipad13": "APP_IPAD_PRO_3GEN_129"}
results = []  # (field, status, detail)


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


_tok = [None, 0]


def token():
    if _tok[0] and time.time() < _tok[1] - 120:
        return _tok[0]
    now = int(time.time())
    msg = b64(json.dumps({"alg": "ES256", "kid": os.environ["ASC_KEY_ID"], "typ": "JWT"}).encode()) + "." + \
        b64(json.dumps({"iss": os.environ["ASC_ISSUER_ID"], "iat": now, "exp": now + 900,
                        "aud": "appstoreconnect-v1"}).encode())
    der = subprocess.run(["openssl", "dgst", "-sha256", "-sign", os.environ["KEY"]], input=msg.encode(),
                         capture_output=True, check=True).stdout
    i = 2 if der[1] < 0x80 else 3
    rl = der[i + 1]; r = der[i + 2:i + 2 + rl]; j = i + 2 + rl; sl = der[j + 1]; s_ = der[j + 2:j + 2 + sl]
    sig = r.lstrip(b"\0").rjust(32, b"\0") + s_.lstrip(b"\0").rjust(32, b"\0")
    _tok[0], _tok[1] = msg + "." + b64(sig), now + 900
    return _tok[0]


class ApiError(Exception):
    pass


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path if path.startswith("/") else path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + token(), "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            b = resp.read()
            return json.loads(b) if b else None
    except urllib.error.HTTPError as e:
        try:
            errs = json.loads(e.read()).get("errors", [])
            msg = "; ".join(f"{x.get('code')}: {x.get('detail') or x.get('title')}" for x in errs)
        except Exception:
            msg = ""
        raise ApiError(f"{method} {path.split('?')[0]} -> HTTP {e.code} {msg}"[:600])


def text(name):
    return open(os.path.join(HERE, name), encoding="utf-8").read().rstrip()


def sha(s):
    return hashlib.sha1(s.encode() if isinstance(s, str) else s).hexdigest()[:10]


def step(field, fn):
    try:
        fn()
    except ApiError as e:
        results.append((field, "ERROR", str(e)))
        print(f"::warning::{field}: {e}")


def check(field, want, got, public=True):
    ok = (got or "") == want
    shown = (got if public and got and len(got) <= 120 else f"len {len(got or '')} sha {sha(got or '')}")
    results.append((field, "OK" if ok else "MISMATCH", shown if ok else f"want len {len(want)} sha {sha(want)}; got {shown}"))


def main():
    app, ver, build, mode = os.environ["APP_ID"], os.environ["VERSION"], os.environ["BUILD"], os.environ.get("MODE", "apply")
    other_sets = os.environ.get("OTHER_SETS", "keep")
    apply = mode == "apply"
    print(f"app {app} version {ver} build {build} mode {mode} other sets {other_sets}")

    vs = call("GET", f"/v1/apps/{app}/appStoreVersions?filter[versionString]={ver}&filter[platform]=IOS")["data"]
    if len(vs) != 1:
        raise SystemExit(f"::error::expected one iOS version {ver}, found {len(vs)}")
    v = vs[0]; vid = v["id"]; state = v["attributes"].get("appStoreState") or v["attributes"].get("appVersionState")
    print(f"version {vid} state {state} copyright {v['attributes'].get('copyright')!r}")
    if apply and state not in EDITABLE and v["attributes"].get("appVersionState") not in EDITABLE | {"READY_FOR_REVIEW"}:
        raise SystemExit(f"::error::version {ver} is {state}; not editing it")

    # --- version localizations: promo, description, keywords, whatsNew
    want = {"promotionalText": text("promotional_text.txt"), "description": text("description.txt"),
            "keywords": text("keywords.txt"), "whatsNew": text("whats_new.txt")}
    locs = call("GET", f"/v1/appStoreVersions/{vid}/appStoreVersionLocalizations?limit=50")["data"]
    print("version locales:", [l["attributes"]["locale"] for l in locs])
    for l in locs:
        loc = l["attributes"]["locale"]
        if apply:
            main_attrs = {k: want[k] for k in ("promotionalText", "description", "keywords")}
            step(f"{loc} promo/description/keywords", lambda: call("PATCH", f"/v1/appStoreVersionLocalizations/{l['id']}",
                 {"data": {"type": "appStoreVersionLocalizations", "id": l["id"], "attributes": main_attrs}}))
            step(f"{loc} whatsNew", lambda: call("PATCH", f"/v1/appStoreVersionLocalizations/{l['id']}",
                 {"data": {"type": "appStoreVersionLocalizations", "id": l["id"], "attributes": {"whatsNew": want["whatsNew"]}}}))

    # --- app info localizations: subtitle, privacy policy URL
    infos = call("GET", f"/v1/apps/{app}/appInfos")["data"]
    for inf in infos:
        print(f"appInfo {inf['id']} state {inf['attributes'].get('appStoreState') or inf['attributes'].get('state')}")
    live = {"READY_FOR_DISTRIBUTION", "READY_FOR_SALE", "REPLACED_WITH_NEW_INFO"}
    edit_infos = [i for i in infos if (i["attributes"].get("state") or i["attributes"].get("appStoreState")) not in live] or infos[:1]
    info = edit_infos[0]
    ilocs = call("GET", f"/v1/appInfos/{info['id']}/appInfoLocalizations?limit=50")["data"]
    print("app info locales:", [l["attributes"]["locale"] for l in ilocs])
    sub, priv = text("subtitle.txt"), text("privacy_policy_url.txt")
    for l in ilocs:
        if apply:
            step(f"{l['attributes']['locale']} subtitle/privacyPolicyUrl", lambda: call("PATCH", f"/v1/appInfoLocalizations/{l['id']}",
                 {"data": {"type": "appInfoLocalizations", "id": l["id"], "attributes": {"subtitle": sub, "privacyPolicyUrl": priv}}}))

    # --- review detail: notes + demoAccountRequired=false; contact fields left as they are
    rd = call("GET", f"/v1/appStoreVersions/{vid}/appStoreReviewDetail")
    rd = rd and rd.get("data")
    notes_want = None
    if not rd:
        results.append(("review detail", "ERROR", "no appStoreReviewDetail on this version (contact not set); not creating one"))
    else:
        a = rd["attributes"]
        name = " ".join(x for x in (a.get("contactFirstName"), a.get("contactLastName")) if x)
        ph = (a.get("contactPhone") or "").replace(" ", "")
        if ph.startswith("+44") and len(ph) == 13:
            ph = f"+44 {ph[3:7]} {ph[7:]}"
        if not name or not ph:
            results.append(("review notes", "ERROR", "contact name/phone empty in App Store Connect; not writing notes"))
        else:
            notes_want = text("review_notes.txt").replace("{contact_name}", name).replace("{contact_phone}", ph)
            print(f"review notes: {len(notes_want)} chars (limit 4000); contact fields present: "
                  f"first={bool(a.get('contactFirstName'))} last={bool(a.get('contactLastName'))} "
                  f"phone={bool(a.get('contactPhone'))} email={bool(a.get('contactEmail'))}")
            if apply:
                step("review notes/demoAccountRequired", lambda: call("PATCH", f"/v1/appStoreReviewDetails/{rd['id']}",
                     {"data": {"type": "appStoreReviewDetails", "id": rd["id"],
                               "attributes": {"notes": notes_want, "demoAccountRequired": False}}}))

    # --- build
    bl = call("GET", f"/v1/builds?filter[app]={app}&filter[version]={build}&filter[preReleaseVersion.version]={ver}"
                     f"&filter[preReleaseVersion.platform]=IOS&limit=5")["data"]
    if len(bl) != 1:
        results.append(("build", "ERROR", f"expected one build {ver} ({build}), found {len(bl)}"))
        bid = None
    else:
        bid = bl[0]["id"]; ba = bl[0]["attributes"]
        print(f"build {bid} processingState {ba.get('processingState')} expired {ba.get('expired')}")
        if apply:
            step("build attach", lambda: call("PATCH", f"/v1/appStoreVersions/{vid}/relationships/build",
                 {"data": {"type": "builds", "id": bid}}))

    # --- screenshots (first version localization of each locale gets the same sets)
    for l in locs:
        loc = l["attributes"]["locale"]
        sets = call("GET", f"/v1/appStoreVersionLocalizations/{l['id']}/appScreenshotSets?limit=50")["data"]
        by_type = {s["attributes"]["screenshotDisplayType"]: s for s in sets}
        print(f"{loc} screenshot sets: {sorted(by_type)}")
        for folder, dtype in SETS.items():
            step(f"{loc} {dtype} screenshots", lambda: screenshots(loc, l["id"], folder, dtype, by_type.get(dtype), apply))
        for dtype, s in by_type.items():
            if dtype in SETS.values():
                continue
            shots = call("GET", f"/v1/appScreenshotSets/{s['id']}/appScreenshots?limit=50")["data"]
            print(f"{loc} other set {dtype}: {len(shots)} screenshots")
            if apply and other_sets == "clear":
                for sh in shots:
                    call("DELETE", f"/v1/appScreenshots/{sh['id']}")
                print(f"{loc} other set {dtype}: cleared")

    # --- read back
    print("\n== read back ==")
    for l in call("GET", f"/v1/appStoreVersions/{vid}/appStoreVersionLocalizations?limit=50")["data"]:
        loc, a = l["attributes"]["locale"], l["attributes"]
        for k in ("promotionalText", "description", "keywords", "whatsNew"):
            check(f"{loc} {k}", want[k], a.get(k))
    for l in call("GET", f"/v1/appInfos/{info['id']}/appInfoLocalizations?limit=50")["data"]:
        loc, a = l["attributes"]["locale"], l["attributes"]
        check(f"{loc} subtitle", sub, a.get("subtitle"))
        check(f"{loc} privacyPolicyUrl", priv, a.get("privacyPolicyUrl"))
    rd2 = (call("GET", f"/v1/appStoreVersions/{vid}/appStoreReviewDetail") or {}).get("data")
    if rd2:
        a = rd2["attributes"]
        if notes_want is not None:
            check("review notes", notes_want, a.get("notes"), public=False)
        results.append(("demoAccountRequired", "OK" if a.get("demoAccountRequired") is False else "MISMATCH", str(a.get("demoAccountRequired"))))
        results.append(("review contact fields", "OK" if all(a.get(k) for k in ("contactFirstName", "contactLastName", "contactPhone", "contactEmail")) else "MISSING",
                        "present, unchanged by this script"))
    b2 = (call("GET", f"/v1/appStoreVersions/{vid}/build") or {}).get("data")
    got_b = b2 and f"{b2['id']} version {b2['attributes'].get('version')}"
    results.append(("build attached", "OK" if b2 and bid and b2["id"] == bid else "MISMATCH", str(got_b)))
    v2 = call("GET", f"/v1/appStoreVersions/{vid}")["data"]["attributes"]
    results.append(("version", "OK" if v2.get("versionString") == ver else "MISMATCH",
                     f"{v2.get('versionString')} {v2.get('appStoreState')} copyright {v2.get('copyright')!r}"))
    for l in locs:
        loc = l["attributes"]["locale"]
        sets = call("GET", f"/v1/appStoreVersionLocalizations/{l['id']}/appScreenshotSets?limit=50")["data"]
        by_type = {s["attributes"]["screenshotDisplayType"]: s for s in sets}
        for folder, dtype in SETS.items():
            files = sorted(os.listdir(os.path.join(HERE, "screenshots", folder)))
            s = by_type.get(dtype)
            shots = call("GET", f"/v1/appScreenshotSets/{s['id']}/appScreenshots?limit=50")["data"] if s else []
            names = [x["attributes"].get("fileName") for x in shots]
            states = [(x["attributes"].get("assetDeliveryState") or {}).get("state") for x in shots]
            ok = names == files and all(st == "COMPLETE" for st in states)
            results.append((f"{loc} {dtype} screenshots", "OK" if ok else "MISMATCH", f"{len(shots)} in order={names == files} states={sorted(set(map(str, states)))}"))

    print("\n== results ==")
    for f, st, d in results:
        print(f"{st:9} {f}: {d}")
    summ = os.environ.get("GITHUB_STEP_SUMMARY")
    if summ:
        with open(summ, "a") as fh:
            fh.write("| field | status | detail |\n|---|---|---|\n" + "".join(f"| {f} | {st} | {d.replace('|', '/')} |\n" for f, st, d in results))
    print("Nothing was submitted for review.")
    if any(st not in ("OK",) for _, st, _ in results):
        sys.exit(1)


def md5(b):
    return hashlib.md5(b).hexdigest()


def screenshots(loc, loc_id, folder, dtype, s, apply):
    d = os.path.join(HERE, "screenshots", folder)
    files = sorted(os.listdir(d))
    blobs = {f: open(os.path.join(d, f), "rb").read() for f in files}
    if s:
        shots = call("GET", f"/v1/appScreenshotSets/{s['id']}/appScreenshots?limit=50")["data"]
        cur = [(x["attributes"].get("fileName"), x["attributes"].get("sourceFileChecksum"),
                (x["attributes"].get("assetDeliveryState") or {}).get("state")) for x in shots]
        print(f"{loc} {dtype}: {len(shots)} existing")
        if cur == [(f, md5(blobs[f]), "COMPLETE") for f in files]:
            print(f"{loc} {dtype}: already the same {len(files)} files, in order; nothing to do")
            return
    else:
        shots = []
    if not apply:
        return
    if not s:
        s = call("POST", "/v1/appScreenshotSets", {"data": {"type": "appScreenshotSets",
                 "attributes": {"screenshotDisplayType": dtype},
                 "relationships": {"appStoreVersionLocalization": {"data": {"type": "appStoreVersionLocalizations", "id": loc_id}}}}})["data"]
        print(f"{loc} {dtype}: created set")
    for x in shots:
        call("DELETE", f"/v1/appScreenshots/{x['id']}")
    print(f"{loc} {dtype}: removed {len(shots)} old screenshots")
    new_ids = []
    for f in files:
        data = blobs[f]
        r = call("POST", "/v1/appScreenshots", {"data": {"type": "appScreenshots",
                 "attributes": {"fileName": f, "fileSize": len(data)},
                 "relationships": {"appScreenshotSet": {"data": {"type": "appScreenshotSets", "id": s["id"]}}}}})["data"]
        for op in r["attributes"]["uploadOperations"]:
            part = data[op["offset"]:op["offset"] + op["length"]]
            req = urllib.request.Request(op["url"], data=part, method=op["method"],
                                         headers={h["name"]: h["value"] for h in op.get("requestHeaders", [])})
            with urllib.request.urlopen(req, timeout=120) as resp:
                resp.read()
        call("PATCH", f"/v1/appScreenshots/{r['id']}", {"data": {"type": "appScreenshots", "id": r["id"],
             "attributes": {"uploaded": True, "sourceFileChecksum": md5(data)}}})
        new_ids.append(r["id"])
        print(f"{loc} {dtype}: uploaded {f} ({len(data)} bytes)")
    call("PATCH", f"/v1/appScreenshotSets/{s['id']}/relationships/appScreenshots",
         {"data": [{"type": "appScreenshots", "id": i} for i in new_ids]})
    for _ in range(40):
        st = [(call("GET", f"/v1/appScreenshots/{i}")["data"]["attributes"].get("assetDeliveryState") or {}).get("state") for i in new_ids]
        if all(x in ("COMPLETE", "FAILED") for x in st):
            break
        time.sleep(10)
    print(f"{loc} {dtype}: processing states {st}")
    if "FAILED" in st:
        raise ApiError(f"{dtype}: {st.count('FAILED')} screenshot(s) failed processing")


if __name__ == "__main__":
    main()
