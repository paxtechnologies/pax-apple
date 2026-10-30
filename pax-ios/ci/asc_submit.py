# SPDX-License-Identifier: GPL-3.0-only
"""Send one iOS version to App Review (App Store Connect API), released automatically once approved.

Checks first and writes nothing until every check passes:
  - exactly one iOS version VERSION, in an editable state, with build BUILD attached;
  - BUILD is processed (VALID), not expired, and no newer valid build of VERSION exists;
  - listing text, subtitle, privacy policy URL, review notes and contact, screenshots are present;
  - export compliance answered on the build, content rights and age rating answered on the app.
Then: releaseType AFTER_APPROVAL, an open review submission for the app (reuses one that was never
sent; cancels only one that Apple returned with unresolved issues; stops if one is waiting or in
review), adds the version as its only item, submits, and reads the state back.

Uses token() / call() from asc_metadata.py. Never prints the key, a token or review contact fields.
env: ASC_KEY_ID, ASC_ISSUER_ID, KEY, APP_ID, VERSION, BUILD.  usage (from pax-ios/): python3 ci/asc_submit.py"""
import json, os, sys, time, urllib.error, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import asc_metadata as m  # noqa: E402

API = m.API
EDITABLE = {"PREPARE_FOR_SUBMISSION", "DEVELOPER_REJECTED", "REJECTED", "METADATA_REJECTED", "INVALID_BINARY",
            "READY_FOR_REVIEW"}


class ApiError(Exception):
    pass


def call(method, path, body=None):
    """Like asc_metadata.call, but keeps Apple's associated errors (they name what is missing)."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + m.token(), "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            b = resp.read()
            return json.loads(b) if b else None
    except urllib.error.HTTPError as e:
        raw = e.read()
        lines = []
        try:
            for x in json.loads(raw).get("errors", []):
                lines.append(f"{x.get('code')}: {x.get('title')} | {x.get('detail')}")
                assoc = (x.get("meta") or {}).get("associatedErrors") or {}
                for where, errs in assoc.items():
                    for y in errs:
                        lines.append(f"  - [{where}] {y.get('code')}: {y.get('detail') or y.get('title')}")
        except Exception:
            lines.append(raw[:400].decode("utf-8", "ignore"))
        raise ApiError(f"{method} {path.split('?')[0]} -> HTTP {e.code}\n" + "\n".join(lines))


problems = []


def need(ok, what):
    print(f"{'OK     ' if ok else 'MISSING'} {what}")
    if not ok:
        problems.append(what)


def main():
    app, ver, build = os.environ["APP_ID"], os.environ["VERSION"], os.environ["BUILD"]
    print(f"app {app} version {ver} build {build} mode submit")

    # ---- version
    vs = call("GET", f"/v1/apps/{app}/appStoreVersions?filter[platform]=IOS&limit=50")["data"]
    for v in vs:
        a = v["attributes"]
        print(f"ios version {a.get('versionString')} {v['id']} appStoreState={a.get('appStoreState')} "
              f"appVersionState={a.get('appVersionState')} releaseType={a.get('releaseType')}")
    mine = [v for v in vs if v["attributes"].get("versionString") == ver]
    if len(mine) != 1:
        raise SystemExit(f"::error::expected one iOS version {ver}, found {len(mine)}")
    v = mine[0]; vid = v["id"]; va = v["attributes"]
    vstate = va.get("appStoreState"); avstate = va.get("appVersionState")
    if vstate in ("WAITING_FOR_REVIEW", "IN_REVIEW") or avstate in ("WAITING_FOR_REVIEW", "IN_REVIEW"):
        print(f"version {ver} is already {vstate}/{avstate}; nothing to do")
        return
    need(vstate in EDITABLE or avstate in EDITABLE, f"version {ver} editable (state {vstate}/{avstate})")

    # ---- builds of this version
    bl = call("GET", f"/v1/builds?filter[app]={app}&filter[preReleaseVersion.version]={ver}"
                     f"&filter[preReleaseVersion.platform]=IOS&sort=-uploadedDate&limit=20")["data"]
    for b in bl:
        a = b["attributes"]
        print(f"build {ver} ({a.get('version')}) {b['id']} uploaded {a.get('uploadedDate')} "
              f"processing={a.get('processingState')} expired={a.get('expired')} "
              f"usesNonExemptEncryption={a.get('usesNonExemptEncryption')}")
    valid = [b for b in bl if b["attributes"].get("processingState") == "VALID" and not b["attributes"].get("expired")]
    newest = max(valid, key=lambda b: int(b["attributes"]["version"])) if valid else None
    need(newest is not None and newest["attributes"]["version"] == build,
         f"build {build} is the newest valid build of {ver} (newest valid: {newest and newest['attributes']['version']})")
    attached = (call("GET", f"/v1/appStoreVersions/{vid}/build") or {}).get("data")
    if newest is not None and newest["attributes"]["version"] == build and \
            (not attached or attached["attributes"].get("version") != build) and not problems:
        print(f"attaching build {build} to {ver} (was {attached and attached['attributes'].get('version')})")
        call("PATCH", f"/v1/appStoreVersions/{vid}/relationships/build",
             {"data": {"type": "builds", "id": newest["id"]}})
        attached = (call("GET", f"/v1/appStoreVersions/{vid}/build") or {}).get("data")
    need(bool(attached) and attached["attributes"].get("version") == build,
         f"build {build} attached to {ver} (attached: {attached and attached['attributes'].get('version')})")
    if attached:
        enc = attached["attributes"].get("usesNonExemptEncryption")
        need(enc is False, f"export compliance answered on the build (usesNonExemptEncryption={enc})")
        try:
            bd = call("GET", f"/v1/builds/{attached['id']}/buildBetaDetail")["data"]["attributes"]
            print(f"testflight internalBuildState={bd.get('internalBuildState')} externalBuildState={bd.get('externalBuildState')}")
        except ApiError as e:
            print(f"(buildBetaDetail not read: {str(e).splitlines()[0]})")

    # ---- listing
    locs = call("GET", f"/v1/appStoreVersions/{vid}/appStoreVersionLocalizations?limit=50")["data"]
    need(bool(locs), "version localization present")
    for l in locs:
        a = l["attributes"]; loc = a["locale"]
        for k in ("description", "keywords"):
            need(bool((a.get(k) or "").strip()), f"{loc} {k} (len {len(a.get(k) or '')})")
        need(a.get("supportUrl") is not None and bool(a.get("supportUrl")), f"{loc} supportUrl {a.get('supportUrl')!r}")
        print(f"{loc} marketingUrl {a.get('marketingUrl')!r} promotionalText len {len(a.get('promotionalText') or '')} "
              f"whatsNew len {len(a.get('whatsNew') or '')} (not editable on a first release)")
        sets = call("GET", f"/v1/appStoreVersionLocalizations/{l['id']}/appScreenshotSets?limit=50")["data"]
        for s in sets:
            shots = call("GET", f"/v1/appScreenshotSets/{s['id']}/appScreenshots?limit=50")["data"]
            states = sorted({str((x["attributes"].get("assetDeliveryState") or {}).get("state")) for x in shots})
            dtype = s["attributes"]["screenshotDisplayType"]
            if dtype in ("APP_IPHONE_67", "APP_IPAD_PRO_3GEN_129"):
                need(len(shots) > 0 and states == ["COMPLETE"], f"{loc} {dtype}: {len(shots)} screenshots {states}")
            else:
                print(f"{loc} other set {dtype}: {len(shots)} {states}")
        types = {s["attributes"]["screenshotDisplayType"] for s in sets}
        need("APP_IPHONE_67" in types, f"{loc} iPhone 6.9\" screenshots set")
        need("APP_IPAD_PRO_3GEN_129" in types, f"{loc} iPad 13\" screenshots set")

    infos = call("GET", f"/v1/apps/{app}/appInfos")["data"]
    live = {"READY_FOR_DISTRIBUTION", "READY_FOR_SALE", "REPLACED_WITH_NEW_INFO"}
    info = ([i for i in infos if (i["attributes"].get("state") or i["attributes"].get("appStoreState")) not in live] or infos)[0]
    for l in call("GET", f"/v1/appInfos/{info['id']}/appInfoLocalizations?limit=50")["data"]:
        a = l["attributes"]
        need(bool(a.get("name")), f"{a['locale']} name {a.get('name')!r}")
        need(bool(a.get("subtitle")), f"{a['locale']} subtitle {a.get('subtitle')!r}")
        need(bool(a.get("privacyPolicyUrl")), f"{a['locale']} privacyPolicyUrl {a.get('privacyPolicyUrl')!r}")
    try:
        cat = call("GET", f"/v1/appInfos/{info['id']}/primaryCategory")
        cid = (cat or {}).get("data") and cat["data"]["id"]
        need(bool(cid), f"primary category {cid}")
    except ApiError as e:
        need(False, f"primary category ({str(e).splitlines()[0]})")
    try:
        ar = call("GET", f"/v1/appInfos/{info['id']}/ageRatingDeclaration")["data"]["attributes"]
        unanswered = sorted(k for k, x in ar.items() if x is None)
        need(bool(ar), "age rating declaration present")
        print(f"age rating: {len(ar) - len(unanswered)} answered; unanswered/optional: {unanswered}")
    except ApiError as e:
        need(False, f"age rating declaration ({str(e).splitlines()[0]})")

    appa = call("GET", f"/v1/apps/{app}")["data"]["attributes"]
    print(f"app {appa.get('name')!r} bundle {appa.get('bundleId')} primaryLocale {appa.get('primaryLocale')}")
    need(appa.get("contentRightsDeclaration") is not None, f"content rights answered ({appa.get('contentRightsDeclaration')})")

    rd = (call("GET", f"/v1/appStoreVersions/{vid}/appStoreReviewDetail") or {}).get("data")
    if rd:
        a = rd["attributes"]
        need(all(a.get(k) for k in ("contactFirstName", "contactLastName", "contactPhone", "contactEmail")),
             "review contact fields present")
        name = " ".join(x for x in (a.get("contactFirstName"), a.get("contactLastName")) if x)
        ph = (a.get("contactPhone") or "").replace(" ", "")
        if ph.startswith("+44") and len(ph) == 13:
            ph = f"+44 {ph[3:7]} {ph[7:]}"
        if name and ph:
            want = m.text("review_notes.txt").replace("{contact_name}", name).replace("{contact_phone}", ph)
            if len(want) > 4000:
                need(False, f"review notes from the repo fit 4000 chars (len {len(want)})")
            elif want != (a.get("notes") or ""):
                call("PATCH", f"/v1/appStoreReviewDetails/{rd['id']}", {"data": {"type": "appStoreReviewDetails",
                     "id": rd["id"], "attributes": {"notes": want}}})
                a = call("GET", f"/v1/appStoreReviewDetails/{rd['id']}")["data"]["attributes"]
                need(a.get("notes") == want, f"review notes updated from the repo (len {len(want)})")
            else:
                print(f"review notes already match the repo (len {len(want)})")
        need(len(a.get("notes") or "") > 0, f"review notes present (len {len(a.get('notes') or '')})")
        need(a.get("demoAccountRequired") is False, f"demoAccountRequired={a.get('demoAccountRequired')}")
    else:
        need(False, "review detail present")

    if problems:
        print("\n== not submitted; missing ==\n" + "\n".join(problems))
        raise SystemExit(1)

    # ---- existing review submissions
    subs = call("GET", f"/v1/reviewSubmissions?filter[app]={app}&filter[platform]=IOS&limit=50")
    open_sub = None
    returned = None
    for s in subs["data"]:
        a = s["attributes"]
        print(f"review submission {s['id']} state={a.get('state')} submitted={a.get('submittedDate')}")
    for s in subs["data"]:
        st = s["attributes"].get("state")
        if st in ("WAITING_FOR_REVIEW", "IN_REVIEW", "CANCELING", "COMPLETING"):
            raise SystemExit(f"::error::review submission {s['id']} is {st}; not touching it")
        if st == "UNRESOLVED_ISSUES" and returned is None:
            returned = s  # resubmitted below, after the release type is set
        elif st == "UNRESOLVED_ISSUES":
            print(f"cancelling review submission {s['id']} (returned with unresolved issues, not in review)")
            call("PATCH", f"/v1/reviewSubmissions/{s['id']}",
                 {"data": {"type": "reviewSubmissions", "id": s["id"], "attributes": {"canceled": True}}})
            for _ in range(30):
                st2 = call("GET", f"/v1/reviewSubmissions/{s['id']}")["data"]["attributes"].get("state")
                if st2 not in ("CANCELING", "UNRESOLVED_ISSUES"):
                    break
                time.sleep(10)
            print(f"  now {st2}")
        elif st == "READY_FOR_REVIEW":
            open_sub = s  # never sent: reuse it

    # ---- release type
    call("PATCH", f"/v1/appStoreVersions/{vid}", {"data": {"type": "appStoreVersions", "id": vid,
         "attributes": {"releaseType": "AFTER_APPROVAL", "earliestReleaseDate": None}}})
    rt = call("GET", f"/v1/appStoreVersions/{vid}")["data"]["attributes"].get("releaseType")
    need(rt == "AFTER_APPROVAL", f"releaseType {rt}")
    if problems:
        raise SystemExit(1)

    # ---- submission
    if returned is not None:
        sid = returned["id"]
        items = call("GET", f"/v1/reviewSubmissions/{sid}/items?limit=50&include=appStoreVersion")["data"]
        ours = [it for it in items if (((it.get("relationships") or {}).get("appStoreVersion") or {}).get("data") or {}).get("id") == vid]
        print(f"review submission {sid} was returned (UNRESOLVED_ISSUES); items: "
              + ", ".join(f"{it['id'][:12]}… {it['attributes'].get('state')}" for it in items))
        try:
            if not ours:
                raise ApiError("version is not an item of the returned submission")
            call("PATCH", f"/v1/reviewSubmissions/{sid}",
                 {"data": {"type": "reviewSubmissions", "id": sid, "attributes": {"submitted": True}}})
            print(f"resubmitted review submission {sid}")
            return read_back(sid, vid, ver)
        except ApiError as e:
            print(f"resubmitting {sid} was refused, so cancelling it and making a new one:\n{e}")
            call("PATCH", f"/v1/reviewSubmissions/{sid}",
                 {"data": {"type": "reviewSubmissions", "id": sid, "attributes": {"canceled": True}}})
            for _ in range(30):
                st2 = call("GET", f"/v1/reviewSubmissions/{sid}")["data"]["attributes"].get("state")
                if st2 not in ("CANCELING", "UNRESOLVED_ISSUES"):
                    break
                time.sleep(10)
            print(f"  now {st2}")
    if open_sub:
        sid = open_sub["id"]
        print(f"reusing review submission {sid}")
    else:
        sid = call("POST", "/v1/reviewSubmissions", {"data": {"type": "reviewSubmissions", "attributes": {"platform": "IOS"},
                   "relationships": {"app": {"data": {"type": "apps", "id": app}}}}})["data"]["id"]
        print(f"created review submission {sid}")
    items = call("GET", f"/v1/reviewSubmissions/{sid}/items?limit=50&include=appStoreVersion")["data"]
    have = False
    for it in items:
        rel = ((it.get("relationships") or {}).get("appStoreVersion") or {}).get("data")
        if rel and rel.get("id") == vid:
            have = True
        else:
            print(f"removing stale item {it['id']} from the unsent submission")
            call("DELETE", f"/v1/reviewSubmissionItems/{it['id']}")
    if not have:
        call("POST", "/v1/reviewSubmissionItems", {"data": {"type": "reviewSubmissionItems", "relationships": {
             "reviewSubmission": {"data": {"type": "reviewSubmissions", "id": sid}},
             "appStoreVersion": {"data": {"type": "appStoreVersions", "id": vid}}}}})
        print(f"added version {ver} to submission {sid}")
    call("PATCH", f"/v1/reviewSubmissions/{sid}",
         {"data": {"type": "reviewSubmissions", "id": sid, "attributes": {"submitted": True}}})
    print("submitted")
    read_back(sid, vid, ver)


def read_back(sid, vid, ver):
    for _ in range(12):
        s = call("GET", f"/v1/reviewSubmissions/{sid}")["data"]["attributes"]
        v2 = call("GET", f"/v1/appStoreVersions/{vid}")["data"]["attributes"]
        if s.get("state") != "READY_FOR_REVIEW":
            break
        time.sleep(10)
    print("\n== read back ==")
    print(f"review submission {sid} state={s.get('state')} submittedDate={s.get('submittedDate')}")
    print(f"version {v2.get('versionString')} appStoreState={v2.get('appStoreState')} "
          f"appVersionState={v2.get('appVersionState')} releaseType={v2.get('releaseType')}")
    b2 = (call("GET", f"/v1/appStoreVersions/{vid}/build") or {}).get("data")
    print(f"build attached {b2 and b2['attributes'].get('version')}")
    summ = os.environ.get("GITHUB_STEP_SUMMARY")
    if summ:
        with open(summ, "a") as fh:
            fh.write(f"Submitted {ver} ({b2 and b2['attributes'].get('version')}): submission {sid} {s.get('state')} "
                     f"at {s.get('submittedDate')}; version {v2.get('appStoreState')}; release {v2.get('releaseType')}\n")
    if s.get("state") not in ("WAITING_FOR_REVIEW", "IN_REVIEW"):
        raise SystemExit(f"::error::submission state is {s.get('state')}")


if __name__ == "__main__":
    try:
        main()
    except ApiError as e:
        print("::error::App Store Connect refused a call")
        print(str(e))
        sys.exit(1)
