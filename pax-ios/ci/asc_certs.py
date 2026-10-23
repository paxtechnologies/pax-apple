# SPDX-License-Identifier: GPL-3.0-only
"""CI development certificates for ios-upload (App Store Connect API, ASC key from the env).

Automatic signing on a fresh runner makes an "Apple Development: Created via API" certificate whose
private key leaves with the runner; the next run's archive then fails. Three subcommands:

  check     read only: stop early if a CI-made ("Created via API") development certificate is
            already there (an earlier run didn't clean up). Never revokes.
  snapshot  record the IDs of every certificate that exists now (before the archive) in FILE.
  cleanup   after the archive: revoke ONLY development certificates that (1) are named
            "Created via API", (2) were not in the snapshot, i.e. were created during this run
            (the workflow's concurrency group keeps runs one at a time), and (3) have a serial number
            matching an "Apple Development: Created via API" certificate in THIS runner's keychain.
            Distribution certificates and any person's own certificate are never touched.

env: ASC_KEY_ID, ASC_ISSUER_ID, KEY (path to the .p8). usage: asc_certs.py check|snapshot FILE|cleanup FILE
Prints certificate names, types, IDs and expiry dates only; never the key or a token."""
import base64, json, os, re, subprocess, sys, time, urllib.request

API = "https://api.appstoreconnect.apple.com"
CI_NAME = "Created via API"
DEV_TYPES = ("DEVELOPMENT", "IOS_DEVELOPMENT")


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def token():
    kid, iss, key = os.environ["ASC_KEY_ID"], os.environ["ASC_ISSUER_ID"], os.environ["KEY"]
    now = int(time.time())
    msg = b64(json.dumps({"alg": "ES256", "kid": kid, "typ": "JWT"}).encode()) + "." + \
        b64(json.dumps({"iss": iss, "iat": now, "exp": now + 900, "aud": "appstoreconnect-v1"}).encode())
    der = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key], input=msg.encode(),
                         capture_output=True, check=True).stdout
    # DER ECDSA signature -> raw r||s (32 bytes each) for JWS.
    i = 2 if der[1] < 0x80 else 3
    rl = der[i + 1]; r = der[i + 2:i + 2 + rl]; j = i + 2 + rl; sl = der[j + 1]; s_ = der[j + 2:j + 2 + sl]
    sig = r.lstrip(b"\0").rjust(32, b"\0") + s_.lstrip(b"\0").rjust(32, b"\0")
    return msg + "." + b64(sig)


def call(method, path):
    req = urllib.request.Request(API + path, method=method, headers={"Authorization": "Bearer " + token()})
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read()
        return json.loads(body) if body else None


def certs():
    out = call("GET", "/v1/certificates?limit=200&fields[certificates]=name,certificateType,displayName,"
                      "expirationDate,serialNumber")["data"]
    for c in out:
        a = c["attributes"]
        print(f"  {c['id']} {a.get('certificateType')}: {a.get('name')} (expires {a.get('expirationDate')})")
    return out


def is_ci_dev(c):
    a = c["attributes"]
    return a.get("certificateType") in DEV_TYPES and CI_NAME in (a.get("name") or "")


def norm_serial(s):
    return (s or "").upper().replace(":", "").lstrip("0")


def local_ci_serials():
    """Serials of 'Apple Development: Created via API' certificates in this runner's keychains."""
    r = subprocess.run(["security", "find-certificate", "-a", "-c", CI_NAME, "-p"], capture_output=True, text=True)
    serials = set()
    for pem in re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", r.stdout, re.S):
        o = subprocess.run(["openssl", "x509", "-noout", "-serial", "-subject"], input=pem,
                           capture_output=True, text=True).stdout
        m = re.search(r"serial=([0-9A-Fa-f]+)", o)
        if m and CI_NAME in o:
            serials.add(norm_serial(m.group(1)))
    return serials


def main():
    cmd = sys.argv[1]
    if cmd == "check":
        print("Certificates on the team:")
        stale = [c for c in certs() if is_ci_dev(c)]
        if stale:
            print("::error::An 'Apple Development: Created via API' certificate from an earlier CI run exists "
                  f"({', '.join(c['id'] for c in stale)}); its private key left with that runner, so automatic "
                  "signing can't archive. Revoke only that one in developer.apple.com > Certificates, then push "
                  "the build number again. This step never revokes.")
            sys.exit(1)
    elif cmd == "snapshot":
        print("Certificates before the archive:")
        ids = [c["id"] for c in certs()]
        json.dump(ids, open(sys.argv[2], "w"))
        print(f"snapshot: {len(ids)} certificates")
    elif cmd == "cleanup":
        path = sys.argv[2]
        if not os.path.exists(path):
            print("No snapshot (the run stopped before the archive): nothing to clean up.")
            return
        before = set(json.load(open(path)))
        print("Certificates after the archive:")
        new = [c for c in certs() if is_ci_dev(c) and c["id"] not in before]
        if not new:
            print("No new CI development certificate from this run.")
            return
        local = local_ci_serials()
        print(f"this runner's keychain holds {len(local)} CI development certificate(s)")
        mine = [c for c in new if norm_serial(c["attributes"].get("serialNumber")) in local]
        for c in new:
            if c not in mine:
                print(f"::warning::{c['id']} is new but its serial isn't in this runner's keychain: left alone. "
                      "The next run's check will stop on it.")
        for c in mine:
            call("DELETE", f"/v1/certificates/{c['id']}")
            a = c["attributes"]
            print(f"revoked this run's CI development certificate {c['id']} ({a.get('name')}, "
                  f"expires {a.get('expirationDate')})")
        if len(mine) != len(new):
            sys.exit(1)
    else:
        sys.exit(f"unknown command {cmd}")


if __name__ == "__main__":
    main()
