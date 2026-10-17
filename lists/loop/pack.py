# SPDX-License-Identifier: GPL-3.0-only
"""Filter packs: assemble, sign and check them.

A pack is filter-pack.json (a signed pax.filterpack.v1 document, see
guard/pax_signing.py) plus one file per changed block list, named by its
content ("pax-block-<first 16 hex of SHA-256>.txt.gz"), so a mirror that lags
behind never serves a file that disagrees with the manifest next to it.
Only block lists travel in a pack; pax-guard and the server ignore anything else."""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path

import loop_util as lu

import filter_lists as fl
import pax_signing

PACK_LISTS = ("pax-block", "pax-bypass", "pax-nrd")


def bundled_manifest() -> dict:
    return json.loads((lu.GUARD / "filters" / "filters.json").read_text())


def object_name(file: str, digest: str) -> str:
    stem = file.split(".")[0]
    return f"{stem}-{digest[:16]}{file[len(stem):]}"


def assemble(out: Path, lists: dict, version: str, meta: dict | None = None) -> dict:
    """Write the objects and payload.json (unsigned) into `out`. Returns the payload."""
    out.mkdir(parents=True, exist_ok=True)
    bundled = bundled_manifest()["lists"]
    items = {}
    for lid in PACK_LISTS:
        data = lists.get(lid)
        if data is None:
            continue
        rule = bundled[lid]
        digest = lu.sha256(data)
        obj = object_name(rule["file"], digest)
        (out / obj).write_bytes(data)
        item = {k: rule[k] for k in ("file", "kind", "format", "min_entries", "max_drop") if k in rule}
        if "restricted" in rule:
            item["restricted"] = rule["restricted"]
        if rule.get("optional"):
            item["optional"] = True
        item.update(object=obj, sha256=digest, bytes=len(data), entries=fl.count_entries(rule, data))
        items[lid] = item
    payload = {"schema": fl.PACK_SCHEMA, "version": version,
               "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
               "lists": items}
    if meta:
        payload.update(meta)
    (out / "payload.json").write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n")
    return payload


def filter_seed(update_key_text: str) -> bytes:
    """The filter-pack seed, derived from the app update key (pax_signing.derive_filter_seed)."""
    if not update_key_text.strip():
        raise SystemExit("PAX_UPDATE_SIGNING_KEY is empty: refusing to publish an unsigned pack")
    return pax_signing.derive_filter_seed(pax_signing.seed_from_text(update_key_text))


def public_key_hex(update_key_text: str) -> str:
    import ed25519
    return ed25519.public_key(filter_seed(update_key_text)).hex()


def sign(out: Path, update_key_text: str) -> dict:
    """Sign payload.json into filter-pack.json with the derived filter key, then check
    it against the public key pinned in this checkout (a wrong secret fails here,
    before publishing)."""
    seed = filter_seed(update_key_text)
    payload = json.loads((out / "payload.json").read_text())
    doc = pax_signing.sign_document(payload, seed, context=pax_signing.FILTER_CONTEXT)
    verify(doc, out)
    (out / fl.PACK_MANIFEST).write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    return doc


def verify(doc: dict, objects_dir: Path | None = None, fetch=None, base: str = "") -> dict:
    """The payload of a correctly signed pack whose files all match; else raises."""
    payload = pax_signing.verify_document(doc, pax_signing.filter_keys(), context=pax_signing.FILTER_CONTEXT)
    if payload.get("schema") != fl.PACK_SCHEMA:
        raise ValueError("not a filter pack")
    for lid, item in payload["lists"].items():
        if objects_dir is not None:
            data = (objects_dir / item["object"]).read_bytes()
        elif fetch is not None:
            data = fetch(base + item["object"])
        else:
            continue
        if lu.sha256(data) != item["sha256"]:
            raise ValueError(f"{lid}: file does not match the signed manifest")
    return payload


def fetch_published(fetch=lu.fetch, base: str = fl.PACK_BASES[0]):
    """(payload, {lid: bytes}) of the pack published now, or (None, {}) if none was
    ever published. Anything else wrong raises (the run stops: never guess)."""
    import urllib.error
    try:
        doc = json.loads(fetch(base + fl.PACK_MANIFEST))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None, {}
        raise
    payload = verify(doc)
    files = {}
    for lid, item in payload["lists"].items():
        data = fetch(base + item["object"])
        if lu.sha256(data) != item["sha256"]:
            raise ValueError(f"published {lid} does not match its manifest")
        files[lid] = data
    return payload, files


def env_key() -> str:
    """The app update key's seed (Actions secret); the filter key is derived from it."""
    return os.environ.get("PAX_UPDATE_SIGNING_KEY", "")
