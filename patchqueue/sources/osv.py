"""OSV.dev — which vulnerabilities affect package@version, and the fixed version.

Only package names, versions and ecosystems are sent (public data). Uses
/v1/querybatch to find vuln IDs, then /v1/vulns/{id} for details. Cached 24h.
"""
from __future__ import annotations

import hashlib
import re
from concurrent.futures import ThreadPoolExecutor
from functools import cmp_to_key

from .. import model
from ..version import compare, normalize_ecosystem
from . import cache, cvss as _cvss, net

QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
QUERY_URL = "https://api.osv.dev/v1/query"
VULN_URL = "https://api.osv.dev/v1/vulns/{}"
TTL = 24 * 3600
SUPPORTED = ("npm", "PyPI")  # ecosystems PatchQ v1 parses itself
BATCH = 1000
WORKERS = 8


def key(pkg):
    eco = normalize_ecosystem(pkg["ecosystem"])
    return (eco, model.norm_name(pkg["name"], eco), str(pkg["version"]))


def pkg_cache_path(eco, name, version):
    h = hashlib.sha256(f"{eco}|{model.norm_name(name, eco)}|{version}".encode()).hexdigest()[:40]
    return cache.cache_dir("osv", "pkg") / f"{h}.json"


def vuln_cache_path(vid):
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(vid))[:150]  # IDs come from the network
    return cache.cache_dir("osv", "vuln") / f"{safe}.json"


def _query_pages(name, eco, version, token):
    ids = []
    while token:
        data = net.fetch_json(QUERY_URL, {"package": {"name": name, "ecosystem": eco},
                                          "version": version, "page_token": token})
        ids += [v["id"] for v in data.get("vulns") or [] if v.get("id")]
        token = data.get("next_page_token")
    return ids


def lookup(packages, offline=False):
    """Return ({key: [osv records]}, Status)."""
    status = cache.Status("OSV")
    wanted = {}
    for p in packages:
        if normalize_ecosystem(p["ecosystem"]) in SUPPORTED:
            wanted.setdefault(key(p), p["name"])

    ids_for, need = {}, []
    for k, name in wanted.items():
        c = cache.read_json(pkg_cache_path(*k))
        if c and (offline or cache.age_seconds(c.get("fetched")) < TTL):
            ids_for[k] = c.get("ids", [])
            status.used(c.get("fetched"))
        else:
            need.append((k, name, c))

    if need and offline:
        status.unchecked += len(need)
        status.note = "offline: packages with no cached result were not checked"
    elif need:
        for start in range(0, len(need), BATCH):
            chunk = need[start:start + BATCH]
            payload = {"queries": [{"package": {"name": name, "ecosystem": k[0]}, "version": k[2]}
                                   for k, name, _ in chunk]}
            try:
                results = net.fetch_json(QUERYBATCH_URL, payload).get("results") or []
                if len(results) != len(chunk):
                    raise net.FetchError("querybatch returned a different number of results")
                now = cache.now_iso()
                for (k, name, _), res in zip(chunk, results):
                    ids = [v["id"] for v in (res or {}).get("vulns") or [] if v.get("id")]
                    if (res or {}).get("next_page_token"):
                        ids += _query_pages(name, k[0], k[2], res["next_page_token"])
                    cache.write_json(pkg_cache_path(*k), {"fetched": now, "ids": sorted(set(ids))})
                    ids_for[k] = sorted(set(ids))
                status.live = True
                status.used(now)
            except net.FetchError as e:
                status.error = str(e)
                for k, _name, c in chunk:
                    if c:
                        ids_for[k] = c.get("ids", [])
                        status.used(c.get("fetched"))
                    else:
                        status.unchecked += 1

    records = _load_records({i for ids in ids_for.values() for i in ids}, offline, status)
    return {k: [records[i] for i in ids] for k, ids in ids_for.items()}, status


def _load_records(all_ids, offline, status):
    records, fetch_ids = {}, []
    for vid in all_ids:
        c = cache.read_json(vuln_cache_path(vid))
        if c and (offline or cache.age_seconds(c.get("fetched")) < TTL):
            records[vid] = c["record"]
        else:
            fetch_ids.append((vid, c))
    if fetch_ids and not offline:
        def get(vid):
            return vid, net.fetch_json(VULN_URL.format(vid))

        errors = []
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            futures = {vid: ex.submit(get, vid) for vid, _ in fetch_ids}
        for vid, c in fetch_ids:
            try:
                _, rec = futures[vid].result()
                cache.write_json(vuln_cache_path(vid), {"fetched": cache.now_iso(), "record": rec})
                records[vid] = rec
                status.live = True
            except net.FetchError as e:
                errors.append(str(e))
                records[vid] = c["record"] if c else {"id": vid, "_missing": True}
        if errors:
            status.error = status.error or f"{len(errors)} advisory downloads failed ({errors[0]})"
    else:
        for vid, c in fetch_ids:
            records[vid] = c["record"] if c else {"id": vid, "_missing": True}
    return records


# ------------------------------------------------------------ record -> finding
def _event(e):
    for k in ("introduced", "fixed", "last_affected"):
        if k in e:
            return k, str(e[k])
    return None


def eval_range(events, version, eco):
    """Return (affected, fixed_version_for_this_interval) per the OSV range rules."""
    evs = [x for x in (_event(e) for e in events) if x]

    def is_zero(x):
        return x[0] == "introduced" and x[1] == "0"

    def cmp(a, b):
        if is_zero(a) or is_zero(b):
            return (0 if is_zero(b) else -1) if is_zero(a) else 1
        c = compare(a[1], b[1], eco)
        if c == 0:  # at the same version: introduced applies before fixed
            order = {"introduced": 0, "last_affected": 1, "fixed": 2}
            return order[a[0]] - order[b[0]]
        return c

    evs.sort(key=cmp_to_key(cmp))
    affected, fix = False, None
    for kind, ver in evs:
        if kind == "introduced":
            if ver == "0" or compare(version, ver, eco) >= 0:
                affected, fix = True, None
            else:
                break
        elif kind == "fixed":
            if compare(version, ver, eco) >= 0:
                affected = False
            else:
                if affected:
                    fix = ver
                break
        elif kind == "last_affected":
            if compare(version, ver, eco) > 0:
                affected = False
            else:
                break
    return affected, (fix if affected else None)


def _entries(record, eco, name):
    n = model.norm_name(name, eco)
    for aff in record.get("affected") or []:
        pkg = aff.get("package") or {}
        if normalize_ecosystem(pkg.get("ecosystem", "")) == eco and model.norm_name(pkg.get("name", ""), eco) == n:
            yield aff


def fix_for(record, ecosystem, name, installed):
    """Return (fixed_version or None, in_range: bool)."""
    eco = normalize_ecosystem(ecosystem)
    containing, all_fixes = [], []
    for aff in _entries(record, eco, name):
        for rng in aff.get("ranges") or []:
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            events = rng.get("events") or []
            all_fixes += [str(e["fixed"]) for e in events if "fixed" in e]
            affected, fix = eval_range(events, installed, eco)
            if affected:
                containing.append(fix)
    if containing:
        fixes = [f for f in containing if f]
        if not fixes:
            return None, True
        best = fixes[0]
        for f in fixes[1:]:  # overlapping ranges: the highest fix clears all of them
            if compare(f, best, eco) > 0:
                best = f
        return best, True
    # OSV matched it but our range walk didn't place it: smallest fix above installed.
    higher = [f for f in all_fixes if compare(f, installed, eco) > 0]
    if higher:
        best = higher[0]
        for f in higher[1:]:
            if compare(f, best, eco) < 0:
                best = f
        return best, False
    return None, False


def cvss_from_record(record):
    best = None
    for sev in record.get("severity") or []:
        if str(sev.get("type", "")).startswith("CVSS_V3"):
            s = _cvss.base_score_v3(sev.get("score", ""))
            if s is not None and (best is None or s > best):
                best = s
    return (best, "OSV (CVSS v3 vector)") if best is not None else (None, None)


def _summary(record):
    s = record.get("summary") or ""
    if not s:
        details = (record.get("details") or "").strip().splitlines()
        s = details[0] if details else ""
    return s[:300]


def finding_from_osv(record, pkg, origin="osv", location=None):
    eco = normalize_ecosystem(pkg["ecosystem"])
    rid = str(record.get("id", ""))
    pid, aliases = model.primary_id(rid, record.get("aliases") or [])
    missing = bool(record.get("_missing"))
    fixed = None if missing else fix_for(record, eco, pkg["name"], str(pkg["version"]))[0]
    score, src = (None, None) if missing else cvss_from_record(record)
    poc = any(str(r.get("type", "")).upper() == "EVIDENCE" for r in record.get("references") or [])
    loc = location or {k: pkg.get(k) for k in ("file", "system", "dir", "direct", "dev", "kind", "approx")}
    return model.new_finding(
        id=pid, aliases=aliases, ecosystem=eco, package=pkg["name"], installed=str(pkg["version"]),
        fixed=fixed, fix_unknown=missing, summary=_summary(record), url=f"https://osv.dev/vulnerability/{rid}",
        cvss=score, cvss_source=src, poc=poc, origin=[origin], locations=[loc],
        match_keys=list(pkg.get("keys") or []),
    )
