"""NVD — CVSS + exploit-reference tags, best effort.

NVD enrichment is incomplete and the API is rate-limited (5 requests / 30 s
without a key). PatchQ only asks NVD about CVEs that still lack a CVSS score or
sit on an exposed system, caps lookups per run, and caches answers for 7 days.
Set NVD_API_KEY (free) for faster lookups. A missing score stays "pending".
"""
from __future__ import annotations

import os
import time

from ..model import is_cve
from . import cache, net

API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
TTL = 7 * 24 * 3600
DELAY_NO_KEY = 6.5
DELAY_KEY = 0.7


def _parse(data):
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return {"cvss": None, "version": None, "exploit_ref": False, "found": False}
    cve = vulns[0].get("cve") or {}
    metrics = cve.get("metrics") or {}
    score = version = None
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        rows = metrics.get(k) or []
        rows = sorted(rows, key=lambda r: 0 if r.get("type") == "Primary" else 1)
        for r in rows:
            s = (r.get("cvssData") or {}).get("baseScore")
            if s is not None:
                score, version = float(s), (r.get("cvssData") or {}).get("version")
                break
        if score is not None:
            break
    exploit = any("Exploit" in (ref.get("tags") or []) for ref in cve.get("references") or [])
    return {"cvss": score, "version": version, "exploit_ref": exploit, "found": True}


def load(cves, offline=False, max_lookups=None):
    status = cache.Status("NVD")
    path = cache.cache_dir() / "nvd.json"
    store = (cache.read_json(path) or {}).get("cves") or {}
    key = os.environ.get("NVD_API_KEY", "").strip()
    if max_lookups is None:
        max_lookups = 50 if key else 10
    delay = DELAY_KEY if key else DELAY_NO_KEY
    cves = [c.upper() for c in dict.fromkeys(cves) if is_cve(c)]
    need = [c for c in cves if cache.age_seconds((store.get(c) or {}).get("fetched")) >= TTL]
    skipped = 0
    if need and not offline:
        todo, skipped = need[:max_lookups], max(0, len(need) - max_lookups)
        headers = {"apiKey": key} if key else None
        for n, c in enumerate(todo):
            if n:
                time.sleep(delay)
            try:
                store[c] = dict(_parse(net.fetch_json(API + c, headers=headers, timeout=30)), fetched=cache.now_iso())
                status.live = True
            except net.FetchError as e:
                status.error = str(e)
                break  # rate-limited or down: stop hammering, use cache
        cache.write_json(path, {"cves": store})
    out = {}
    for c in cves:
        if c in store:
            out[c] = store[c]
            status.used(store[c].get("fetched"))
        else:
            status.unchecked += 1
    if skipped:
        status.note = f"{skipped} CVEs not looked up this run (rate limit cap; set NVD_API_KEY or --nvd-max)"
    elif offline and status.unchecked:
        status.note = "offline"
    return out, status
