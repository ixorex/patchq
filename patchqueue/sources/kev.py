"""CISA Known Exploited Vulnerabilities — downloaded once per day, never per CVE."""
from __future__ import annotations

from . import cache, net

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _index(raw):
    out = {}
    for v in raw.get("vulnerabilities") or []:
        cve = str(v.get("cveID", "")).upper()
        if cve:
            out[cve] = {
                "date_added": v.get("dateAdded"),
                "due_date": v.get("dueDate"),
                "ransomware": str(v.get("knownRansomwareCampaignUse", "")).strip().lower() == "known",
                "action": v.get("requiredAction"),
                "name": v.get("vulnerabilityName"),
            }
    return out


def load(offline=False):
    """Return ({CVE: entry}, Status)."""
    status = cache.Status("KEV")
    path = cache.cache_dir() / "kev.json"
    c = cache.read_json(path)
    fresh = bool(c) and str(c.get("fetched", ""))[:10] == cache.utc_today()
    if not fresh and not offline:
        try:
            raw = net.fetch_json(URL, timeout=60)
            if not isinstance(raw, dict) or not isinstance(raw.get("vulnerabilities"), list):
                raise net.FetchError("unexpected KEV format")
            c = {"fetched": cache.now_iso(), "catalog_version": raw.get("catalogVersion"), "data": raw}
            cache.write_json(path, c)
            status.live = True
        except net.FetchError as e:
            status.error = str(e)
    if not c:
        status.error = status.error or ("offline and no cached KEV" if offline else "no KEV data")
        status.note = "Tier 0 could not be computed for this run"
        return {}, status
    status.used(c.get("fetched"))
    status.note = f"catalog {c.get('catalog_version')}" if c.get("catalog_version") else None
    return _index(c.get("data") or {}), status
