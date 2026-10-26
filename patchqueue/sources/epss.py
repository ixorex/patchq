"""FIRST EPSS — probability of exploitation in the next 30 days. Cached per day."""
from __future__ import annotations

from ..model import is_cve
from . import cache, net

API = "https://api.first.org/data/v1/epss"
BATCH = 100


def load(cves, offline=False):
    """Return ({CVE: {epss, percentile, date}}, Status). Unscored CVEs map to epss None."""
    status = cache.Status("EPSS")
    path = cache.cache_dir() / "epss.json"
    store = cache.read_json(path) or {}
    scores = store.get("scores") or {}
    today = cache.utc_today()
    cves = sorted({c.upper() for c in cves if is_cve(c)})
    need = [c for c in cves if str((scores.get(c) or {}).get("fetched", ""))[:10] != today]
    if need and not offline:
        try:
            now = cache.now_iso()
            for i in range(0, len(need), BATCH):
                batch = need[i:i + BATCH]
                data = net.fetch_json(f"{API}?cve={','.join(batch)}").get("data") or []
                got = {}
                for row in data:
                    try:
                        got[str(row["cve"]).upper()] = {"epss": float(row["epss"]),
                                                        "percentile": float(row.get("percentile", 0)),
                                                        "date": row.get("date")}
                    except (KeyError, TypeError, ValueError):
                        continue
                for c in batch:  # not in the response = not scored yet; remember that too
                    scores[c] = dict(got.get(c, {"epss": None, "percentile": None, "date": None}), fetched=now)
            status.live = True
            cache.write_json(path, {"scores": scores})
        except net.FetchError as e:
            status.error = str(e)
            cache.write_json(path, {"scores": scores})  # keep what the earlier batches got
    out = {}
    for c in cves:
        s = scores.get(c)
        if s:
            out[c] = {"epss": s.get("epss"), "percentile": s.get("percentile"), "date": s.get("date")}
            status.used(s.get("fetched"))
        else:
            status.unchecked += 1
    if offline and status.unchecked:
        status.note = "offline: some CVEs have no cached score"
    return out, status
