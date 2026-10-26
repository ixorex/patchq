"""Group ranked findings into one action per package@version.

Forty Django CVEs are one decision: "upgrade Django". Each group offers up to
three upgrade targets (stay on this minor line / stay on this major / newest
fix) and how many of the package's advisories each one clears.

Counting assumes a later version contains earlier fixes, which is how almost
every project ships — but it is an assumption, so the UI says "clears ~N".
"""
from __future__ import annotations

from . import fixcmd
from .model import norm_name
from .version import _release_nums, compare, normalize_ecosystem

HIDDEN = ("deferred", "not_affected")


def _key(item):
    eco = normalize_ecosystem(item.get("ecosystem", ""))
    return f"{eco}|{norm_name(item.get('package', ''), eco)}|{item.get('installed', '')}"


def _max(versions, eco):
    best = None
    for v in versions:
        if best is None or compare(v, best, eco) > 0:
            best = v
    return best


def targets_for(installed, items, eco, locations=None):
    fixes = [i["fixed"] for i in items if i.get("fixed")]
    if not fixes:
        return []
    have = _release_nums(installed) or [0, 0, 0]
    same_minor = [f for f in fixes if (_release_nums(f) or [None, None])[:2] == have[:2]]
    same_major = [f for f in fixes if (_release_nums(f) or [None])[:1] == have[:1]]
    picks = []
    for label, pool in (("same minor line", same_minor), ("same major", same_major), ("newest fix", fixes)):
        v = _max(pool, eco)
        if v and v not in [p["version"] for p in picks]:
            picks.append({"version": v, "scope": label})
    out = []
    for p in picks:
        clears = sum(1 for f in fixes if compare(p["version"], f, eco) >= 0)
        probe = dict(items[0], fixed=p["version"], locations=locations or items[0].get("locations", []))
        cmd, note = fixcmd.command(probe)
        out.append({**p, "clears": clears, "of": len(fixes), "breaks": fixcmd.breaks_risk(probe),
                    "fix_cmd": cmd, "fix_note": note})
    # drop a "safer" option that clears nothing more than doing nothing
    return [t for t in out if t["clears"] > 0]


def group(ranked):
    """ranked: output of rank.rank() (already sorted). Returns (groups, decided_items)."""
    groups, order, decided = {}, [], []
    for r in ranked:
        if r.get("status") in HIDDEN:
            decided.append(r)
            continue
        k = _key(r)
        if k not in groups:
            groups[k] = {"key": k, "package": r.get("package"), "ecosystem": normalize_ecosystem(r.get("ecosystem")),
                         "installed": r.get("installed"), "items": []}
            order.append(k)
        groups[k]["items"].append(r)
    out = []
    for k in order:
        g = groups[k]
        items = g["items"]
        best = items[0]  # ranked order: the worst item comes first
        locs, seen = [], set()
        for it in items:
            for l in it.get("locations", []):
                lk = (l.get("file"), l.get("system"), l.get("target"))
                if lk not in seen:
                    seen.add(lk)
                    locs.append(l)
        epss = [i["epss"] for i in items if i.get("epss") is not None]
        cvss = [i["cvss"] for i in items if i.get("cvss") is not None]
        by_tier = {}
        for it in items:
            by_tier[it["tier"]] = by_tier.get(it["tier"], 0) + 1
        g.update({
            "tier": best["tier"], "tier_name": best["tier_name"], "best": best,
            "count": len(items), "by_tier": by_tier,
            "kev": any(i.get("kev") for i in items),
            "max_epss": max(epss) if epss else None, "max_cvss": max(cvss) if cvss else None,
            "exposed": any(i.get("exposed") for i in items), "critical": any(i.get("critical") for i in items),
            "locations": locs,
            "no_fix": [i["id"] for i in items if not i.get("fixed")],
            "notes": sorted({i["status_note"] for i in items if i.get("status_note")}),
            "targets": targets_for(g["installed"], items, g["ecosystem"], locs),
        })
        out.append(g)
    return out, decided
