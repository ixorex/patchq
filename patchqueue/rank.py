"""Tiered ranking. Pure functions: same input -> same queue. No I/O, no black-box score.

Tier 0  Patch Today   in CISA KEV (or KEV ransomware use) AND a fix exists.
                      Order: KEV due date soonest, then EPSS desc, then CVSS desc.
Tier 1  This Week     EPSS >= 0.10, OR public PoC + internet-facing, AND a fix exists.
                      Order: EPSS desc, then CVSS desc.
Tier 2  This Sprint   EPSS >= 0.01, OR CVSS >= 7.0, with a fix.
Tier 3  Watching      everything else with a fix, no-fix-yet, deferred, not-affected.

Modifier: an item on a system marked `exposed: true` in patchqueue.yml moves up
one tier. A major-version bump only adds a warning — it never demotes anything.
"""
from __future__ import annotations

import datetime as _dt

from . import fixcmd, inventory as _inv
from .model import is_cve

TIER_NAMES = {0: "Patch Today", 1: "This Week", 2: "This Sprint / Plan", 3: "Watching"}
EPSS_TIER1 = 0.10
EPSS_TIER2 = 0.01
CVSS_TIER2 = 7.0


def _signals(item):
    e = item.get("epss")
    if e is not None:
        epss = f"EPSS {e:.3f}"
    elif is_cve(item.get("id", "")):
        epss = "EPSS not available"
    else:
        epss = "EPSS n/a (no CVE ID)"
    c = item.get("cvss")
    cvss = f"CVSS {c:.1f}" if c is not None else "CVSS pending"
    return f"{epss} · {cvss}"


def base_tier(item):
    """Tier from feed data alone (no exposure, no decisions). Returns (tier, reasons)."""
    kev = item.get("kev")
    epss = item.get("epss")
    cvss = item.get("cvss")
    if not item.get("fixed"):
        if item.get("fix_unknown"):
            r = "fix status unknown (advisory details unavailable)"
        else:
            r = "no fix yet"
        if kev:
            r += f" — CONFIRMED EXPLOITED (CISA KEV, added {kev.get('date_added')}): mitigate or isolate now"
        return 3, [r]
    if kev:
        r = f"in CISA KEV — confirmed exploited (added {kev.get('date_added')}, CISA due {kev.get('due_date')})"
        if kev.get("ransomware"):
            r += "; known ransomware campaign use"
        return 0, [r, "fix available"]
    if item.get("ransomware"):
        return 0, ["known ransomware campaign use", "fix available"]
    if epss is not None and epss >= EPSS_TIER1:
        return 1, [f"EPSS {epss:.2f} ≥ {EPSS_TIER1:.2f} (≈{epss * 100:.0f}% chance of exploitation in the next 30 days)", "fix available"]
    if epss is not None and epss >= EPSS_TIER2:
        return 2, [f"EPSS {epss:.3f} ≥ {EPSS_TIER2:.2f}", "fix available"]
    if cvss is not None and cvss >= CVSS_TIER2:
        return 2, [f"CVSS {cvss:.1f} ≥ {CVSS_TIER2:.1f}", "fix available"]
    return 3, ["fix available, low exploitation signal"]


def find_decision(decisions, item):
    if not decisions:
        return None
    ids = [str(item.get("id", "")).upper()] + [str(a).upper() for a in item.get("aliases", [])]
    for i in ids:
        d = decisions.get(i)
        if d and (not d.get("package") or d["package"].lower() == str(item.get("package", "")).lower()):
            return d
    return None


def _today(today):
    if today is None:
        return _dt.date.today()
    if isinstance(today, str):
        return _dt.date.fromisoformat(today)
    return today


def rank_item(item, decisions=None, inventory=None, today=None):
    today = _today(today)
    tier, reasons = base_tier(item)
    has_fix = bool(item.get("fixed"))
    exposed, critical, matched = _inv.lookup(inventory, item.get("match_keys", []))

    if exposed and has_fix:
        new_tier = tier
        if item.get("poc") and new_tier > 1:
            new_tier = 1
            reasons.append(f"public PoC + internet-facing ({matched[0]} is exposed)")
        bumped = max(0, tier - 1)
        if bumped < new_tier:
            new_tier = bumped
            reasons.append(f"+1 tier: {matched[0]} marked exposed in patchqueue.yml")
        tier = new_tier

    status, recheck, note = "open", None, None
    dec = find_decision(decisions, item)
    if dec:
        st = dec.get("status")
        rc = dec.get("recheck")
        rc_date = _dt.date.fromisoformat(rc) if rc else None
        if st == "patched":
            status = "patched_but_present"
            note = (f"you marked this patched on {dec.get('at', '')[:10]}, but {item.get('package')} "
                    f"{item.get('installed')} is still detected — check the upgrade landed")
        elif st == "deferred":
            if rc_date and rc_date > today:
                tier, status, recheck = 3, "deferred", rc
                note = f"deferred until {rc}: {dec.get('reason', '')}"
            else:
                status = "defer_expired"
                note = f"deferral expired {rc} (was: {dec.get('reason', '')})"
        elif st == "not_affected":
            if rc_date and rc_date <= today:
                status = "recheck_due"
                note = f"marked not-affected ({dec.get('reason', '')}); recheck date {rc} reached"
            else:
                tier, status, recheck = 3, "not_affected", rc
                note = f"not affected: {dec.get('reason', '')}"

    if tier == 3 and recheck is None and status not in ("deferred", "not_affected"):
        recheck = "next scan"

    cmd, cmd_note = fixcmd.command(item)
    out = dict(item)
    out.update({
        "tier": tier,
        "tier_name": TIER_NAMES[tier],
        "why": f"Tier {tier} ({TIER_NAMES[tier]}): " + "; ".join(reasons) + f". {_signals(item)}.",
        "fix_cmd": cmd,
        "fix_note": cmd_note,
        "breaks": fixcmd.breaks_risk(item) if has_fix else {"kind": "unknown", "label": "n/a — no fix yet"},
        "exposed": exposed,
        "critical": critical,
        "status": status,
        "status_note": note,
        "decision": dec,
        "recheck": recheck,
    })
    return out


_WATCH_GROUP = {"open": 0, "patched_but_present": 0, "defer_expired": 0, "recheck_due": 0,
                "deferred": 2, "not_affected": 3}


def sort_key(r):
    epss = r.get("epss")
    cvss = r.get("cvss")
    tier = r["tier"]
    due = "9999-12-31"
    group = 0
    if tier == 0 and r.get("kev"):
        due = r["kev"].get("due_date") or due
    if tier == 3:
        group = _WATCH_GROUP.get(r.get("status"), 0)
        if group == 0 and not r.get("kev"):
            group = 1  # exploited-no-fix first, then other open items
    return (
        tier, group, due,
        -(epss if epss is not None else -1.0),
        -(cvss if cvss is not None else -1.0),
        0 if r.get("critical") else 1,
        str(r.get("package", "")).lower(), str(r.get("id", "")),
    )


def rank(items, decisions=None, inventory=None, today=None):
    """Rank findings into one ordered queue."""
    ranked = [rank_item(i, decisions, inventory, today) for i in items]
    ranked.sort(key=sort_key)
    return ranked
