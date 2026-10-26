"""Terminal rendering of a ranked queue."""
from __future__ import annotations

import os
import sys

from . import DISCLAIMER, __version__

_C = {"red": "31", "yellow": "33", "blue": "34", "dim": "2", "bold": "1", "green": "32", "magenta": "35"}


def use_color(stream=None) -> bool:
    stream = stream or sys.stdout
    return hasattr(stream, "isatty") and stream.isatty() and "NO_COLOR" not in os.environ \
        and os.environ.get("TERM") != "dumb"


class Painter:
    def __init__(self, on: bool):
        self.on = on

    def __call__(self, text, *styles):
        if not self.on or not styles:
            return text
        return "\033[" + ";".join(_C[s] for s in styles) + "m" + str(text) + "\033[0m"


TIER_STYLE = {0: ("red", "bold"), 1: ("yellow", "bold"), 2: ("blue", "bold"), 3: ("dim",)}
BREAK_STYLE = {"major": ("red",), "minor": ("yellow",), "patch": ("green",), "unknown": ("dim",)}


def _clean(s) -> str:
    """Strip control characters from feed / lockfile text before it hits the terminal."""
    return "".join(ch for ch in str(s) if ch == "\n" or (ch >= " " and ch != "\x7f" and not "\x80" <= ch <= "\x9f"))


def source_line(sources: dict) -> list:
    lines = []
    parts = []
    for name in ("OSV", "KEV", "EPSS", "NVD"):
        s = sources.get(name)
        if not s:
            continue
        as_of = (s.get("as_of") or "")[:16].replace("T", " ")
        if s.get("error"):
            parts.append(f"{name} ⚠ {('cache ' + as_of) if as_of else 'NO DATA'}")
            lines.append(f"⚠ {name}: {_clean(s['error'])} — {'using cached data as of ' + as_of if as_of else 'no cached data'}"
                         + (f"; {s['unchecked']} not checked" if s.get("unchecked") else ""))
        elif as_of:
            parts.append(f"{name} {as_of}{'' if s.get('live') else ' (cache)'}")
        else:
            parts.append(f"{name} —")
        if s.get("note"):
            lines.append(f"  {name}: {_clean(s['note'])}")
    return ["Data as of (UTC): " + " · ".join(parts)] + lines


def _where(item) -> str:
    out = []
    for loc in item.get("locations", [])[:3]:
        bits = [loc.get("system") or "?"]
        if loc.get("file"):
            bits.append(f"({loc['file']}" + (f" → {loc['target']}" if loc.get("target") else "") + ")")
        tags = []
        if loc.get("direct") is False:
            tags.append("transitive")
        if loc.get("dev"):
            tags.append("dev")
        if loc.get("approx"):
            tags.append("approx. version")
        if tags:
            bits.append("[" + ", ".join(tags) + "]")
        out.append(" ".join(bits))
    more = len(item.get("locations", [])) - 3
    s = "; ".join(out) + (f" (+{more} more)" if more > 0 else "")
    flags = [f for f, on in (("exposed", item.get("exposed")), ("critical", item.get("critical"))) if on]
    return _clean(s) + (f"  [{', '.join(flags)}]" if flags else "")


def _versions(item) -> str:
    fixed = item.get("fixed") or ("fix unknown" if item.get("fix_unknown") else "no fix yet")
    return f"{item.get('package')} {item.get('installed')} → {fixed}"


def render_item(n, item, p) -> list:
    br = item.get("breaks", {})
    head = (f"{n:>3}  {p(_clean(item['id']), 'bold')}  {_clean(_versions(item))}   "
            f"breaks risk: {p(br.get('label', 'n/a'), *BREAK_STYLE.get(br.get('kind'), ()))}")
    lines = [head, f"     where  {_where(item)}", f"     why    {_clean(item['why'])}"]
    if item.get("status_note"):
        lines.append(f"     note   {p(_clean(item['status_note']), 'magenta')}")
    for k, cmd in enumerate((item.get("fix_cmd") or "").splitlines()):
        lines.append(f"     {'fix ' if k == 0 else '    '}   {p(cmd, 'green')}")
    if item.get("fix_note"):
        lines.append(f"            {_clean(item['fix_note'])}")
    if item.get("summary"):
        lines.append(f"     what   {_clean(item['summary'])[:160]}  {p(_clean(item.get('url', '')), 'dim')}")
    return lines


def _watch_line(n, item, p) -> str:
    status = item.get("status")
    if status == "deferred":
        tail = f"deferred until {item.get('recheck')}"
    elif status == "not_affected":
        tail = "not affected" + (f" · recheck {item['recheck']}" if item.get("recheck") else "")
    else:
        tail = f"recheck: {item.get('recheck') or 'next scan'}"
    reason = ""
    if item.get("decision") and item["decision"].get("reason"):
        reason = f' — "{_clean(item["decision"]["reason"])}"'
    elif not item.get("fixed"):
        reason = " — " + _clean(item["why"].split(": ", 1)[-1].split(".")[0])
    return f"{n:>3}  {_clean(item['id'])}  {_clean(_versions(item))}  ·  {tail}{reason}"


def render_queue(ranked, scans, sources, warnings=(), color=False, show_all=False, title="queue") -> str:
    p = Painter(color)
    out = []
    labels = ", ".join(f"{os.path.basename(s.get('label', '').rstrip('/')) or s.get('label')} "
                       f"(scanned {s.get('scanned_at', '')[:16].replace('T', ' ')})" for s in scans)
    out.append(p(f"PatchQ {__version__}", "bold") + f" — {title} for: {labels or 'nothing scanned yet'}")
    out += source_line(sources)
    if warnings:
        out.append("")
        out.append(p(f"Heads-up ({len(warnings)}):", "yellow"))
        for w in warnings:
            out.append(f"  • {_clean(w)}")

    by_tier = {t: [r for r in ranked if r["tier"] == t] for t in range(4)}
    names = {0: "PATCH TODAY", 1: "THIS WEEK", 2: "THIS SPRINT / PLAN", 3: "WATCHING"}
    n = 0
    for t in range(4):
        rows = by_tier[t]
        out.append("")
        if t == 3:
            collapsed = "" if show_all else "  (collapsed — `patchq queue --all` for full detail)"
            out.append(p(f"{names[t]} · {len(rows)}", *TIER_STYLE[t]) + collapsed)
        else:
            out.append(p(f"{names[t]} · {len(rows)}", *TIER_STYLE[t]))
        if not rows:
            out.append("     (nothing)")
            continue
        for r in rows:
            n += 1
            if t == 3 and not show_all:
                out.append(_watch_line(n, r, p))
            else:
                out += render_item(n, r, p)
                if show_all and r.get("decision", {}) and r["decision"].get("history"):
                    for h in r["decision"]["history"]:
                        out.append(f"            history: {h.get('at', '')[:10]} {h.get('status')} — {_clean(h.get('reason') or '')}")
    out.append("")
    out.append(p(DISCLAIMER, "dim"))
    return "\n".join(out)
