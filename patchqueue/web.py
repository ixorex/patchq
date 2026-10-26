"""Local dashboard — same queue.json, same rank.py as the CLI.

Actions: Scan now, mark patched / defer / not affected / reopen, change the
schedule. Security model for those actions:
  * binds 127.0.0.1 only; requests with a foreign Host header are refused (DNS rebinding)
  * every POST needs a per-process random token from the page (CSRF), a same-origin
    Origin / Sec-Fetch-Site when the browser sends them, and a small form body
  * no JavaScript at all; strict CSP; every value from feeds/lockfiles is HTML-escaped
"""
from __future__ import annotations

import datetime as dt
import hmac
import html
import json
import secrets
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import DISCLAIMER, __version__, config, group, model, rank, state

MAX_BODY = 8192

CSS = """
:root{--bg:#f5f6f8;--card:#fff;--ink:#12151a;--mute:#5b6472;--line:#e2e5ea;--soft:#eef0f3;--code:#f1f3f6;
--t0:#c62828;--t1:#c76a00;--t2:#2457d6;--t3:#6b7280;--ok:#13804a;--warn:#a85d00;--acc:#2457d6;--acc-ink:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#0e1014;--card:#161a20;--ink:#e8eaee;--mute:#98a1ae;--line:#262b33;
--soft:#1d2229;--code:#1e232a;--t0:#ef5350;--t1:#f5a524;--t2:#6aa3ff;--t3:#9aa3af;--ok:#4ade80;--warn:#fbbf24;--acc:#6aa3ff;--acc-ink:#0e1014}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
header{position:sticky;top:0;z-index:5;background:var(--card);border-bottom:1px solid var(--line)}
.bar{max-width:1040px;margin:0 auto;padding:10px 16px;display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.brand{font-weight:800;font-size:17px;letter-spacing:-.01em}.brand small{font-weight:500;color:var(--mute);font-size:12px;margin-left:6px}
nav{display:flex;gap:4px}nav a{padding:6px 10px;border-radius:7px;color:var(--mute);font-weight:600;font-size:14px}
nav a.on{background:var(--soft);color:var(--ink)}nav a:hover{text-decoration:none;color:var(--ink)}
.spacer{flex:1}.meta{color:var(--mute);font-size:12.5px;text-align:right;line-height:1.35}
.btn{font:inherit;font-size:14px;font-weight:650;border:1px solid var(--line);background:var(--card);color:var(--ink);
border-radius:8px;padding:7px 13px;cursor:pointer}.btn:hover{background:var(--soft)}
.btn.primary{background:var(--acc);border-color:var(--acc);color:var(--acc-ink)}.btn.primary:hover{filter:brightness(1.08)}
.btn.small{font-size:12.5px;padding:4px 9px;font-weight:600}.btn[disabled]{opacity:.55;cursor:default}
main{max-width:1040px;margin:0 auto;padding:20px 16px 56px}
.flash{border-radius:9px;padding:10px 14px;margin:0 0 16px;font-size:14px;border:1px solid var(--line);background:var(--card)}
.flash.run{border-left:4px solid var(--acc)}.flash.err{border-left:4px solid var(--t0)}.flash.ok{border-left:4px solid var(--ok)}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:0 0 14px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:11px;padding:12px 14px;border-top:3px solid var(--line)}
.stat b{display:block;font-size:26px;line-height:1.1;font-variant-numeric:tabular-nums}.stat span{color:var(--mute);font-size:12.5px}
.s0{border-top-color:var(--t0)}.s0 b{color:var(--t0)}.s1{border-top-color:var(--t1)}.s1 b{color:var(--t1)}
.s2{border-top-color:var(--t2)}.s2 b{color:var(--t2)}.s3{border-top-color:var(--t3)}
.pills{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 14px}
.pill{border:1px solid var(--line);border-radius:999px;padding:2px 10px;font-size:12px;background:var(--card);color:var(--mute)}
.pill.err{border-color:var(--warn);color:var(--warn)}
details.heads{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--warn);border-radius:9px;
padding:9px 14px;margin:0 0 18px;font-size:13.5px}details.heads summary{cursor:pointer;font-weight:650}
details.heads ul{margin:8px 0 2px;padding-left:18px}details.heads li{margin:3px 0;overflow-wrap:anywhere}
h2.tier{display:flex;align-items:baseline;gap:9px;font-size:13px;letter-spacing:.08em;margin:26px 0 10px}
h2.tier .n{color:var(--mute);font-weight:500;letter-spacing:0}
.t0{color:var(--t0)}.t1{color:var(--t1)}.t2{color:var(--t2)}.t3{color:var(--t3)}
.card{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--line);border-radius:11px;
padding:14px 16px;margin:0 0 10px}.c0{border-left-color:var(--t0)}.c1{border-left-color:var(--t1)}
.c2{border-left-color:var(--t2)}.c3{border-left-color:var(--t3)}
.top{display:flex;flex-wrap:wrap;align-items:baseline;gap:6px 10px}.pkg{font-weight:750;font-size:16px}
.ver,code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.ver{font-size:13px;color:var(--mute);overflow-wrap:anywhere}
.chip{font-size:11.5px;border-radius:5px;padding:1px 7px;border:1px solid var(--line);color:var(--mute);white-space:nowrap}
.kev{background:var(--t0);border-color:var(--t0);color:#fff}.b-major{color:var(--t0);border-color:var(--t0)}
.b-minor{color:var(--t1);border-color:var(--t1)}.b-patch{color:var(--ok);border-color:var(--ok)}
.why{margin:8px 0 0;font-size:14px}.why .lbl,.where .lbl{color:var(--mute)}.where{font-size:13px;margin:4px 0 0;overflow-wrap:anywhere}
.opts{margin:12px 0 0;display:grid;grid-template-columns:minmax(0,1fr);gap:8px}.opt{min-width:0;background:var(--soft);border-radius:9px;padding:9px 11px}
.tv{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:var(--ink)}
.opt .h{display:flex;flex-wrap:wrap;gap:6px 10px;align-items:center;font-size:13.5px}.opt .h b{font-size:14.5px}
code{display:block;font-size:12.5px;background:var(--code);border:1px solid var(--line);padding:6px 9px;border-radius:7px;
margin:7px 0 0;white-space:pre;overflow-x:auto;max-width:100%}.note{font-size:12.5px;color:var(--mute);margin:5px 0 0}
.warnnote{color:var(--warn);font-size:13px;margin:6px 0 0}
details.cves{margin:10px 0 0}details.cves>summary{cursor:pointer;color:var(--mute);font-size:13px;font-weight:600}
.cve{border-top:1px solid var(--line);padding:9px 0 8px;font-size:13.5px}.cve:first-of-type{border-top:0}
.cve .r{display:flex;flex-wrap:wrap;gap:4px 10px;align-items:baseline}.cve .id{font-weight:700}
.cve .s{color:var(--mute);font-size:12.5px;margin:3px 0 0}
.acts{display:flex;flex-wrap:wrap;gap:6px;margin:7px 0 0}.acts form{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:0}
.acts input[type=text],.acts input[type=date],select,input[type=time]{font:inherit;font-size:12.5px;padding:4px 7px;
border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--ink)}
.acts input[type=text]{width:190px;max-width:100%}
details.act>summary{list-style:none;cursor:pointer;display:inline-block}details.act>summary::-webkit-details-marker{display:none}
details.act[open]>summary{background:var(--soft)}details.act>form{margin:6px 0 0}
details.watch>summary{cursor:pointer;color:var(--mute);margin:4px 0 12px;font-weight:600;font-size:14px}
.row{display:flex;flex-wrap:wrap;gap:4px 12px;align-items:baseline;padding:8px 12px;background:var(--card);
border:1px solid var(--line);border-radius:9px;margin:0 0 6px;font-size:13.5px}
.empty{color:var(--mute);font-size:13.5px;padding:2px 2px 6px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:11px;padding:16px 18px;margin:0 0 14px}
.panel h3{margin:0 0 10px;font-size:15px}.panel p{margin:6px 0;font-size:14px}.panel ul{margin:6px 0;padding-left:18px;font-size:14px}
.kv{display:grid;grid-template-columns:150px minmax(0,1fr);gap:6px 12px;font-size:14px}.kv dt{color:var(--mute)}.kv dd{margin:0;overflow-wrap:anywhere}
footer{margin-top:40px;color:var(--mute);font-size:12px;border-top:1px solid var(--line);padding-top:12px}
@media (max-width:640px){.chip{white-space:normal}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.meta{display:none}.kv{grid-template-columns:1fr}}
"""

TIER_TITLES = {0: "PATCH TODAY", 1: "THIS WEEK", 2: "THIS SPRINT / PLAN", 3: "WATCHING"}


def e(s) -> str:
    return html.escape("" if s is None else str(s), quote=True)


def _link(url, text=None) -> str:
    url = str(url or "")
    if url.startswith("https://"):
        return f'<a href="{e(url)}" rel="noreferrer noopener" target="_blank">{e(text or url)}</a>'
    return e(text or url)


def fmt_time(iso) -> str:
    if not iso:
        return "never"
    try:
        t = dt.datetime.fromisoformat(str(iso)).astimezone()
    except ValueError:
        return e(iso)
    return t.strftime("%b %d, %H:%M")


# ---------------------------------------------------------------- scan runner (one per process)
class ScanJob:
    def __init__(self):
        self.lock = threading.Lock()
        self.running = False
        self.log = []
        self.error = None
        self.started = None

    def start(self, targets, docker):
        with self.lock:
            if self.running:
                return False
            self.running, self.log, self.error, self.started = True, [], None, dt.datetime.now().astimezone()
        threading.Thread(target=self._run, args=(targets, docker), daemon=True).start()
        return True

    def _run(self, targets, docker):
        from . import runner
        try:
            _, errors = runner.run(targets, docker=docker, log=self._log, trigger="dashboard")
            self.error = "; ".join(errors) or None
        except state.Busy:
            self.error = "another scan (probably the scheduled one) is already running"
        except Exception as ex:  # noqa: BLE001 — surface, never crash the server
            self.error = f"{type(ex).__name__}: {ex}"
        finally:
            with self.lock:
                self.running = False

    def _log(self, msg):
        self.log = (self.log + [str(msg)])[-8:]


def other_scan_running() -> bool:
    try:
        with state.scan_lock(blocking=False):
            return False
    except state.Busy:
        return True


def default_targets(data):
    if config.exists():
        cfg = config.load()
        if cfg["roots"] or cfg["docker"]:
            return cfg["roots"], cfg["docker"]
    roots = [k for k in data.get("scans", {}) if not k.startswith("docker://")]
    docker = any(k.startswith("docker://") for k in data.get("scans", {}))
    return roots, docker


# ---------------------------------------------------------------- page pieces
def _layout(title, active, body, token, data, job, refresh=False):
    cfg = config.load()
    last = (data.get("last_run") or {}).get("finished")
    running = job.running or other_scan_running()
    sched = config.describe_schedule(cfg["schedule"])
    scan_btn = (f"<form method='post' action='/scan'><input type='hidden' name='token' value='{e(token)}'>"
                f"<button class='btn primary' {'disabled' if running else ''}>"
                f"{'Scanning…' if running else 'Scan now'}</button></form>")
    nav = "".join(f"<a href='{href}' class='{'on' if active == key else ''}'>{label}</a>"
                  for key, href, label in (("queue", "/", "Queue"), ("cve", "/?view=cve", "By CVE"),
                                           ("settings", "/settings", "Settings")))
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            + ("<meta http-equiv='refresh' content='4'>" if refresh else "")
            + f"<title>{e(title)} · PatchQ</title><style>{CSS}</style></head><body>"
            f"<header><div class='bar'><span class='brand'>PatchQ<small>{e(__version__)}</small></span>"
            f"<nav>{nav}</nav><span class='spacer'></span>"
            f"<span class='meta'>last scan {e(fmt_time(last))}<br>auto: {e(sched)}</span>{scan_btn}</div></header>"
            f"<main>{body}<footer>{e(DISCLAIMER)} Runs on this machine only (127.0.0.1).</footer></main></body></html>")


def _flash(job, msg, err):
    out = []
    if job.running:
        tail = e(job.log[-1]) if job.log else "starting…"
        out.append(f"<div class='flash run'><b>Scanning…</b> {tail} <span class='note'>(this page refreshes itself)</span></div>")
    elif other_scan_running():
        out.append("<div class='flash run'><b>A scheduled scan is running.</b> Refresh in a minute.</div>")
    elif job.error:
        out.append(f"<div class='flash err'><b>Last scan had problems:</b> {e(job.error)}</div>")
    if msg:
        out.append(f"<div class='flash {'err' if err else 'ok'}'>{e(msg[:300])}</div>")
    return "".join(out)


def _pills(sources):
    out = []
    for name in ("OSV", "KEV", "EPSS", "NVD"):
        s = sources.get(name)
        if not s:
            continue
        cls = " err" if s.get("error") else ""
        when = fmt_time(s.get("as_of")) if s.get("as_of") else ("no data" if s.get("error") else "not used")
        title = s.get("error") or s.get("note") or ""
        out.append(f"<span class='pill{cls}' title='{e(title)}'>{name} {'⚠ ' if s.get('error') else ''}{e(when)}</span>")
    return f"<div class='pills'>{''.join(out)}</div>" if out else ""


def _heads(warnings):
    if not warnings:
        return ""
    return (f"<details class='heads'{' open' if len(warnings) <= 2 else ''}><summary>Heads-up · {len(warnings)} "
            "thing(s) PatchQ couldn't check</summary><ul>" + "".join(f"<li>{e(w)}</li>" for w in warnings)
            + "</ul></details>")


def _breaks(b):
    return f"<span class='chip b-{e(b.get('kind'))}'>breaks risk: {e(b.get('label'))}</span>"


def _hidden(token, **kw):
    return f"<input type='hidden' name='token' value='{e(token)}'>" + "".join(
        f"<input type='hidden' name='{e(k)}' value='{e(v)}'>" for k, v in kw.items() if v is not None)


def _actions(r, token, back):
    vid = r["id"]
    tomorrow = (dt.date.today() + dt.timedelta(days=1)).isoformat()
    default_rc = (dt.date.today() + dt.timedelta(days=14)).isoformat()
    h = lambda action: _hidden(token, id=vid, action=action, back=back)  # noqa: E731
    if r.get("status") in ("deferred", "not_affected"):
        return (f"<div class='acts'><form method='post' action='/decide'>{h('reopen')}"
                "<button class='btn small'>Put back in queue</button></form></div>")
    return ("<div class='acts'>"
            f"<form method='post' action='/decide'>{h('done')}<button class='btn small'>Mark patched</button></form>"
            "<details class='act'><summary class='btn small'>Defer…</summary>"
            f"<form method='post' action='/decide'>{h('defer')}"
            f"<input type='date' name='recheck' min='{tomorrow}' value='{default_rc}' required>"
            "<input type='text' name='reason' maxlength='300' placeholder='why defer?' required>"
            "<button class='btn small'>Defer</button></form></details>"
            "<details class='act'><summary class='btn small'>Not affected…</summary>"
            f"<form method='post' action='/decide'>{h('ignore')}"
            "<input type='text' name='reason' maxlength='300' placeholder='why not affected?' required>"
            "<button class='btn small'>Save</button></form></details></div>")


def _cve_row(r, token, back):
    fixed = r.get("fixed") or ("fix unknown" if r.get("fix_unknown") else "no fix yet")
    sig = []
    if r.get("kev"):
        sig.append("<span class='chip kev'>CISA KEV</span>")
    sig.append(f"<span class='chip'>EPSS {r['epss']:.3f}</span>" if r.get("epss") is not None else "")
    sig.append(f"<span class='chip'>CVSS {r['cvss']:.1f}</span>" if r.get("cvss") is not None
               else "<span class='chip'>CVSS pending</span>")
    note = f"<div class='warnnote'>{e(r['status_note'])}</div>" if r.get("status_note") else ""
    hist = "".join(f"<div class='s'>history: {e((x.get('at') or '')[:10])} {e(x.get('status'))} — {e(x.get('reason'))}</div>"
                   for x in (r.get("decision") or {}).get("history") or [])
    return (f"<div class='cve'><div class='r'><span class='id'>{_link(r.get('url'), r['id'])}</span>"
            f"<span class='chip t{r['tier']}'>{e(r['tier_name'])}</span>{''.join(sig)}"
            f"<span class='ver'>→ {e(fixed)}</span></div>"
            f"<div class='s'>{e(r.get('summary'))}</div><div class='s'>{e(r.get('why'))}</div>"
            f"{note}{hist}{_actions(r, token, back)}</div>")


def _group_card(g, token):
    best = g["best"]
    chips = [f"<span class='chip'>{e(g['ecosystem'])}</span>",
             f"<span class='chip'>{g['count']} vuln{'s' if g['count'] != 1 else ''}</span>"]
    if g["kev"]:
        chips.append("<span class='chip kev'>CISA KEV</span>")
    if g["exposed"]:
        chips.append("<span class='chip'>exposed</span>")
    if g["critical"]:
        chips.append("<span class='chip'>critical</span>")
    where = "; ".join(f"{e(l.get('system'))} <span class='ver'>({e(l.get('file'))})</span>"
                      + (" · transitive" if l.get("direct") is False else "") for l in g["locations"][:4])
    opts = []
    for t in g["targets"]:
        clears = ("clears all" if t["clears"] == t["of"] else f"clears {t['clears']} of {t['of']}") if t["of"] > 1 else ""
        scope = f"<span class='note'>{e(t['scope'])}</span>" if len(g["targets"]) > 1 else ""
        cmd = f"<code>{e(t['fix_cmd'])}</code>" if t["fix_cmd"] else ""
        opts.append(f"<div class='opt'><div class='h'><b class='tv'>→ {e(t['version'])}</b>"
                    f"{('<span>' + clears + '</span>') if clears else ''}{_breaks(t['breaks'])}{scope}</div>"
                    f"{cmd}{('<div class=note>' + e(t['fix_note']) + '</div>') if t.get('fix_note') else ''}</div>")
    if g["no_fix"]:
        opts.append(f"<div class='opt'><div class='h'><b>No fix yet</b> for {e(', '.join(g['no_fix'][:5]))}</div>"
                    "<div class='note'>mitigate (advisory workaround), isolate (cut exposure), or watch — "
                    "PatchQ re-checks every scan</div></div>")
    notes = "".join(f"<div class='warnnote'>{e(n)}</div>" for n in g["notes"])
    back = "/"
    rows = "".join(_cve_row(r, token, back) for r in g["items"])
    return (f"<div class='card c{g['tier']}'><div class='top'><span class='pkg'>{e(g['package'])}</span>"
            f"<span class='ver'>{e(g['installed'])}</span>{''.join(chips)}</div>"
            f"<div class='why'><span class='lbl'>Why: </span>{e(best['why'])}</div>"
            f"<div class='where'><span class='lbl'>Where: </span>{where}</div>{notes}"
            f"<div class='opts'>{''.join(opts)}</div>"
            f"<details class='cves'><summary>{g['count']} advisor{'y' if g['count'] == 1 else 'ies'} · details & actions</summary>"
            f"{rows}</details></div>")


def _decided_row(r, token):
    dec = r.get("decision") or {}
    label = "deferred until " + str(r.get("recheck")) if r["status"] == "deferred" else "not affected"
    return (f"<div class='row'><b>{_link(r.get('url'), r['id'])}</b><span class='ver'>{e(r.get('package'))} "
            f"{e(r.get('installed'))}</span><span class='chip'>{e(label)}</span>"
            f"<span class='note'>“{e(dec.get('reason'))}” · {e((dec.get('at') or '')[:10])}</span>"
            f"{_actions(r, token, '/')}</div>")


def page_queue(data, token, job, msg=None, err=False, today=None):
    ranked = rank.rank(state.merged_items(data), data.get("decisions"), state.merged_inventory(data), today)
    groups, decided = group.group(ranked)
    scans = list(data.get("scans", {}).values())
    warnings = [w for s in scans for w in s.get("warnings", [])]
    counts = {t: sum(1 for g in groups if g["tier"] == t) for t in range(4)}
    labels = {0: "Patch Today", 1: "This Week", 2: "This Sprint", 3: "Watching"}
    stats = "".join(f"<div class='stat s{t}'><b>{counts[t]}</b><span>{labels[t]} · packages</span></div>" for t in range(4))
    body = [_flash(job, msg, err)]
    if not scans:
        body.append("<div class='panel'><h3>Nothing scanned yet</h3><p>Run <b>patchq init</b> in a terminal for "
                    "guided setup, or press <b>Scan now</b> to scan the folders in your config.</p></div>")
    body += [f"<div class='stats'>{stats}</div>", _pills(state.merged_sources(data)), _heads(warnings)]
    for t in range(4):
        rows = [g for g in groups if g["tier"] == t]
        extra = f" + {len(decided)} decided" if t == 3 and decided else ""
        body.append(f"<h2 class='tier t{t}'>{TIER_TITLES[t]} <span class='n'>{len(rows)} package{'s' if len(rows) != 1 else ''}{extra}</span></h2>")
        cards = "".join(_group_card(g, token) for g in rows)
        if t == 3:
            cards += "".join(_decided_row(r, token) for r in decided)
            if cards:
                cards = f"<details class='watch'><summary>Show watching items</summary>{cards}</details>"
        body.append(cards or "<div class='empty'>Nothing here.</div>")
    return _layout("Queue", "queue", "".join(body), token, data, job, refresh=job.running or other_scan_running())


def page_cve(data, token, job, msg=None, err=False, today=None):
    ranked = rank.rank(state.merged_items(data), data.get("decisions"), state.merged_inventory(data), today)
    body = [_flash(job, msg, err), _pills(state.merged_sources(data))]
    for t in range(4):
        rows = [r for r in ranked if r["tier"] == t]
        body.append(f"<h2 class='tier t{t}'>{TIER_TITLES[t]} <span class='n'>{len(rows)}</span></h2>")
        inner = "".join(f"<div class='card c{t}'><div class='top'><span class='pkg'>{e(r.get('package'))}</span>"
                        f"<span class='ver'>{e(r.get('installed'))}</span>{_breaks(r.get('breaks') or {})}</div>"
                        f"{_cve_row(r, token, '/?view=cve')}"
                        + (f"<code>{e(r['fix_cmd'])}</code>" if r.get('fix_cmd') else "") + "</div>" for r in rows)
        body.append(inner or "<div class='empty'>Nothing here.</div>")
    return _layout("By CVE", "cve", "".join(body), token, data, job, refresh=job.running)


def page_settings(data, token, job, msg=None, err=False):
    from . import service
    cfg = config.load()
    st = service.status()
    s = cfg["schedule"]
    freq_opts = "".join(f"<option value='{f}' {'selected' if s['freq'] == f else ''}>{f}</option>" for f in config.FREQS)
    day_opts = "".join(f"<option value='{d}' {'selected' if s['weekday'] == d else ''}>{d}</option>" for d in config.WEEKDAYS)
    roots = "".join(f"<li class='ver'>{e(r)}</li>" for r in cfg["roots"]) or "<li>none yet</li>"
    last = data.get("last_run") or {}
    svc = ("<p>Background services aren't available here (no systemd user session). Use cron or run "
           "<b>patchq serve</b> when needed.</p>" if not st["available"] else
           f"<dl class='kv'><dt>Dashboard service</dt><dd>{e(st['dashboard'])}</dd>"
           f"<dt>Scan timer</dt><dd>{e(st['timer'])}</dd><dt>Next scan</dt><dd>{e(st['next'] or '—')}</dd></dl>")
    body = (_flash(job, msg, err)
            + "<div class='panel'><h3>Automatic scans</h3>"
            f"<form method='post' action='/schedule' class='acts'>{_hidden(token)}"
            f"<select name='freq'>{freq_opts}</select>"
            f"<input type='time' name='time' value='{e(s['time'])}' required>"
            f"<select name='weekday' title='day for weekly scans'>{day_opts}</select>"
            "<button class='btn small'>Save schedule</button></form>"
            f"<p class='note'>Currently: {e(config.describe_schedule(s))}. Weekly uses the day picker.</p>{svc}</div>"
            "<div class='panel'><h3>What gets scanned</h3>"
            f"<ul>{roots}</ul><p>Running containers: <b>{'yes' if cfg['docker'] else 'no'}</b></p>"
            "<p class='note'>Change these with <b>patchq init</b> in a terminal (folder access stays out of the browser on purpose).</p></div>"
            "<div class='panel'><h3>Last run</h3><dl class='kv'>"
            f"<dt>Finished</dt><dd>{e(fmt_time(last.get('finished')))}</dd>"
            f"<dt>Triggered by</dt><dd>{e(last.get('trigger') or '—')}</dd>"
            f"<dt>Targets</dt><dd>{e(', '.join(last.get('targets') or []) or '—')}</dd>"
            f"<dt>Errors</dt><dd>{e('; '.join(last.get('errors') or []) or 'none')}</dd></dl></div>"
            "<div class='panel'><h3>Open this from another computer</h3>"
            f"<p>The dashboard only listens on this machine. From your PC run:</p>"
            f"<code>ssh -N -L {cfg['port']}:127.0.0.1:{cfg['port']} &lt;user&gt;@&lt;this-host&gt;</code>"
            f"<p>then open http://127.0.0.1:{cfg['port']} in your browser.</p></div>")
    return _layout("Settings", "settings", body, token, data, job, refresh=job.running)


# ---------------------------------------------------------------- HTTP
def make_handler(port, token, job):
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    origins = {f"http://{h}" for h in hosts}

    class Handler(BaseHTTPRequestHandler):
        server_version = f"patchq/{__version__}"
        sys_version = ""

        def _send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; "
                             "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "same-origin")  # no-referrer would make browsers send Origin: null on our own forms
            self.send_header("Cache-Control", "no-store")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _redirect(self, where, msg=None, err=False):
            q = {}
            if msg:
                q["msg"] = msg[:300]
            if err:
                q["err"] = "1"
            path, _, existing = where.partition("?")
            params = dict(urllib.parse.parse_qsl(existing))
            params.update(q)
            loc = path + ("?" + urllib.parse.urlencode(params) if params else "")
            self.send_response(303)
            self.send_header("Location", loc)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _host_ok(self):
            return self.headers.get("Host", "") in hosts

        def do_GET(self):  # noqa: N802
            if not self._host_ok():
                return self._send(403, "forbidden host", "text/plain; charset=utf-8")
            path, _, qs = self.path.partition("?")
            q = dict(urllib.parse.parse_qsl(qs))
            try:
                data = state.load()
            except state.StateError as ex:
                return self._send(500, str(ex), "text/plain; charset=utf-8")
            msg, err = q.get("msg"), q.get("err") == "1"
            if path == "/":
                page = page_cve if q.get("view") == "cve" else page_queue
                return self._send(200, page(data, token, job, msg, err))
            if path == "/settings":
                return self._send(200, page_settings(data, token, job, msg, err))
            if path == "/api/queue":
                ranked = rank.rank(state.merged_items(data), data.get("decisions"), state.merged_inventory(data))
                return self._send(200, json.dumps({"items": ranked, "sources": state.merged_sources(data)}, default=str),
                                  "application/json")
            if path == "/api/status":
                return self._send(200, json.dumps({"running": job.running or other_scan_running(),
                                                   "log": job.log, "error": job.error,
                                                   "last_run": data.get("last_run")}), "application/json")
            return self._send(404, "not found", "text/plain; charset=utf-8")

        def do_POST(self):  # noqa: N802
            if not self._host_ok():
                return self._send(403, "forbidden host", "text/plain; charset=utf-8")
            origin = self.headers.get("Origin")
            if origin is not None and origin not in origins:
                return self._send(403, "cross-origin request refused", "text/plain; charset=utf-8")
            site = self.headers.get("Sec-Fetch-Site")
            if site is not None and site not in ("same-origin", "none"):
                return self._send(403, "cross-site request refused", "text/plain; charset=utf-8")
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
            if ctype != "application/x-www-form-urlencoded":
                return self._send(415, "form posts only", "text/plain; charset=utf-8")
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if length < 0 or length > MAX_BODY:
                return self._send(413, "request too large", "text/plain; charset=utf-8")
            form = dict(urllib.parse.parse_qsl(self.rfile.read(length).decode("utf-8", "replace")))
            if not hmac.compare_digest(form.get("token", ""), token):
                return self._send(403, "stale or missing form token — reload the page", "text/plain; charset=utf-8")
            path = self.path.partition("?")[0]
            if path == "/scan":
                return self._scan()
            if path == "/decide":
                return self._decide(form)
            if path == "/schedule":
                return self._schedule(form)
            return self._send(404, "not found", "text/plain; charset=utf-8")

        def _scan(self):
            if other_scan_running():
                return self._redirect("/", "A scan is already running.", err=True)
            targets, docker = default_targets(state.load())
            if not targets and not docker:
                return self._redirect("/", "Nothing to scan yet — run `patchq init` in a terminal first.", err=True)
            job.start(targets, docker)
            return self._redirect("/")

        def _decide(self, form):
            back = form.get("back") if form.get("back") in ("/", "/?view=cve") else "/"
            vid, action = form.get("id", ""), form.get("action", "")
            status = {"done": "patched", "defer": "deferred", "ignore": "not_affected", "reopen": "reopened"}.get(action)
            if not status or not model.ID_RE.match(vid):
                return self._redirect(back, "Unknown action.", err=True)
            reason = (form.get("reason") or "").strip()[:300]
            if action in ("defer", "ignore") and not reason:
                return self._redirect(back, "A reason is required.", err=True)
            if action == "reopen":
                reason = reason or "reopened from dashboard"
            try:
                with state.transaction() as data:
                    state.set_decision(data, vid, status, reason=reason,
                                       recheck=(form.get("recheck") or None) if action == "defer" else None)
            except ValueError as ex:
                return self._redirect(back, str(ex), err=True)
            words = {"done": "marked patched — it'll disappear after the next scan if the upgrade landed",
                     "defer": "deferred", "ignore": "marked not affected", "reopen": "back in the queue"}
            return self._redirect(back, f"{vid.upper()} {words[action]}.")

        def _schedule(self, form):
            from . import service
            cfg = config.load()
            cfg["schedule"] = {"freq": form.get("freq", ""), "time": form.get("time", ""),
                               "weekday": form.get("weekday", "")}
            try:
                config.save(cfg)
            except config.ConfigError as ex:
                return self._redirect("/settings", str(ex), err=True)
            msgs = service.set_schedule(cfg)
            return self._redirect("/settings", "Saved. " + " ".join(msgs))

        def log_message(self, *args):
            pass

    return Handler


def make_server(port=8765):
    token = secrets.token_urlsafe(32)
    job = ScanJob()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(port, token, job))
    actual = httpd.server_address[1]
    if actual != port:  # port 0 = pick a free one (tests)
        httpd.RequestHandlerClass = make_handler(actual, token, job)
    httpd.patchq_token = token
    httpd.patchq_job = job
    return httpd
