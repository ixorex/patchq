"""Local dashboard — same queue.json, same rank.py as the CLI. Read-only.

Security: binds 127.0.0.1 only; rejects foreign Host headers (DNS rebinding);
no JavaScript; strict CSP; every value from feeds/lockfiles is HTML-escaped.
Being read-only means a malicious web page can't make it change your decisions.
"""
from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import DISCLAIMER, __version__, rank, state

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#14171c;--mute:#5d6673;--line:#e3e6eb;--code:#f0f2f5;
--t0:#c62828;--t1:#d97706;--t2:#2563eb;--t3:#6b7280;--ok:#15803d;--warn:#b45309}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a20;--ink:#e7e9ee;--mute:#99a1ad;
--line:#272b33;--code:#1f232b;--t0:#ef5350;--t1:#f59e0b;--t2:#60a5fa;--t3:#9ca3af;--ok:#4ade80;--warn:#fbbf24}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 48px}.meta,.warn li{overflow-wrap:anywhere}
h1{font-size:22px;margin:0 0 4px}h1 small{font-weight:400;color:var(--mute);font-size:14px}
.meta{color:var(--mute);font-size:13px;margin:0 0 16px}.src{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0 16px}
.pill{border:1px solid var(--line);border-radius:999px;padding:2px 10px;font-size:12px;background:var(--card)}
.pill.err{border-color:var(--warn);color:var(--warn)}
.warn{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--warn);border-radius:8px;
padding:10px 14px;margin:0 0 20px;font-size:13px}.warn ul{margin:6px 0 0;padding-left:18px}
.tier{margin:28px 0 10px;display:flex;align-items:baseline;gap:10px}.tier h2{font-size:16px;margin:0;letter-spacing:.04em}
.count{color:var(--mute);font-size:13px}.t0 h2{color:var(--t0)}.t1 h2{color:var(--t1)}.t2 h2{color:var(--t2)}.t3 h2{color:var(--t3)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:0 0 10px;
border-left:4px solid var(--line)}.c0{border-left-color:var(--t0)}.c1{border-left-color:var(--t1)}
.c2{border-left-color:var(--t2)}.c3{border-left-color:var(--t3)}
.top{display:flex;flex-wrap:wrap;gap:8px 14px;align-items:baseline}.id{font-weight:700}
.ver{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;overflow-wrap:anywhere}
.badge{font-size:11px;border-radius:4px;padding:1px 6px;border:1px solid var(--line);color:var(--mute)}
.b-major{color:var(--t0);border-color:var(--t0)}.b-minor{color:var(--t1);border-color:var(--t1)}
.b-patch{color:var(--ok);border-color:var(--ok)}.kev{background:var(--t0);color:#fff;border-color:var(--t0)}
dl{display:grid;grid-template-columns:56px minmax(0,1fr);gap:4px 10px;margin:10px 0 0;font-size:13.5px}
dt{color:var(--mute)}dd{margin:0;overflow-wrap:anywhere}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;background:var(--code);
padding:3px 6px;border-radius:5px;display:inline-block;max-width:100%;overflow-x:auto;white-space:pre}
a{color:var(--t2)}details summary{cursor:pointer;color:var(--mute);margin:6px 0 10px}
.empty{color:var(--mute);font-size:13px;padding:4px 2px}.note{color:var(--warn)}
footer{margin-top:36px;color:var(--mute);font-size:12px;border-top:1px solid var(--line);padding-top:12px}
"""

TIER_TITLES = {0: "PATCH TODAY", 1: "THIS WEEK", 2: "THIS SPRINT / PLAN", 3: "WATCHING"}


def e(s) -> str:
    return html.escape("" if s is None else str(s), quote=True)


def _link(url) -> str:
    url = str(url or "")
    if url.startswith("https://"):
        return f'<a href="{e(url)}" rel="noreferrer noopener">{e(url)}</a>'
    return e(url)


def _card(n, r) -> str:
    br = r.get("breaks") or {}
    fixed = r.get("fixed") or ("fix unknown" if r.get("fix_unknown") else "no fix yet")
    badges = []
    if r.get("kev"):
        badges.append('<span class="badge kev">CISA KEV</span>')
    if r.get("exposed"):
        badges.append('<span class="badge">exposed</span>')
    if r.get("critical"):
        badges.append('<span class="badge">critical</span>')
    if r.get("status") not in (None, "open"):
        badges.append(f'<span class="badge">{e(r["status"].replace("_", " "))}</span>')
    where = "; ".join(
        f"{e(l.get('system'))} <span class='ver'>({e(l.get('file'))}{(' → ' + e(l.get('target'))) if l.get('target') else ''})</span>"
        + (" · transitive" if l.get("direct") is False else "") + (" · dev" if l.get("dev") else "")
        for l in r.get("locations", [])[:5])
    rows = [f"<dt>where</dt><dd>{where}</dd>", f"<dt>why</dt><dd>{e(r.get('why'))}</dd>"]
    if r.get("status_note"):
        rows.append(f"<dt>note</dt><dd class='note'>{e(r['status_note'])}</dd>")
    if r.get("fix_cmd"):
        rows.append("<dt>fix</dt><dd>" + "<br>".join(f"<code>{e(c)}</code>" for c in r["fix_cmd"].splitlines()) + "</dd>")
    if r.get("fix_note"):
        rows.append(f"<dt>{'' if r.get('fix_cmd') else 'fix'}</dt><dd>{e(r['fix_note'])}</dd>")
    if r.get("summary") or r.get("url"):
        rows.append(f"<dt>what</dt><dd>{e(r.get('summary'))} {_link(r.get('url'))}</dd>")
    dec = r.get("decision") or {}
    for h in dec.get("history") or []:
        rows.append(f"<dt>history</dt><dd>{e((h.get('at') or '')[:10])} {e(h.get('status'))} — {e(h.get('reason'))}</dd>")
    return (f'<div class="card c{r["tier"]}"><div class="top"><span class="count">#{n}</span>'
            f'<span class="id">{e(r["id"])}</span><span class="ver">{e(r.get("package"))} '
            f'{e(r.get("installed"))} → {e(fixed)}</span>'
            f'<span class="badge b-{e(br.get("kind"))}">breaks risk: {e(br.get("label"))}</span>'
            f'{"".join(badges)}</div><dl>{"".join(rows)}</dl></div>')


def render_page(data, today=None) -> str:
    ranked = rank.rank(state.merged_items(data), data.get("decisions"), state.merged_inventory(data), today)
    scans = list(data.get("scans", {}).values())
    sources = state.merged_sources(data)
    warnings = [w for s in scans for w in s.get("warnings", [])]
    pills = []
    for name in ("OSV", "KEV", "EPSS", "NVD"):
        s = sources.get(name)
        if not s:
            continue
        as_of = (s.get("as_of") or "")[:16].replace("T", " ")
        cls = " err" if s.get("error") else ""
        when = f"{as_of} UTC" if as_of else ("no data" if s.get("error") else "not used")
        label = f"{name}: {'⚠ ' if s.get('error') else ''}{when}"
        title = s.get("error") or s.get("note") or ""
        pills.append(f'<span class="pill{cls}" title="{e(title)}">{e(label)}</span>')
    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
           f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
           f"<title>PatchQ queue</title><style>{CSS}</style></head><body><main>"
           f"<h1>PatchQ <small>{e(__version__)} · local dashboard · read-only</small></h1>"
           f"<p class='meta'>{len(ranked)} items from: "
           + e(", ".join(f"{s.get('label')} (scanned {(s.get('scanned_at') or '')[:16].replace('T', ' ')})" for s in scans)
               or "nothing scanned yet — run `patchq scan <folder>`")
           + f"</p><div class='src'>{''.join(pills)}</div>"]
    if warnings:
        out.append(f"<div class='warn'><strong>Heads-up ({len(warnings)})</strong><ul>"
                   + "".join(f"<li>{e(w)}</li>" for w in warnings) + "</ul></div>")
    n = 0
    for t in range(4):
        rows = [r for r in ranked if r["tier"] == t]
        out.append(f"<div class='tier t{t}'><h2>{TIER_TITLES[t]}</h2><span class='count'>{len(rows)}</span></div>")
        cards = []
        for r in rows:
            n += 1
            cards.append(_card(n, r))
        body = "".join(cards) or "<div class='empty'>Nothing here.</div>"
        if t == 3 and rows:
            body = f"<details><summary>Show {len(rows)} watching items</summary>{body}</details>"
        out.append(body)
    out.append(f"<footer>{e(DISCLAIMER)} Actions (done / defer / ignore) are CLI-only so this page can't be "
               "abused to change your queue. Reload after `patchq scan`.</footer></main></body></html>")
    return "".join(out)


def make_handler(port):
    allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = f"patchq/{__version__}"
        sys_version = ""

        def _send(self, code, body, ctype):
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; "
                             "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802
            if self.headers.get("Host", "") not in allowed:
                return self._send(403, "forbidden host", "text/plain; charset=utf-8")
            try:
                data = state.load()
            except state.StateError as ex:
                return self._send(500, str(ex), "text/plain; charset=utf-8")
            path = self.path.split("?", 1)[0]
            if path == "/":
                return self._send(200, render_page(data), "text/html; charset=utf-8")
            if path == "/api/queue":
                ranked = rank.rank(state.merged_items(data), data.get("decisions"), state.merged_inventory(data))
                return self._send(200, json.dumps({"items": ranked, "sources": state.merged_sources(data)}),
                                  "application/json")
            return self._send(404, "not found", "text/plain; charset=utf-8")

        def do_POST(self):  # noqa: N802
            self._send(405, "read-only", "text/plain; charset=utf-8")

        def log_message(self, *args):
            pass

    return Handler


def make_server(port=8765):
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(port))
    actual = httpd.server_address[1]
    if actual != port:  # port 0 = pick a free one
        httpd.RequestHandlerClass = make_handler(actual)
    return httpd
