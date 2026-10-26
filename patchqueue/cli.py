"""patchq — scan / queue / done / defer / ignore / serve."""
from __future__ import annotations

import argparse
import json
import sys

from . import DISCLAIMER, __version__, rank, render, state
from .scan import ScanError, scan


def _err(msg):
    print(f"patchq: {msg}", file=sys.stderr)


def _show(data, args, title="queue"):
    ranked = rank.rank(state.merged_items(data), data.get("decisions"), state.merged_inventory(data))
    scans = list(data["scans"].values())
    if getattr(args, "json", False):
        print(json.dumps({"items": ranked, "sources": state.merged_sources(data),
                          "scans": [{k: s.get(k) for k in ("label", "root", "scanned_at", "warnings")} for s in scans],
                          "disclaimer": DISCLAIMER}, indent=1))
        return 0
    warnings = [w for s in scans for w in s.get("warnings", [])]
    print(render.render_queue(ranked, scans, state.merged_sources(data), warnings,
                              color=render.use_color(), show_all=getattr(args, "all", False), title=title))
    return 0


def cmd_scan(args):
    data = state.load()
    targets = args.paths or ["."]
    for i, t in enumerate(targets):
        try:
            rec = scan(t, extra_reports=args.imports if i == 0 else (), offline=args.offline, pull=args.pull,
                       use_nvd=not args.no_nvd, nvd_max=args.nvd_max,
                       log=lambda m: print(f"patchq: {m}", file=sys.stderr))
        except ScanError as e:
            _err(str(e))
            return 2
        state.record_scan(data, rec)
    state.save(data)
    return _show(data, args, title="scan")


def cmd_queue(args):
    data = state.load()
    if not data["scans"]:
        _err("nothing scanned yet — run `patchq scan <folder>`")
        return 1
    return _show(data, args)


def _decide(args, status):
    data = state.load()
    try:
        entry = state.set_decision(data, args.id, status, reason=getattr(args, "reason", None),
                                   recheck=getattr(args, "recheck", None), package=args.package)
    except ValueError as e:
        _err(str(e))
        return 2
    state.save(data)
    known = state.known_ids(data)
    label = {"patched": "marked patched", "deferred": "deferred", "not_affected": "marked not affected"}[status]
    msg = f"{args.id.upper()} {label}"
    if entry.get("recheck"):
        msg += f" (recheck {entry['recheck']})"
    if args.id.upper() not in known:
        msg += " — note: not in the current queue; recorded anyway"
    if status == "patched":
        msg += ". Re-run `patchq scan` to confirm it's gone."
    print(msg)
    return 0


def cmd_serve(args):
    from . import web
    try:
        httpd = web.make_server(args.port)
    except OSError as e:
        _err(f"can't listen on 127.0.0.1:{args.port} ({e}) — try --port")
        return 2
    print(f"PatchQ dashboard: http://127.0.0.1:{httpd.server_address[1]}/  (localhost only, read-only; Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="patchq", description="One ranked patch queue for your stack: "
                                "Patch Today / This Week / Watching.", epilog=DISCLAIMER)
    p.add_argument("--version", action="version", version=f"patchq {__version__}")
    sub = p.add_subparsers(dest="cmd", metavar="command")

    s = sub.add_parser("scan", help="find lockfiles/compose files, query feeds, build the queue")
    s.add_argument("paths", nargs="*", help="folder, file, or https/ssh git URL (default: .)")
    s.add_argument("--import", dest="imports", action="append", default=[], metavar="FILE",
                   help="Trivy / Grype / OSV-Scanner JSON report to include (repeatable)")
    s.add_argument("--pull", action="store_true", help="git pull --ff-only before scanning a local repo")
    s.add_argument("--offline", action="store_true", help="use cached feed data only; no network")
    s.add_argument("--no-nvd", action="store_true", help="skip NVD lookups (CVSS shows as pending if missing)")
    s.add_argument("--nvd-max", type=int, default=None, metavar="N", help="max NVD lookups this run")
    s.add_argument("--all", action="store_true", help="expand Watching items")
    s.add_argument("--json", action="store_true", help="machine-readable output")
    s.set_defaults(func=cmd_scan)

    q = sub.add_parser("queue", help="show Patch Today / This Week / Watching")
    q.add_argument("--all", action="store_true", help="expand Watching items and decision history")
    q.add_argument("--json", action="store_true", help="machine-readable output")
    q.set_defaults(func=cmd_queue)

    d = sub.add_parser("done", help="mark a vulnerability patched")
    d.add_argument("id")
    d.add_argument("--reason", default="")
    d.add_argument("--package", help="only for this package")
    d.set_defaults(func=lambda a: _decide(a, "patched"))

    f = sub.add_parser("defer", help="defer with a reason and a recheck date")
    f.add_argument("id")
    f.add_argument("--reason", required=True)
    f.add_argument("--recheck", required=True, metavar="YYYY-MM-DD")
    f.add_argument("--package", help="only for this package")
    f.set_defaults(func=lambda a: _decide(a, "deferred"))

    i = sub.add_parser("ignore", help="mark not affected, with a reason")
    i.add_argument("id")
    i.add_argument("--reason", required=True)
    i.add_argument("--recheck", metavar="YYYY-MM-DD", help="optional date to re-evaluate")
    i.add_argument("--package", help="only for this package")
    i.set_defaults(func=lambda a: _decide(a, "not_affected"))

    v = sub.add_parser("serve", help="local dashboard on http://127.0.0.1")
    v.add_argument("--port", type=int, default=8765)
    v.set_defaults(func=cmd_serve)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 1
    try:
        return args.func(args)
    except state.StateError as e:
        _err(str(e))
        return 2
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
