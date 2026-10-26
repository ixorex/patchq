"""patchq — init / scan / queue / done / defer / ignore / serve / service."""
from __future__ import annotations

import argparse
import json
import sys

from . import DISCLAIMER, __version__, config, group, rank, render, state


def _err(msg):
    print(f"patchq: {msg}", file=sys.stderr)


def _ranked(data):
    return rank.rank(state.merged_items(data), data.get("decisions"), state.merged_inventory(data))


def _show(data, args, title="queue"):
    ranked = _ranked(data)
    scans = list(data["scans"].values())
    if getattr(args, "json", False):
        groups, _ = group.group(ranked)
        slim = []
        for g in groups:
            d = {k: v for k, v in g.items() if k not in ("items", "best")}
            d["ids"] = [i["id"] for i in g["items"]]
            slim.append(d)
        print(json.dumps({"items": ranked, "groups": slim,
                          "sources": state.merged_sources(data),
                          "scans": [{k: s.get(k) for k in ("label", "root", "scanned_at", "warnings")} for s in scans],
                          "disclaimer": DISCLAIMER}, indent=1, default=str))
        return 0
    warnings = [w for s in scans for w in s.get("warnings", [])]
    color = render.use_color()
    if getattr(args, "by_cve", False):
        print(render.render_queue(ranked, scans, state.merged_sources(data), warnings,
                                  color=color, show_all=getattr(args, "all", False), title=title))
    else:
        groups, decided = group.group(ranked)
        print(render.render_grouped(groups, decided, scans, state.merged_sources(data), warnings,
                                    color=color, show_all=getattr(args, "all", False), title=title))
    return 0


def cmd_scan(args):
    from . import runner
    targets = list(args.paths)
    docker = args.docker
    if not targets and not docker:
        if config.exists():
            targets, docker = runner.configured_targets()
            if not targets and not docker:
                _err("config has no folders and docker is off — run `patchq init`, or `patchq scan <folder>`")
                return 1
        else:
            targets = ["."]
    log = (lambda m: None) if args.quiet and not sys.stderr.isatty() else (lambda m: print(f"patchq: {m}", file=sys.stderr))
    try:
        _, errors = runner.run(targets, docker=docker, extra_reports=args.imports, offline=args.offline,
                               pull=args.pull, use_nvd=not args.no_nvd, nvd_max=args.nvd_max, log=log,
                               trigger=args.trigger)
    except state.Busy:
        _err("another scan is already running — try again in a minute")
        return 3
    for e in errors:
        _err(e)
    if errors and len(errors) == len(targets) and not docker:
        return 2
    if args.quiet:
        return 0
    return _show(state.load(), args, title="scan")


def cmd_queue(args):
    data = state.load()
    if not data["scans"]:
        _err("nothing scanned yet — run `patchq init` (guided) or `patchq scan <folder>`")
        return 1
    return _show(data, args)


def _decide(args, status):
    try:
        with state.transaction() as data:
            entry = state.set_decision(data, args.id, status, reason=getattr(args, "reason", None),
                                       recheck=getattr(args, "recheck", None), package=args.package)
            known = state.known_ids(data)
    except ValueError as e:
        _err(str(e))
        return 2
    label = {"patched": "marked patched", "deferred": "deferred", "not_affected": "marked not affected",
             "reopened": "back in the queue"}[status]
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
    port = args.port or config.load()["port"]
    try:
        httpd = web.make_server(port)
    except OSError as e:
        _err(f"can't listen on 127.0.0.1:{port} ({e}) — is the dashboard service already running? "
             "(`patchq service status`) Otherwise try --port")
        return 2
    print(f"PatchQ dashboard: http://127.0.0.1:{httpd.server_address[1]}/  (localhost only; Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


def cmd_init(args):
    from . import init
    if args.yes:
        cfg = config.load()
        if args.path:
            from pathlib import Path
            cfg["roots"] = sorted({str(Path(p).expanduser().resolve()) for p in args.path})
        cfg["docker"] = args.docker
        cfg["schedule"]["freq"] = args.schedule
        cfg["schedule"]["time"] = args.time
        cfg["schedule"]["weekday"] = args.weekday
        try:
            config.save(cfg)
        except config.ConfigError as e:
            _err(str(e))
            return 2
        init.finish(cfg, dashboard=not args.no_service, run_scan=not args.no_scan)
        return 0
    try:
        init.wizard()
    except (KeyboardInterrupt, EOFError):
        print("\nsetup cancelled — nothing changed")
        return 1
    return 0


def cmd_service(args):
    from . import service
    cfg = config.load()
    if args.action == "install":
        msgs = service.install(cfg, dashboard=not args.no_dashboard)
    elif args.action == "uninstall":
        msgs = service.uninstall()
    else:
        st = service.status()
        if not st["available"]:
            msgs = ["systemd user services aren't available on this machine"]
            line = service.cron_line(cfg)
            if line:
                msgs.append(f"cron equivalent: {line}")
        else:
            msgs = [f"dashboard: {st['dashboard']} (http://127.0.0.1:{cfg['port']})",
                    f"scan timer: {st['timer']} — {config.describe_schedule(cfg['schedule'])}",
                    f"next scan: {st['next'] or '—'}"]
    for m in msgs:
        print(m)
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="patchq", description="One ranked patch queue for your stack: "
                                "Patch Today / This Week / Watching. New here? Run `patchq init`.",
                                epilog=DISCLAIMER)
    p.add_argument("--version", action="version", version=f"patchq {__version__}")
    sub = p.add_subparsers(dest="cmd", metavar="command")

    n = sub.add_parser("init", help="guided setup: pick folders, containers, schedule, dashboard")
    n.add_argument("--yes", action="store_true", help="non-interactive: use the flags below")
    n.add_argument("--path", action="append", default=[], help="folder to scan (repeatable, with --yes)")
    n.add_argument("--docker", action="store_true", help="also scan running containers (with --yes)")
    n.add_argument("--schedule", choices=config.FREQS, default="daily")
    n.add_argument("--time", default="06:30", metavar="HH:MM")
    n.add_argument("--weekday", choices=config.WEEKDAYS, default="Mon")
    n.add_argument("--no-service", action="store_true", help="don't keep the dashboard running")
    n.add_argument("--no-scan", action="store_true", help="don't run the first scan")
    n.set_defaults(func=cmd_init)

    s = sub.add_parser("scan", help="scan folders/repos (default: what `patchq init` set up)")
    s.add_argument("paths", nargs="*", help="folder, file, or https/ssh git URL")
    s.add_argument("--docker", action="store_true", help="also scan running containers (needs trivy)")
    s.add_argument("--import", dest="imports", action="append", default=[], metavar="FILE",
                   help="Trivy / Grype / OSV-Scanner JSON report to include (repeatable)")
    s.add_argument("--pull", action="store_true", help="git pull --ff-only before scanning a local repo")
    s.add_argument("--offline", action="store_true", help="use cached feed data only; no network")
    s.add_argument("--no-nvd", action="store_true", help="skip NVD lookups (CVSS shows as pending if missing)")
    s.add_argument("--nvd-max", type=int, default=None, metavar="N", help="max NVD lookups this run")
    s.add_argument("--quiet", action="store_true", help="don't print the queue (for timers/cron)")
    s.add_argument("--trigger", default="cli", help=argparse.SUPPRESS)
    s.add_argument("--all", action="store_true", help="expand Watching items")
    s.add_argument("--by-cve", action="store_true", help="one line per CVE instead of per package")
    s.add_argument("--json", action="store_true", help="machine-readable output")
    s.set_defaults(func=cmd_scan)

    q = sub.add_parser("queue", help="show the queue (grouped by package)")
    q.add_argument("--all", action="store_true", help="expand Watching and decision history")
    q.add_argument("--by-cve", action="store_true", help="one line per CVE instead of per package")
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

    r = sub.add_parser("reopen", help="put a deferred / not-affected item back in the queue")
    r.add_argument("id")
    r.add_argument("--reason", default="reopened")
    r.add_argument("--package", help="only for this package")
    r.set_defaults(func=lambda a: _decide(a, "reopened"))

    v = sub.add_parser("serve", help="dashboard on http://127.0.0.1 (foreground)")
    v.add_argument("--port", type=int, default=None)
    v.set_defaults(func=cmd_serve)

    sv = sub.add_parser("service", help="background dashboard + scheduled scans (systemd --user)")
    sv.add_argument("action", choices=("install", "uninstall", "status"))
    sv.add_argument("--no-dashboard", action="store_true", help="install only the scan timer")
    sv.set_defaults(func=cmd_service)
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
