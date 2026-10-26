"""`patchq init` — one-time guided setup.

Finds folders worth scanning, asks a few questions, saves ~/.patchqueue/config.json,
installs the background services, and runs the first scan.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from . import config, discovery, dockerscan, service

SKIP = discovery.SKIP_DIRS | {"tests", "test", "fixtures", "examples", "snap", "go", ".local", ".cargo",
                               ".rustup", ".npm", ".nvm", ".pyenv", ".mozilla", ".config", "Downloads"}


def default_bases():
    return [Path.home(), Path("/opt"), Path("/srv")]


def find_candidates(bases=None, max_depth=4):
    """Return [(root, {kind: count})] — one proposed root per top-level folder that has something to scan."""
    bases = [Path(b) for b in (bases or default_bases()) if Path(b).is_dir()]
    found = {}
    for base in bases:
        base = base.resolve()
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False, onerror=lambda e: None):
            here = Path(dirpath)
            depth = len(here.relative_to(base).parts)
            dirnames[:] = sorted(d for d in dirnames
                                 if d not in SKIP and not d.startswith(".") and depth < max_depth)
            kinds = {}
            for fn in filenames:
                k = discovery.classify(here / fn)
                if k and k not in ("npm-manifest", "dockerfile"):
                    kinds[k] = kinds.get(k, 0) + 1
            if not kinds or here == base:
                if kinds and here == base and base != Path.home().resolve():
                    found.setdefault(here, {}).update(kinds)
                continue
            rel = here.relative_to(base)
            root = base / rel.parts[0]
            agg = found.setdefault(root, {})
            for k, v in kinds.items():
                agg[k] = agg.get(k, 0) + v
    return sorted(found.items(), key=lambda kv: str(kv[0]))


_KIND_LABEL = {"npm-lock": "npm", "requirements": "requirements", "poetry": "poetry", "pipenv": "pipenv",
               "compose": "compose", "report": "scanner report"}


def _describe(kinds):
    return ", ".join(f"{v} {_KIND_LABEL.get(k, k)}" for k, v in sorted(kinds.items()))


def _ask(ask, prompt, default):
    ans = ask(f"{prompt} [{default}]: ").strip()
    return ans or default


def _yes(ask, prompt, default=True):
    d = "Y/n" if default else "y/N"
    ans = ask(f"{prompt} [{d}]: ").strip().lower()
    return default if not ans else ans in ("y", "yes")


def wizard(ask=input, say=print, bases=None):
    """Interactive setup. Returns the saved config."""
    cfg = config.load()
    say("PatchQ setup — about a minute. Press Enter to accept the [default].\n")

    say("1/4  Looking for projects and compose files…")
    cands = find_candidates(bases)
    roots = []
    if cands:
        for i, (root, kinds) in enumerate(cands, 1):
            say(f"   {i}. {root}   ({_describe(kinds)})")
        pick = _ask(ask, "   Scan which? 'all', numbers like 1,3, or 'none'", "all").lower()
        if pick == "all":
            roots = [str(r) for r, _ in cands]
        elif pick != "none":
            for part in pick.replace(" ", "").split(","):
                if part.isdigit() and 1 <= int(part) <= len(cands):
                    roots.append(str(cands[int(part) - 1][0]))
    else:
        say("   nothing found automatically.")
    while True:
        extra = ask("   Add another folder (path, or Enter to continue): ").strip()
        if not extra:
            break
        p = Path(extra).expanduser().resolve()
        if p.is_dir():
            roots.append(str(p))
        else:
            say(f"   {p} isn't a folder — skipped")
    cfg["roots"] = sorted(set(roots))

    say("\n2/4  Running containers")
    tool, _ = dockerscan._runtime()
    if tool:
        cfg["docker"] = _yes(ask, f"   {tool} found. Scan the containers running on this machine too?", True)
        if cfg["docker"] and not shutil.which("trivy"):
            say("   note: " + dockerscan.TRIVY_HELP)
    else:
        say("   no docker/podman found — skipping.")
        cfg["docker"] = False

    say("\n3/4  Automatic scans")
    freq = _ask(ask, "   How often? daily / weekly / off", "daily").lower()
    cfg["schedule"]["freq"] = freq if freq in config.FREQS else "daily"
    if cfg["schedule"]["freq"] != "off":
        cfg["schedule"]["time"] = _ask(ask, "   What time? (24h HH:MM)", cfg["schedule"]["time"])
        if cfg["schedule"]["freq"] == "weekly":
            day = _ask(ask, "   Which day? Mon-Sun", cfg["schedule"]["weekday"]).capitalize()[:3]
            cfg["schedule"]["weekday"] = day if day in config.WEEKDAYS else "Mon"
    try:
        config.validate_schedule(cfg["schedule"])
    except config.ConfigError as e:
        say(f"   {e} — using 06:30")
        cfg["schedule"]["time"] = "06:30"

    say("\n4/4  Dashboard")
    dash = True
    if service.available():
        dash = _yes(ask, "   Keep the dashboard running in the background (localhost only)?", True)
    config.save(cfg)
    return finish(cfg, dash, say, run_scan=_yes(ask, "\nRun the first scan now?", True))


def finish(cfg, dashboard, say=print, run_scan=True):
    say(f"\nSaved {config.path()}")
    say(f"   folders: {', '.join(cfg['roots']) or '(none)'}")
    say(f"   running containers: {'yes' if cfg['docker'] else 'no'}")
    for m in service.install(cfg, dashboard=dashboard):
        say("   " + m)
    if run_scan:
        from . import runner, state
        say("\nScanning… (first run downloads the vulnerability feeds; can take a minute)")
        try:
            _, errors = runner.run(cfg["roots"], docker=cfg["docker"], log=lambda m: say("   " + m), trigger="init")
            for e in errors:
                say(f"   error: {e}")
        except state.Busy:
            say("   a scan is already running — it'll show up on the dashboard when done")
    say("\nDone. Next:")
    say("   patchq queue            see what to patch")
    say(f"   dashboard              http://127.0.0.1:{cfg['port']}"
        + ("" if dashboard and service.available() else "  (run `patchq serve` first)"))
    say(f"   from another computer  ssh -N -L {cfg['port']}:127.0.0.1:{cfg['port']} <user>@<this-host>")
    say("   patchq init             re-run any time to change these settings")
    return cfg
