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
            if not kinds:
                continue
            if here == base:
                if base == Path.home().resolve():
                    # don't propose scanning all of ~ — propose the individual files instead
                    for fn in filenames:
                        k = discovery.classify(here / fn)
                        if k and k not in ("npm-manifest", "dockerfile"):
                            found[here / fn] = {k: 1}
                else:
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


TRIES = 3


def _ask(ask, prompt, default, valid=None, say=print, normalize=lambda a: a):
    """Ask until the answer is valid (or Enter for the default). Never silently swaps a bad answer."""
    for _ in range(TRIES):
        ans = normalize(ask(f"{prompt} [{default}]: ").strip()) or default
        if valid is None or valid(ans):
            return ans
        say(f"   '{ans}' isn't a valid answer — try again")
    say(f"   using the default: {default}")
    return default


def _yes(ask, prompt, default=True, say=print):
    d = "Y/n" if default else "y/N"
    for _ in range(TRIES):
        ans = ask(f"{prompt} [{d}]: ").strip().lower()
        if not ans:
            return default
        if ans in ("y", "yes", "n", "no"):
            return ans in ("y", "yes")
        say("   please answer y or n")
    return default


def _parse_pick(pick, n):
    """'all' | 'none' | '1,3' | '2-4' -> sorted indexes, or None if invalid."""
    pick = pick.strip().lower()
    if pick == "all":
        return list(range(n))
    if pick == "none":
        return []
    out = set()
    for part in pick.replace(" ", "").split(","):
        a, sep, b = part.partition("-")
        if not a.isdigit() or (sep and not b.isdigit()):
            return None
        lo, hi = int(a), int(b) if sep else int(a)
        if not 1 <= lo <= hi <= n:
            return None
        out.update(range(lo - 1, hi))
    return sorted(out)


def _suggested(cands):
    """Pre-select things that are clearly yours: under your home folder, or compose stacks.
    Lockfiles under /opt are usually installed vendor software, not your projects."""
    home = Path.home().resolve()
    picks = []
    for i, (root, kinds) in enumerate(cands):
        if "compose" in kinds or root == home or home in root.parents:
            picks.append(i)
    return picks


def wizard(ask=input, say=print, bases=None):
    """Interactive setup. Returns the saved config."""
    cfg = config.load()
    say("PatchQ setup — about a minute. Press Enter to accept the [default].\n")

    say("1/4  Looking for projects and compose files…")
    cands = find_candidates(bases)
    roots = []
    if cands:
        suggested = _suggested(cands)
        for i, (root, kinds) in enumerate(cands, 1):
            mark = "*" if i - 1 in suggested else " "
            say(f"  {mark}{i}. {root}   ({_describe(kinds)})")
        say("   (* = suggested: your home folder and compose stacks)")
        default = ",".join(str(i + 1) for i in suggested) or "none"
        pick = _ask(ask, "   Scan which? numbers like 1,3 or 2-4, 'all', or 'none'", default,
                    valid=lambda a: _parse_pick(a, len(cands)) is not None, say=say)
        roots = [str(cands[i][0]) for i in _parse_pick(pick, len(cands))]
    else:
        say("   nothing found automatically.")
    while True:
        extra = ask("   Add another folder or file (path, or Enter to continue): ").strip()
        if not extra:
            break
        p = Path(extra).expanduser().resolve()
        if p.exists():
            roots.append(str(p))
            say(f"   added {p}")
        else:
            say(f"   {p} doesn't exist — skipped")
    cfg["roots"] = sorted(set(roots))

    say("\n2/4  Running containers")
    tool, _ = dockerscan._runtime()
    if tool:
        cfg["docker"] = _yes(ask, f"   {tool} found. Scan the containers running on this machine too?", True, say)
        if cfg["docker"] and not shutil.which("trivy"):
            say("   note: " + dockerscan.TRIVY_HELP)
    else:
        say("   no docker/podman found — skipping.")
        cfg["docker"] = False

    say("\n3/4  Automatic scans")
    s = cfg["schedule"]
    s["freq"] = _ask(ask, "   How often? daily / weekly / off", "daily", valid=lambda a: a in config.FREQS,
                     say=say, normalize=str.lower)
    if s["freq"] != "off":
        s["time"] = _ask(ask, "   What time? (24h HH:MM)", s["time"], say=say,
                         valid=lambda a: bool(config._TIME.match(a)))
        if s["freq"] == "weekly":
            s["weekday"] = _ask(ask, "   Which day? Mon Tue Wed Thu Fri Sat Sun", s["weekday"], say=say,
                                normalize=lambda a: a[:3].capitalize(), valid=lambda a: a in config.WEEKDAYS)

    say("\n4/4  Dashboard")
    dash = True
    if service.available():
        dash = _yes(ask, "   Keep the dashboard running in the background (localhost only)?", True, say)
    else:
        say("   background services aren't available on this machine (no systemd user session) — "
            "run `patchq serve` when you want the dashboard.")
    if not cfg["roots"] and not cfg["docker"]:
        say("\n   note: nothing selected to scan — re-run `patchq init` or use `patchq scan <folder>`.")
    config.save(cfg)
    return finish(cfg, dash, say, run_scan=bool(cfg["roots"] or cfg["docker"])
                  and _yes(ask, "\nRun the first scan now?", True, say))


def prune_stale(cfg):
    """Drop stored results for folders / container scans that are no longer configured.
    Decisions (patched / deferred / not affected) are kept."""
    from . import scan as _scan, state
    keep = {str(Path(r).expanduser().resolve()) for r in cfg["roots"]}
    if cfg["docker"]:
        keep.add(_scan.docker_root_key())
    with state.transaction() as data:
        stale = [k for k in data["scans"] if k not in keep]
        for k in stale:
            del data["scans"][k]
    return stale


def finish(cfg, dashboard, say=print, run_scan=True):
    say(f"\nSaved {config.path()}")
    for k in prune_stale(cfg):
        say(f"   removed old results for {k} (no longer in your setup; decisions kept)")
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
