"""Background services via systemd --user: an always-on dashboard and a scan timer.

No root needed. Units live in ~/.config/systemd/user/. Where systemd isn't
available (macOS, WSL without systemd, containers) we print a cron line instead.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import config

SERVE = "patchq-serve.service"
SCAN = "patchq-scan.service"
TIMER = "patchq-scan.timer"


def unit_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / "systemd" / "user"


def _run(args, timeout=30):
    """Single choke point for subprocess calls (mocked in tests)."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)


def available() -> bool:
    if not shutil.which("systemctl"):
        return False
    code, _ = _run(["systemctl", "--user", "show-environment"])
    return code == 0


def _q(arg: str) -> str:
    # systemd ExecStart quoting: double-quote anything with spaces or quotes
    if any(c in arg for c in ' "\\\'$%;'):
        return '"' + arg.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'
    return arg


def _exec(*args) -> str:
    if any(c in sys.executable for c in "\n\r\x00"):
        raise ServiceError("python path contains a newline — refusing to write a unit file")
    return " ".join(_q(a) for a in [sys.executable, "-m", "patchqueue", *args])


class ServiceError(ValueError):
    pass


def _env_lines() -> str:
    home = os.environ.get("PATCHQ_HOME")
    if not home:
        return ""
    if any(c in home for c in "\n\r\x00"):
        raise ServiceError("PATCHQ_HOME contains a newline — refusing to write a unit file")
    val = ("PATCHQ_HOME=" + home).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    return f'Environment="{val}"\n'


def on_calendar(s: dict) -> str:
    hh, mm = s["time"].split(":")
    day = f"{s['weekday']} " if s["freq"] == "weekly" else ""
    return f"{day}*-*-* {hh}:{mm}:00"


def units(cfg: dict) -> dict:
    return {
        SERVE: ("[Unit]\nDescription=PatchQ dashboard (127.0.0.1 only)\n\n[Service]\n" + _env_lines()
                + f"ExecStart={_exec('serve', '--port', str(cfg['port']))}\nRestart=on-failure\nRestartSec=5\n\n"
                "[Install]\nWantedBy=default.target\n"),
        SCAN: ("[Unit]\nDescription=PatchQ scheduled scan\n\n[Service]\nType=oneshot\n" + _env_lines()
               + f"ExecStart={_exec('scan', '--quiet', '--trigger', 'timer')}\nNice=10\n"),
        TIMER: ("[Unit]\nDescription=PatchQ scan schedule\n\n[Timer]\n"
                f"OnCalendar={on_calendar(cfg['schedule'])}\nPersistent=true\nRandomizedDelaySec=120\n\n"
                "[Install]\nWantedBy=timers.target\n"),
    }


def cron_line(cfg: dict) -> str:
    s = cfg["schedule"]
    if s["freq"] == "off":
        return ""
    hh, mm = s["time"].split(":")
    dow = "*" if s["freq"] == "daily" else str(config.WEEKDAYS.index(s["weekday"]) + 1)
    return f"{int(mm)} {int(hh)} * * {dow} {_exec('scan', '--quiet', '--trigger', 'timer')}"


def install(cfg: dict, dashboard: bool = True) -> list:
    """Write units, enable what's wanted. Returns human-readable messages."""
    if not available():
        msgs = ["systemd user services aren't available here, so nothing runs in the background."]
        line = cron_line(cfg)
        if line:
            msgs.append(f"For scheduled scans add this with `crontab -e`:\n    {line}")
        msgs.append("Start the dashboard when you need it: `patchq serve`")
        return msgs
    d = unit_dir()
    d.mkdir(parents=True, exist_ok=True)
    for name, text in units(cfg).items():
        (d / name).write_text(text, encoding="utf-8")
    msgs = []
    _run(["systemctl", "--user", "daemon-reload"])
    if dashboard:
        code, out = _run(["systemctl", "--user", "enable", "--now", SERVE])
        _run(["systemctl", "--user", "restart", SERVE])
        msgs.append(f"dashboard service: {'on' if code == 0 else 'FAILED — ' + out.strip()[:200]}"
                    + (f" at http://127.0.0.1:{cfg['port']}" if code == 0 else ""))
    else:
        _run(["systemctl", "--user", "disable", "--now", SERVE])
        msgs.append("dashboard service: off (start it with `patchq serve` when you need it)")
    msgs += set_schedule(cfg)
    code, out = _run(["loginctl", "enable-linger", os.environ.get("USER", "")])
    if code != 0:
        msgs.append(f"to keep these running while you're logged out, run once: sudo loginctl enable-linger {os.environ.get('USER', '$USER')}")
    return msgs


def set_schedule(cfg: dict) -> list:
    if not available():
        line = cron_line(cfg)
        return [f"systemd not available — use cron instead: {line}" if line else "schedule off"]
    d = unit_dir()
    d.mkdir(parents=True, exist_ok=True)
    u = units(cfg)
    (d / SCAN).write_text(u[SCAN], encoding="utf-8")
    (d / TIMER).write_text(u[TIMER], encoding="utf-8")
    _run(["systemctl", "--user", "daemon-reload"])
    if cfg["schedule"]["freq"] == "off":
        _run(["systemctl", "--user", "disable", "--now", TIMER])
        return ["scheduled scans: off"]
    code, out = _run(["systemctl", "--user", "enable", "--now", TIMER])
    _run(["systemctl", "--user", "restart", TIMER])
    return [f"scheduled scans: {config.describe_schedule(cfg['schedule'])}"
            + ("" if code == 0 else f" — FAILED: {out.strip()[:200]}")]


def uninstall() -> list:
    msgs = []
    if available():
        _run(["systemctl", "--user", "disable", "--now", SERVE, TIMER])
    for name in (SERVE, SCAN, TIMER):
        p = unit_dir() / name
        if p.exists():
            p.unlink()
            msgs.append(f"removed {p}")
    if available():
        _run(["systemctl", "--user", "daemon-reload"])
    return msgs or ["nothing installed"]


def status() -> dict:
    if not available():
        return {"available": False, "dashboard": None, "timer": None, "next": None}
    _, dash = _run(["systemctl", "--user", "is-active", SERVE])
    _, timer = _run(["systemctl", "--user", "is-enabled", TIMER])
    _, nxt = _run(["systemctl", "--user", "list-timers", TIMER, "--no-legend", "--no-pager"])
    return {"available": True, "dashboard": dash.strip().splitlines()[0] if dash.strip() else "unknown",
            "timer": timer.strip().splitlines()[0] if timer.strip() else "unknown",
            "next": " ".join(nxt.split()[:3]) if nxt.strip() else None}
