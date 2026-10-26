"""~/.patchqueue/config.json — what to scan and when. Written by `patchq init`.

    {"roots": ["/home/me/stack"], "docker": true,
     "schedule": {"freq": "daily", "time": "06:30", "weekday": "Mon"},
     "port": 8765}
"""
from __future__ import annotations

import re

from .sources import cache

FREQS = ("daily", "weekly", "off")
WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_TIME = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")

DEFAULT = {"roots": [], "docker": False, "schedule": {"freq": "off", "time": "06:30", "weekday": "Mon"},
           "port": 8765}


class ConfigError(ValueError):
    pass


def path():
    return cache.home() / "config.json"


def exists() -> bool:
    return path().exists()


def load() -> dict:
    raw = cache.read_json(path()) or {}
    cfg = {**DEFAULT, **{k: v for k, v in raw.items() if k in DEFAULT}}
    cfg["schedule"] = {**DEFAULT["schedule"], **(raw.get("schedule") or {})}
    cfg["roots"] = [str(r) for r in cfg.get("roots") or [] if isinstance(r, str)]
    cfg["docker"] = bool(cfg.get("docker"))
    try:
        validate_schedule(cfg["schedule"])
    except ConfigError:
        cfg["schedule"] = dict(DEFAULT["schedule"])
    return cfg


def validate_schedule(s: dict) -> dict:
    if s.get("freq") not in FREQS:
        raise ConfigError(f"schedule must be one of {', '.join(FREQS)}")
    if not _TIME.match(str(s.get("time", ""))):
        raise ConfigError("time must be HH:MM (24h)")
    if s.get("weekday") not in WEEKDAYS:
        raise ConfigError(f"weekday must be one of {', '.join(WEEKDAYS)}")
    return s


def save(cfg: dict) -> None:
    validate_schedule(cfg["schedule"])
    port = int(cfg.get("port") or 8765)
    if not 1024 <= port <= 65535:
        raise ConfigError("port must be 1024-65535")
    cache.write_json(path(), {"roots": list(cfg["roots"]), "docker": bool(cfg["docker"]),
                              "schedule": dict(cfg["schedule"]), "port": port})


def describe_schedule(s: dict) -> str:
    if s["freq"] == "off":
        return "off"
    if s["freq"] == "weekly":
        return f"weekly, {s['weekday']} {s['time']}"
    return f"daily at {s['time']}"
