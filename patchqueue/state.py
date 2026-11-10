"""~/.patchqueue/queue.json — scans and your decisions (patched / deferred / not-affected).

(Named state.py rather than queue.py so it can never shadow Python's stdlib `queue`.)

Every decision keeps its full history, so six months from now
`patchq queue --all` can still answer "why did we ignore this?".
"""
from __future__ import annotations

import contextlib
import datetime as dt
import json

from . import model
from .sources import cache

SCHEMA = 1
STATUSES = ("patched", "deferred", "not_affected", "reopened")  # reopened = back in the queue, history kept


class StateError(RuntimeError):
    pass


def path():
    return cache.home() / "queue.json"


MAX_BYTES = 50 * 1024 * 1024  # same cap as parsers/base.py read_text


def load() -> dict:
    p = path()
    if not p.exists():
        return {"schema": SCHEMA, "scans": {}, "decisions": {}}
    try:
        if p.stat().st_size > MAX_BYTES:
            raise StateError(f"{p} is larger than {MAX_BYTES // (1024 * 1024)} MB — refusing to load it. "
                             "Fix or move it; PatchQ won't overwrite it.")
        with open(p, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError, RecursionError) as e:
        # Never overwrite a file we can't read: it holds the user's decisions.
        raise StateError(f"{p} is unreadable ({e}). Fix or move it; PatchQ won't overwrite it.")
    if not isinstance(data, dict):
        raise StateError(f"{p} is not a JSON object. Fix or move it; PatchQ won't overwrite it.")
    data.setdefault("scans", {})
    data.setdefault("decisions", {})
    if not isinstance(data["scans"], dict) or not isinstance(data["decisions"], dict):
        raise StateError(f"{p} has a malformed 'scans' or 'decisions' section (not an object). "
                         "Fix or move it; PatchQ won't overwrite it.")
    data["schema"] = SCHEMA
    return data


def save(data: dict) -> None:
    cache.write_json(path(), data)


try:  # POSIX file locks; on Windows we fall back to no locking (single-user tool)
    import fcntl as _fcntl
except ImportError:  # pragma: no cover
    _fcntl = None


@contextlib.contextmanager
def _flock(name: str, blocking: bool = True):
    p = cache.home() / name
    fh = open(p, "a+")
    try:
        if _fcntl is not None:
            flags = _fcntl.LOCK_EX | (0 if blocking else _fcntl.LOCK_NB)
            try:
                _fcntl.flock(fh, flags)
            except BlockingIOError:
                raise Busy()
        yield
    finally:
        if _fcntl is not None:
            try:
                _fcntl.flock(fh, _fcntl.LOCK_UN)
            except OSError:
                pass
        fh.close()


class Busy(RuntimeError):
    """Another scan is already running."""


@contextlib.contextmanager
def transaction():
    """Load -> modify -> save under a lock, so the timer, the dashboard and the CLI
    never overwrite each other's decisions."""
    with _flock(".queue.lock"):
        data = load()
        yield data
        save(data)


def scan_lock(blocking: bool = False):
    """Held for the whole duration of a scan run. Raises Busy if one is running."""
    return _flock(".scan.lock", blocking=blocking)


def record_scan(data: dict, rec: dict) -> None:
    data["scans"][rec["root"]] = rec


def set_decision(data, vuln_id, status, reason=None, recheck=None, package=None, today=None):
    if status not in STATUSES:
        raise ValueError(f"unknown status {status}")
    if not model.ID_RE.match(vuln_id or ""):
        raise ValueError(f"{vuln_id!r} doesn't look like a vulnerability ID (CVE-…, GHSA-…, PYSEC-…)")
    if recheck:
        try:
            rc = dt.date.fromisoformat(recheck)
        except ValueError:
            raise ValueError(f"--recheck must be YYYY-MM-DD, got {recheck!r}")
        today = today or dt.date.today()
        if rc <= today:
            raise ValueError(f"--recheck {recheck} must be in the future")
    key = vuln_id.upper()
    entry = {"status": status, "reason": reason or "", "recheck": recheck, "package": package,
             "at": cache.now_iso()}
    prev = data["decisions"].get(key)
    history = list((prev or {}).get("history") or [])
    if prev:
        history.append({k: prev.get(k) for k in ("status", "reason", "recheck", "package", "at")})
    entry["history"] = history
    data["decisions"][key] = entry
    return entry


def merged_items(data):
    items = []
    for rec in data["scans"].values():
        items += rec.get("items") or []
    return model.merge_findings(items)


def merged_inventory(data):
    from . import inventory
    inv = dict(inventory.load_global()[0])  # edits to the global file apply without a rescan
    for rec in data["scans"].values():
        inv.update(rec.get("inventory") or {})
    return inv


def known_ids(data):
    ids = set()
    for it in merged_items(data):
        ids.add(it["id"].upper())
        ids.update(a.upper() for a in it.get("aliases", []))
    return ids


def merged_sources(data):
    """Worst-case view across scans: oldest data, any error."""
    out = {}
    for rec in data["scans"].values():
        for name, s in (rec.get("sources") or {}).items():
            cur = out.get(name)
            if cur is None:
                out[name] = dict(s)
                continue
            if s.get("as_of") and (not cur.get("as_of") or s["as_of"] < cur["as_of"]):
                cur["as_of"] = s["as_of"]
            cur["error"] = cur.get("error") or s.get("error")
            cur["unchecked"] = (cur.get("unchecked") or 0) + (s.get("unchecked") or 0)
            cur["note"] = cur.get("note") or s.get("note")
            cur["live"] = cur.get("live") or s.get("live")
    return out
