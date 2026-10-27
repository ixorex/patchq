"""~/.patchqueue/ storage: atomic JSON writes, private permissions, source status."""
from __future__ import annotations

import datetime as dt
import json
import os
import tempfile
from pathlib import Path


def home() -> Path:
    p = Path(os.environ.get("PATCHQ_HOME") or "~/.patchqueue").expanduser()
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    return p


def cache_dir(*parts) -> Path:
    p = home().joinpath("cache", *parts)
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    return p


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def utc_today() -> str:
    return dt.datetime.now(dt.timezone.utc).date().isoformat()


def age_seconds(iso: str) -> float:
    try:
        then = dt.datetime.fromisoformat(iso)
    except (TypeError, ValueError):
        return float("inf")
    if then.tzinfo is None:
        then = then.replace(tzinfo=dt.timezone.utc)
    return (dt.datetime.now(dt.timezone.utc) - then).total_seconds()


def read_json(path: Path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError, RecursionError):
        return None


def write_json(path: Path, obj) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=1, sort_keys=False)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class Status:
    """What one feed contributed to this run. Rendered as the 'data as of' line."""

    def __init__(self, name: str):
        self.name = name
        self.as_of = None       # oldest data used (ISO UTC)
        self.live = False       # fetched something from the network this run
        self.error = None       # what went wrong, if anything
        self.unchecked = 0      # items that got no data at all
        self.note = None

    def used(self, iso: str):
        if iso and (self.as_of is None or iso < self.as_of):
            self.as_of = iso

    def to_dict(self):
        return {"name": self.name, "as_of": self.as_of, "live": self.live, "error": self.error,
                "unchecked": self.unchecked, "note": self.note}
