"""One scan run: every target plus (optionally) running containers, under a lock.

Used by `patchq scan`, the scheduled timer, and the dashboard's Scan button, so
all three behave identically and can never run on top of each other.
"""
from __future__ import annotations

from . import config, state
from .scan import ScanError, scan, scan_docker
from .sources import cache


def configured_targets():
    cfg = config.load()
    return cfg["roots"], cfg["docker"]


def run(targets, docker=False, extra_reports=(), offline=False, pull=False, use_nvd=True,
        nvd_max=None, log=None, trigger="cli"):
    """Return (records, errors). Raises state.Busy if another scan is running."""
    log = log or (lambda _m: None)
    records, errors = [], []
    with state.scan_lock():
        started = cache.now_iso()
        for i, t in enumerate(targets):
            try:
                rec = scan(t, extra_reports=extra_reports if i == 0 else (), offline=offline, pull=pull,
                           use_nvd=use_nvd, nvd_max=nvd_max, log=log)
            except ScanError as e:
                errors.append(str(e))
                continue
            with state.transaction() as data:
                state.record_scan(data, rec)
            records.append(rec)
        if docker:
            inv = state.merged_inventory(state.load())
            rec = scan_docker(offline=offline, use_nvd=use_nvd, nvd_max=nvd_max, inv=inv, log=log)
            with state.transaction() as data:
                state.record_scan(data, rec)
            records.append(rec)
        with state.transaction() as data:
            data["last_run"] = {"started": started, "finished": cache.now_iso(), "trigger": trigger,
                                "targets": list(targets) + (["running containers"] if docker else []),
                                "errors": errors}
    return records, errors
