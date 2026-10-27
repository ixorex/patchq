"""One scan run: every target plus (optionally) running containers, under a lock.

Used by `patchq scan`, the scheduled timer, and the dashboard's Scan button, so
all three behave identically and can never run on top of each other.
"""
from __future__ import annotations

from pathlib import Path

from . import config, inventory, state
from .scan import ScanError, scan, scan_docker
from .sources import cache


def configured_targets():
    cfg = config.load()
    return cfg["roots"], cfg["docker"]


def _folder_inventories(targets):
    inv = {}
    for t in targets:
        p = Path(t).expanduser()
        if p.exists():
            inv.update(inventory.load(p if p.is_dir() else p.parent)[0])
    return inv


def run(targets, docker=False, extra_reports=(), offline=False, pull=False, use_nvd=True,
        nvd_max=None, log=None, trigger="cli", wait=False):
    """Return (records, errors). Raises state.Busy if another scan is running (unless wait=True,
    which queues behind it — used by the scheduled timer so a run is never silently skipped)."""
    log = log or (lambda _m: None)
    records, errors = [], []
    with state.scan_lock(blocking=wait):
        started = cache.now_iso()
        covered = set()
        if docker:  # first, so folder scans know which compose images are already covered
            rec = scan_docker(offline=offline, use_nvd=use_nvd, nvd_max=nvd_max,
                              inv=_folder_inventories(targets), log=log)
            covered = {i for s in rec["systems"] for i in s.get("images", [])}
            with state.transaction() as data:
                state.record_scan(data, rec)
            records.append(rec)
            failed = {w for w in rec["warnings"] if w.startswith("trivy failed on ")}
            covered = {i for i in covered if not any(f"trivy failed on {i}:" in w for w in failed)}
        for i, t in enumerate(targets):
            try:
                rec = scan(t, extra_reports=extra_reports if i == 0 else (), offline=offline, pull=pull,
                           use_nvd=use_nvd, nvd_max=nvd_max, log=log, covered_images=covered)
            except ScanError as e:
                errors.append(str(e))
                continue
            with state.transaction() as data:
                state.record_scan(data, rec)
            records.append(rec)
        with state.transaction() as data:
            data["last_run"] = {"started": started, "finished": cache.now_iso(), "trigger": trigger,
                                "targets": list(targets) + (["running containers"] if docker else []),
                                "errors": errors}
    return records, errors
