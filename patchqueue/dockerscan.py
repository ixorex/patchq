"""Running containers -> image list -> Trivy reports.

PatchQ never re-implements image scanning: it asks Docker (or Podman) what's
running and asks Trivy to scan those images. Everything is called with argument
lists (no shell), image names are validated, and reports are cached for 24h.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess

from .sources import cache

TTL = 24 * 3600
TRIVY_TIMEOUT = 900
_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,250}$")

TRIVY_HELP = ("Trivy isn't installed, so container images can't be checked. Install it: "
              "Debian/Ubuntu/Kali `sudo apt install trivy` (Kali ships it; on Debian/Ubuntu add the Aqua "
              "repo first — see https://trivy.dev), macOS `brew install trivy`. Then re-run the scan.")


def _runtime():
    for tool in ("docker", "podman"):
        path = shutil.which(tool)
        if path:
            return tool, path
    return None, None


def running_containers():
    """Return ([{name, image, published}], warnings)."""
    tool, path = _runtime()
    if not tool:
        return [], ["--docker: neither docker nor podman was found on this machine"]
    try:
        p = subprocess.run([path, "ps", "--format", "{{json .}}"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        return [], [f"--docker: couldn't run `{tool} ps` ({e})"]
    if p.returncode != 0:
        err = (p.stderr or "").strip()
        if "permission denied" in err.lower():
            return [], [f"--docker: no permission to talk to {tool}. Fix: `sudo usermod -aG docker $USER`, "
                        "then log out and back in (or reboot)."]
        return [], [f"--docker: `{tool} ps` failed: {err[:300]}"]
    out, warnings = [], []
    for line in p.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        image = str(row.get("Image") or "")
        name = str(row.get("Names") or row.get("Name") or "").split(",")[0].strip()
        if isinstance(row.get("Names"), list):
            name = str(row["Names"][0]) if row["Names"] else ""
        if not _IMAGE.match(image):
            warnings.append(f"--docker: skipped container {name!r}: unusual image reference")
            continue
        ports = row.get("Ports")
        published = bool(ports) and "->" in str(ports)
        out.append({"name": name or image, "image": image, "published": published})
    if not out:
        warnings.append(f"--docker: no running containers ({tool} ps returned nothing)")
    return out, warnings


def report_path(image: str):
    h = hashlib.sha256(image.encode()).hexdigest()[:12]
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", image)[:60]
    return cache.cache_dir("trivy") / f"trivy-{safe}-{h}.json"


def trivy_reports(images, offline=False, log=None):
    """Return ({image: report_path}, warnings). Reuses reports younger than 24h."""
    log = log or (lambda _m: None)
    trivy = shutil.which("trivy")
    reports, warnings = {}, []
    todo = []
    for img in images:
        rp = report_path(img)
        fresh = rp.exists() and cache.age_seconds(_mtime_iso(rp)) < TTL
        if fresh or (offline and rp.exists()):
            reports[img] = rp
        else:
            todo.append((img, rp))
    if not todo:
        return reports, warnings
    if offline:
        warnings.append(f"offline: {len(todo)} image(s) have no cached Trivy report and were NOT checked")
        return reports, warnings
    if not trivy:
        return reports, [TRIVY_HELP]
    for n, (img, rp) in enumerate(todo, 1):
        log(f"trivy {n}/{len(todo)}: {img} (first run downloads Trivy's database — can take a few minutes)")
        tmp = rp.with_suffix(".part")
        try:
            p = subprocess.run([trivy, "image", "--quiet", "--format", "json", "--output", str(tmp),
                                "--timeout", "10m", img],
                               capture_output=True, text=True, timeout=TRIVY_TIMEOUT)
        except (OSError, subprocess.TimeoutExpired) as e:
            warnings.append(f"trivy failed on {img}: {e}")
            continue
        if p.returncode != 0 or not tmp.exists():
            warnings.append(f"trivy failed on {img}: {(p.stderr or '').strip()[:300]}")
            continue
        os.chmod(tmp, 0o600)
        os.replace(tmp, rp)
        reports[img] = rp
    return reports, warnings


def _mtime_iso(path):
    import datetime as dt
    return dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc).replace(microsecond=0).isoformat()
