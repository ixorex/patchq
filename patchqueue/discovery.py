"""Walk a folder and find everything PatchQ can scan — and everything it can't.

Rule: nothing is skipped silently. Unsupported lockfiles are reported with
what to do instead.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .parsers.python import is_requirements_name

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", ".venv", "venv", "__pycache__",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages", ".cache",
    "dist", "build", ".next", ".nuxt", ".terraform", ".idea", ".vscode", ".patchqueue",
}

UNSUPPORTED = {
    "yarn.lock": "Yarn lockfiles aren't parsed in v1 — run `osv-scanner --format json -L yarn.lock > osv-scanner.json` and PatchQ will import it",
    "pnpm-lock.yaml": "pnpm lockfiles aren't parsed in v1 — run `osv-scanner --format json -L pnpm-lock.yaml > osv-scanner.json` and PatchQ will import it",
    "uv.lock": "uv.lock isn't parsed in v1 — run `uv export --format requirements-txt > requirements.lock.txt`",
    "go.sum": "Go isn't supported in v1 — run `osv-scanner --format json -L go.mod > osv-scanner.json` and PatchQ will import it",
    "cargo.lock": "Rust isn't supported in v1 — run `osv-scanner --format json -L Cargo.lock > osv-scanner.json` and PatchQ will import it",
    "gemfile.lock": "Ruby isn't supported in v1 — use osv-scanner JSON and PatchQ will import it",
    "composer.lock": "PHP isn't supported in v1 — use osv-scanner JSON and PatchQ will import it",
    "pom.xml": "Maven isn't supported in v1 — use Trivy/osv-scanner JSON and PatchQ will import it",
    "pipfile": "Pipfile without Pipfile.lock: installed versions unknown — run `pipenv lock`",
}

REPORT_HINTS = ("trivy", "grype", "osv-scanner", "osv_scanner", "osvscanner")


@dataclass
class Found:
    path: Path
    kind: str


@dataclass
class Discovery:
    files: list = field(default_factory=list)        # [Found]
    reports: list = field(default_factory=list)      # [Path] scanner JSON to import
    unsupported: list = field(default_factory=list)  # [(Path, reason)]
    errors: list = field(default_factory=list)       # [str]


def classify(path: Path):
    n = path.name
    low = n.lower()
    if low in ("package-lock.json", "npm-shrinkwrap.json"):
        return "npm-lock"
    if low == "package.json":
        return "npm-manifest"
    if is_requirements_name(path):
        return "requirements"
    if low == "poetry.lock":
        return "poetry"
    if low == "pipfile.lock":
        return "pipenv"
    if low.endswith((".yml", ".yaml")) and (low.startswith("docker-compose") or low.startswith("compose")):
        return "compose"
    if low == "dockerfile" or low.startswith("dockerfile.") or low.endswith(".dockerfile"):
        return "dockerfile"
    if low.endswith(".json") and any(h in low for h in REPORT_HINTS):
        return "report"
    return None


def _looks_like_report(path: Path) -> bool:
    try:
        if path.stat().st_size > 200 * 1024 * 1024:
            return False
        with open(path, "rb") as fh:
            head = fh.read(4096).decode("utf-8", "replace")
    except OSError:
        return False
    return any(k in head for k in ('"SchemaVersion"', '"matches"', '"results"', '"Results"'))


def discover(root: Path) -> Discovery:
    root = Path(root)
    d = Discovery()
    if root.is_file():
        kind = classify(root)
        if kind == "report":
            d.reports.append(root)
        elif kind:
            d.files.append(Found(root, kind))
        else:
            d.unsupported.append((root, "not a file type PatchQ v1 understands"))
        return d

    real_root = root.resolve()

    def onerror(err):
        d.errors.append(f"can't read {err.filename}: {err.strerror}")

    for dirpath, dirnames, filenames in os.walk(root, onerror=onerror, followlinks=False):
        dirnames[:] = sorted(x for x in dirnames if x not in SKIP_DIRS and not x.endswith(".egg-info"))
        here = Path(dirpath)
        lower = {f.lower() for f in filenames}
        for fn in sorted(filenames):
            p = here / fn
            kind = classify(p)
            if kind and p.is_symlink():
                try:
                    p.resolve().relative_to(real_root)
                except (ValueError, OSError):
                    d.unsupported.append((p, "symlink points outside the scanned folder — skipped for safety"))
                    continue
            low = fn.lower()
            if kind == "npm-manifest" and ({"package-lock.json", "npm-shrinkwrap.json"} & lower):
                continue  # the lockfile next to it is authoritative
            if kind == "npm-manifest" and ({"yarn.lock", "pnpm-lock.yaml"} & lower):
                continue  # reported via the unsupported lockfile instead
            if kind == "report":
                if _looks_like_report(p):
                    d.reports.append(p)
                continue
            if kind:
                d.files.append(Found(p, kind))
            elif low in UNSUPPORTED:
                if low == "pipfile" and "pipfile.lock" in lower:
                    continue
                d.unsupported.append((p, UNSUPPORTED[low]))
            elif low == "pyproject.toml" and not ({"poetry.lock", "uv.lock", "pipfile.lock"} & lower) \
                    and not any(is_requirements_name(here / f) for f in filenames):
                d.unsupported.append((p, "pyproject.toml without a lockfile: installed versions unknown — "
                                         "run `poetry lock`, or `pip freeze > requirements.lock.txt`"))
    return d


MAX_REPORT_BYTES = 50 * 1024 * 1024  # same cap as parsers/base.py read_text


def sniff_report(path: Path):
    """Return 'trivy' | 'grype' | 'osv-scanner' | None for a parsed JSON file."""
    try:
        if path.stat().st_size > MAX_REPORT_BYTES:
            return None, None
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError, RecursionError):
        return None, None
    if isinstance(data, dict):
        if "SchemaVersion" in data and ("Results" in data or "ArtifactName" in data):
            return "trivy", data
        if "matches" in data and ("descriptor" in data or "source" in data):
            return "grype", data
        if isinstance(data.get("results"), list):
            return "osv-scanner", data
    return None, data
