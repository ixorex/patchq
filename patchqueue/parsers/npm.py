"""npm: package-lock.json / npm-shrinkwrap.json (v1, v2, v3) and package.json."""
from __future__ import annotations

import json
import re

from .base import ParseResult, read_text

_DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
_REGISTRY_VER = re.compile(r"^\d+\.\d+\.\d+")


def _manifest_direct(dirpath):
    try:
        data = json.loads(read_text(dirpath / "package.json"))
    except (OSError, ValueError, RecursionError):
        return None
    names = set()
    for sec in _DEP_SECTIONS:
        if isinstance(data.get(sec), dict):
            names |= set(data[sec])
    return names


def parse_lock(path) -> ParseResult:
    res = ParseResult()
    data = json.loads(read_text(path))
    if not isinstance(data, dict):
        raise ValueError("not a JSON object")
    found = {}
    skipped = []

    def add(name, ver, direct, dev):
        if not isinstance(ver, str) or not _REGISTRY_VER.match(ver):
            skipped.append(f"{name}@{ver}")
            return
        k = (name, ver)
        if k in found:
            found[k]["direct"] = found[k]["direct"] or direct
            found[k]["dev"] = found[k]["dev"] and dev
        else:
            found[k] = {"name": name, "version": ver, "ecosystem": "npm", "direct": direct, "dev": dev}

    pkgs = data.get("packages")
    if isinstance(pkgs, dict) and pkgs:  # lockfileVersion 2 / 3
        root = pkgs.get("") or {}
        direct = set()
        for sec in _DEP_SECTIONS:
            if isinstance(root.get(sec), dict):
                direct |= set(root[sec])
        if not direct:
            direct = _manifest_direct(path.parent) or set()
        for p, meta in pkgs.items():
            if not p or not isinstance(meta, dict) or meta.get("link"):
                continue
            if "node_modules/" not in p:
                continue  # workspace source folders, not installed packages
            name = meta.get("name") or p.rsplit("node_modules/", 1)[1]
            top = p == f"node_modules/{name}"
            add(name, meta.get("version"), top and name in direct,
                bool(meta.get("dev") or meta.get("devOptional")))
    elif isinstance(data.get("dependencies"), dict):  # lockfileVersion 1
        direct = _manifest_direct(path.parent)

        def walk(deps, depth):
            for name, meta in deps.items():
                if not isinstance(meta, dict):
                    continue
                is_direct = depth == 0 and (direct is None or name in direct)
                add(name, meta.get("version"), is_direct, bool(meta.get("dev")))
                if isinstance(meta.get("dependencies"), dict):
                    walk(meta["dependencies"], depth + 1)

        walk(data["dependencies"], 0)
    else:
        res.warnings.append("lockfile has no packages — nothing to scan (run npm install?)")

    res.packages = list(found.values())
    if skipped:
        res.warnings.append(f"{len(skipped)} non-registry dependencies not checked (git/file/url): "
                            + ", ".join(skipped[:5]) + (" …" if len(skipped) > 5 else ""))
    return res


_RANGE = re.compile(r"^(\^|~|>=|=|v)?[ \t]*(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$")


def parse_manifest(path) -> ParseResult:
    """package.json with no lockfile next to it: best-effort, flagged approximate."""
    res = ParseResult()
    data = json.loads(read_text(path))
    if not isinstance(data, dict):
        raise ValueError("not a JSON object")
    skipped = []
    for sec, dev in (("dependencies", False), ("devDependencies", True), ("optionalDependencies", False)):
        deps = data.get(sec)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            m = _RANGE.match(str(spec).strip()[:200])
            if not m:
                skipped.append(f"{name}@{spec}")
                continue
            approx = m.group(1) in ("^", "~", ">=")
            res.packages.append({"name": name, "version": m.group(2), "ecosystem": "npm",
                                 "direct": True, "dev": dev, "approx": approx})
    if res.packages or skipped:
        res.warnings.append("no package-lock.json — ranges like ^1.2.3 were checked at their lowest "
                            "version (1.2.3), so results are approximate. Run `npm install "
                            "--package-lock-only` for exact results.")
    if skipped:
        res.warnings.append(f"{len(skipped)} dependencies with ranges PatchQ can't pin were not checked: "
                            + ", ".join(skipped[:5]) + (" …" if len(skipped) > 5 else ""))
    return res
