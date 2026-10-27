"""Python: requirements*.txt, poetry.lock, Pipfile.lock."""
from __future__ import annotations

import json
import re
from pathlib import Path

from .base import ParseResult, read_text

_REQ = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)[ \t]*(\[[^\]]*\][ \t]*)?(===|==)[ \t]*([A-Za-z0-9][A-Za-z0-9.!+_*-]*)$"
)


def is_requirements_name(path: Path) -> bool:
    n = path.name.lower()
    return (n.startswith("requirements") and n.endswith(".txt")) or (
        path.parent.name.lower() == "requirements" and n.endswith(".txt"))


def _logical_lines(text):
    buf = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        yield buf + line
        buf = ""
    if buf:
        yield buf


def parse_requirements(path, _seen=None, root=None) -> ParseResult:
    res = ParseResult()
    _seen = _seen if _seen is not None else set()
    real = Path(path).resolve()
    if real in _seen:
        return res
    _seen.add(real)
    # `-r` includes may only point inside the scanned folder: a hostile repo must not be able
    # to make PatchQ read (and send "name==version" lines from) files elsewhere on the machine.
    root = Path(root).resolve() if root else real.parent
    unpinned, skipped = [], []
    for line in _logical_lines(read_text(path)):
        line = re.sub(r"(^|\s)#.*$", "", line).strip()
        if not line:
            continue
        if line.startswith(("-r", "--requirement", "-c", "--constraint")):
            opt, _, target = line.replace("=", " ", 1).partition(" ")
            target = target.strip()
            if opt in ("-c", "--constraint"):
                res.warnings.append(f"constraints file {target} not scanned (pins there only apply if installed)")
                continue
            inc = (Path(path).parent / target)
            try:
                inc.resolve().relative_to(root)
            except (ValueError, OSError):
                res.warnings.append(f"included file {target} is outside the scanned folder — not read")
                continue
            if is_requirements_name(inc):
                continue  # auto-discovery scans it on its own
            if inc.is_file():
                sub = parse_requirements(inc, _seen, root)
                for p in sub.packages:
                    p.setdefault("file_abs", str(inc))
                res.packages += sub.packages
                res.warnings += [f"{inc.name}: {w}" for w in sub.warnings]
            else:
                res.warnings.append(f"included file {target} not found")
            continue
        if line.startswith("-"):
            if line.startswith(("-e", "--editable")):
                skipped.append(line)
            continue  # --index-url and friends
        req = line.split(";", 1)[0].strip()
        req = re.split(r"\s--hash", req)[0].strip()
        if "://" in req or req.startswith(("git+", "file:", ".", "/")):
            skipped.append(req)
            continue
        m = _REQ.match(req)
        if m and "*" not in m.group(4):
            res.packages.append({"name": m.group(1), "version": m.group(4), "ecosystem": "PyPI",
                                 "direct": True, "dev": False})
        else:
            unpinned.append(req)
    if unpinned:
        res.warnings.append(f"{len(unpinned)} unpinned requirements not checked (installed version unknown): "
                            + ", ".join(unpinned[:5]) + (" …" if len(unpinned) > 5 else "")
                            + " — pin them, or scan `pip freeze > requirements.lock.txt`")
    if skipped:
        res.warnings.append(f"{len(skipped)} editable/URL requirements not checked: " + ", ".join(skipped[:3]))
    return res


def _toml_packages_fallback(text):
    """Python < 3.11 has no tomllib: pull name/version out of [[package]] blocks."""
    out = []
    for block in re.split(r"^\[\[package\]\]\s*$", text, flags=re.M)[1:]:
        body = re.split(r"^\[(?!package\.)", block, maxsplit=1, flags=re.M)[0]
        name = re.search(r'^name\s*=\s*"([^"]+)"', body, re.M)
        ver = re.search(r'^version\s*=\s*"([^"]+)"', body, re.M)
        cat = re.search(r'^category\s*=\s*"([^"]+)"', body, re.M)
        groups = re.search(r'^groups\s*=\s*\[([^\]]*)\]', body, re.M)
        src = re.search(r'^\[package\.source\][^\[]*?^type\s*=\s*"([^"]+)"', body, re.M | re.S)
        if name and ver:
            p = {"name": name.group(1), "version": ver.group(1)}
            if cat:
                p["category"] = cat.group(1)
            if groups:
                p["groups"] = re.findall(r'"([^"]+)"', groups.group(1))
            if src:
                p["source"] = {"type": src.group(1)}
            out.append(p)
    return out


def parse_poetry(path) -> ParseResult:
    res = ParseResult()
    text = read_text(path)
    try:
        import tomllib  # Python 3.11+
        pkgs = tomllib.loads(text).get("package", [])
    except ImportError:
        pkgs = _toml_packages_fallback(text)
    skipped = []
    for p in pkgs:
        name, ver = p.get("name"), p.get("version")
        if not name or not ver:
            continue
        if (p.get("source") or {}).get("type") in ("git", "directory", "file", "url"):
            skipped.append(name)
            continue
        groups = p.get("groups") or []
        dev = p.get("category") == "dev" or (bool(groups) and "main" not in groups)
        res.packages.append({"name": name, "version": ver, "ecosystem": "PyPI", "direct": None, "dev": dev})
    if skipped:
        res.warnings.append(f"{len(skipped)} git/path packages not checked: " + ", ".join(skipped[:5]))
    return res


def parse_pipfile_lock(path) -> ParseResult:
    res = ParseResult()
    data = json.loads(read_text(path))
    if not isinstance(data, dict):
        raise ValueError("not a JSON object")
    skipped = []
    for sec, dev in (("default", False), ("develop", True)):
        for name, meta in (data.get(sec) or {}).items():
            v = (meta or {}).get("version", "") if isinstance(meta, dict) else ""
            if isinstance(v, str) and v.startswith("=="):
                res.packages.append({"name": name, "version": v[2:], "ecosystem": "PyPI", "direct": None, "dev": dev})
            else:
                skipped.append(name)
    if skipped:
        res.warnings.append(f"{len(skipped)} git/path packages not checked: " + ", ".join(skipped[:5]))
    return res
