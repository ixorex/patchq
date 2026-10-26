"""patchqueue.yml — the tiny inventory that tells PatchQ what is internet-facing.

    systems:
      proxy:            # compose service name, image name, or folder path
        exposed: true
        critical: true
      apps/web: {exposed: false}
"""
from __future__ import annotations

from pathlib import Path

from . import miniyaml
from .model import normalize_image

FILENAMES = ("patchqueue.yml", "patchqueue.yaml", ".patchqueue.yml")


def norm_key(k) -> str:
    return str(k).strip().lower().rstrip("/") or "."


def keys_for_image(ref: str):
    full, repo = normalize_image(ref)
    return [full, repo]


def find(root: Path):
    root = Path(root)
    if root.is_file():
        root = root.parent
    for name in FILENAMES:
        p = root / name
        if p.is_file():
            return p
    return None


def load(root: Path):
    """Return (inventory dict, warnings). Missing file = empty inventory, no error."""
    path = find(root)
    if path is None:
        return {}, []
    warnings = []
    try:
        data = miniyaml.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, miniyaml.YamlError) as e:
        return {}, [f"{path.name}: could not read ({e}) — exposure flags ignored"]
    if not isinstance(data, dict):
        return {}, [f"{path.name}: expected a mapping of systems — exposure flags ignored"]
    systems = data.get("systems") if isinstance(data.get("systems"), dict) else data
    out = {}
    for k, v in systems.items():
        if not isinstance(v, dict):
            continue
        entry = {}
        for flag in ("exposed", "critical"):
            val = v.get(flag, False)
            if val not in (True, False, None):
                warnings.append(f"{path.name}: {k}.{flag} = {val!r} is not true/false — treated as false")
            entry[flag] = val is True
        key = norm_key(k)
        out[key] = entry
        if ":" in key or "/" in key:  # also index image-style keys in normalized form
            for ik in keys_for_image(key):
                out.setdefault(ik, entry)
    return out, warnings


def lookup(inventory: dict, keys):
    """Return (exposed, critical, [matched keys])."""
    exposed = critical = False
    matched = []
    for k in keys or []:
        e = (inventory or {}).get(norm_key(k))
        if e:
            matched.append(k)
            exposed = exposed or e.get("exposed", False)
            critical = critical or e.get("critical", False)
    return exposed, critical, matched
