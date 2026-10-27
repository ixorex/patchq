"""Exact upgrade command for a finding.

Package names come from lockfiles and scanner reports, i.e. untrusted input that
a user will copy-paste into a shell. Names and versions are validated against a
strict per-ecosystem pattern and shell-quoted; anything odd gets no command.
"""
from __future__ import annotations

import os
import shlex
import re

from .version import bump_kind, normalize_ecosystem

_NPM = re.compile(r"^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$", re.I)
_PY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_OS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]*$")
_GO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~/-]*$")
_VER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_~:!-]*$")

BREAKS = {
    "major": "high — major bump, test in staging",
    "minor": "medium — minor bump",
    "patch": "low — patch bump",
    "calver": "unknown — calendar-versioned, check the changelog",
    "unknown": "unknown — check the changelog",
}

NO_FIX = (
    "no fix yet — mitigate (apply the advisory's workaround), isolate (cut this "
    "service's network exposure), or watch (PatchQ re-checks on every scan)"
)


def _q(s: str) -> str:
    return shlex.quote(s)


_UNSAFE = re.compile("[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")


def unsafe_text(s) -> bool:
    """Control chars or invisible / bidi-override chars that could make a printed
    command look different from what actually gets pasted and run."""
    return bool(_UNSAFE.search(str(s or "")))


def _cd(directory):
    """`cd <dir> && ` prefix, '' for no dir, None when the path isn't safe to print."""
    if not directory:
        return ""
    if unsafe_text(directory):
        return None
    home = os.path.expanduser("~")
    if directory == home:
        return "cd ~ && "
    if directory.startswith(home + os.sep):
        rest = directory[len(home) + 1:]
        return f"cd ~/{_q(rest)} && "  # ~ stays unquoted so the shell expands it
    return f"cd {_q(directory)} && "


def breaks_risk(item) -> dict:
    kind = bump_kind(item.get("installed", ""), item.get("fixed"), item.get("ecosystem", ""))
    return {"kind": kind, "label": BREAKS[kind]}


def command(item) -> tuple:
    """Return (command, note) covering every location (one command line each).

    command is '' when PatchQ won't emit one; multiple lines are joined with newlines.
    """
    locs = item.get("locations") or [{}]
    ordered = sorted(locs, key=lambda l: 0 if l.get("direct") else 1)
    cmds, notes = [], []
    for loc in ordered:
        cmd, note = _command_for(item, loc)
        if cmd and cmd not in cmds:
            cmds.append(cmd)
        if note and note not in notes:
            notes.append(note)
    return "\n".join(cmds), (" | ".join(notes) or None)


def _command_for(item, loc) -> tuple:
    url = item.get("url") or ""
    if item.get("fix_unknown") and not item.get("fixed"):
        return "", "advisory details unavailable (offline / feed down) — re-run `patchq scan` when online"
    fixed = item.get("fixed")
    if not fixed:
        return "", f"{NO_FIX}. Advisory: {url}" if url else NO_FIX
    eco = normalize_ecosystem(item.get("ecosystem", ""))
    name = item.get("package", "")
    if not _VER.match(str(fixed)):
        return "", f"not generating a command: fixed version {fixed!r} has unexpected characters"
    pattern = {"npm": _NPM, "PyPI": _PY, "Go": _GO}.get(eco, _OS)
    if not pattern.match(name):
        return "", f"not generating a command: package name {name!r} has unexpected characters — inspect {loc.get('file')}"

    cd = _cd(loc.get("dir"))
    if cd is None:
        return "", ("not generating a command: the folder path contains control or invisible characters "
                    f"— inspect {loc.get('file')!r} by hand")
    kind = loc.get("kind", "")
    image = loc.get("image")
    in_image = f" (inside image {image})" if image else ""

    if eco == "npm":
        spec = _q(f"{name}@{fixed}")
        if kind == "npm-manifest":
            return (f"{cd}npm install {spec}",
                    "version came from a package.json range, not a lockfile — run `npm install --package-lock-only` for exact results")
        if loc.get("direct") is False:
            return (f"{cd}npm update {_q(name)}",
                    f"transitive dependency{in_image}: if the lockfile still shows < {fixed}, add "
                    f'"overrides": {{"{name}": "{fixed}"}} to package.json and run npm install')
        dev = " --save-dev" if loc.get("dev") else ""
        return f"{cd}npm install{dev} {spec}", (f"run inside the image's build{in_image}" if image else None)
    if eco == "PyPI":
        if kind == "poetry":
            return f"{cd}poetry add {_q(f'{name}>={fixed}')}", None
        if kind == "pipenv":
            return f"{cd}pipenv install {_q(f'{name}>={fixed}')}", None
        note = f"then change the pin in {loc.get('file')} to {name}=={fixed}" if kind == "requirements" else None
        if image:
            note = f"inside image {image}: bump it in the image's requirements and rebuild"
        return f"{cd}pip install {_q(f'{name}=={fixed}')}", note
    if eco in ("Debian", "Ubuntu"):
        return (f"apt-get update && apt-get install -y --only-upgrade {_q(name)}",
                f"add to the image's Dockerfile as a RUN step and rebuild{in_image} — or move to a newer base image tag")
    if eco == "Alpine":
        return (f"apk add --no-cache --upgrade {_q(name)}",
                f"add to the image's Dockerfile as a RUN step and rebuild{in_image} — or move to a newer base image tag")
    if eco == "Go":
        v = fixed if str(fixed).startswith("v") else f"v{fixed}"
        return f"{cd}go get {_q(f'{name}@{v}')} && go mod tidy", None
    if eco == "crates.io":
        return f"{cd}cargo update -p {_q(name)} --precise {_q(str(fixed))}", None
    return "", f"upgrade {name} to {fixed} with your build tool{in_image} (v1 generates commands for npm, PyPI, Debian/Ubuntu, Alpine, Go, Cargo)"
