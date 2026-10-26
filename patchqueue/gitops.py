"""git clone / pull. Uses the system `git` binary with argument lists (no shell)."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

# https and ssh only: git:// and http:// are unauthenticated/unencrypted.
_URL = re.compile(r"^(https://[^\s]+|ssh://[^\s]+|git@[A-Za-z0-9.-]+:[^\s]+)$")


class GitError(RuntimeError):
    pass


def is_git_url(s: str) -> bool:
    return bool(_URL.match(s or ""))


def _git(args, cwd=None, timeout=300, strict=False):
    if shutil.which("git") is None:
        raise GitError("git is not installed — install git, or clone the repo yourself and run `patchq scan <folder>`")
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")  # never hang waiting for a password
    cmd = ["git", "-c", "protocol.ext.allow=never"]
    if strict:  # cloning a URL you typed: no local-file or ext:: transports, no submodules
        cmd += ["-c", "protocol.file.allow=never"]
    cmd += list(args)
    try:
        p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise GitError(f"git {args[0]} timed out after {timeout}s")
    if p.returncode != 0:
        raise GitError(f"git {args[0]} failed: {(p.stderr or p.stdout).strip()[:500]}")
    return p.stdout


def repo_dir(url: str, home: Path) -> Path:
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", re.sub(r"^\w+://|^git@", "", url))
    name = re.sub(r"\.{2,}", ".", name).strip("._")[:120] or "repo"  # no '..' path tricks
    return Path(home) / "repos" / name


def clone_or_pull(url: str, home: Path, offline: bool = False):
    """Return (path, message). Shallow-clones into ~/.patchqueue/repos/, or fast-forwards it."""
    if not is_git_url(url):
        raise GitError(f"not an https/ssh git URL: {url}")
    dest = repo_dir(url, home)
    if dest.is_dir() and (dest / ".git").exists():
        if offline:
            return dest, f"offline: using existing clone at {dest}"
        _git(["-C", str(dest), "pull", "--ff-only", "--quiet"], strict=True)
        return dest, f"updated {dest}"
    if offline:
        raise GitError(f"offline and no previous clone of {url}")
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _git(["clone", "--depth", "1", "--quiet", "--", url, str(dest)], strict=True)
    return dest, f"cloned to {dest}"


def pull_local(path: Path):
    """`git pull --ff-only` in a local repo. Returns a message; never destructive."""
    if not (Path(path) / ".git").exists():
        return f"--pull ignored: {path} is not a git repo root"
    _git(["-C", str(path), "pull", "--ff-only", "--quiet"])
    return f"pulled latest in {path}"
