"""Ecosystem-aware version comparison.

String-comparing versions is the #1 bug source in tools like this
("1.10.0" < "1.9.0" as strings). Every comparison in PatchQ goes through here.

Supported precisely: npm / Go / crates.io (SemVer 2.0), PyPI (PEP 440),
Debian / Ubuntu (dpkg algorithm), Alpine (apk). Anything else, or anything
that fails to parse, falls back to a tokenized numeric comparison.
"""
from __future__ import annotations

import re

__all__ = ["compare", "bump_kind", "normalize_ecosystem", "InvalidVersion"]


MAX_LEN = 128  # no real version is longer; caps regex work on hostile input


class InvalidVersion(ValueError):
    pass


_ECO_ALIASES = {
    "npm": "npm", "node": "npm", "node-pkg": "npm", "nodejs": "npm", "yarn": "npm", "pnpm": "npm",
    "pypi": "PyPI", "pip": "PyPI", "pipenv": "PyPI", "poetry": "PyPI", "python": "PyPI",
    "python-pkg": "PyPI", "uv": "PyPI",
    "debian": "Debian", "deb": "Debian", "dpkg": "Debian",
    "ubuntu": "Ubuntu",
    "alpine": "Alpine", "apk": "Alpine", "wolfi": "Alpine", "chainguard": "Alpine",
    "maven": "Maven", "jar": "Maven", "pom": "Maven", "gradle": "Maven", "java-archive": "Maven",
    "go": "Go", "gomod": "Go", "gobinary": "Go", "go-module": "Go",
    "crates.io": "crates.io", "cargo": "crates.io", "rust-crate": "crates.io", "rust-binary": "crates.io",
    "rubygems": "RubyGems", "gem": "RubyGems", "gemspec": "RubyGems", "bundler": "RubyGems",
    "packagist": "Packagist", "composer": "Packagist", "php-composer": "Packagist",
}


def normalize_ecosystem(eco: str) -> str:
    """Map OSV / Trivy / Grype ecosystem spellings to one canonical name."""
    if not eco:
        return "unknown"
    base = str(eco).split(":", 1)[0].strip()  # OSV uses e.g. "Debian:12"
    return _ECO_ALIASES.get(base.lower(), base)


# ---------------------------------------------------------------- SemVer (npm)
_SEMVER = re.compile(
    r"^[vV=]*[ \t]*(\d+)(?:\.(\d+))?(?:\.(\d+))?"
    r"(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


def _semver_key(v: str):
    m = _SEMVER.match(v)
    if not m:
        raise InvalidVersion(v)
    major, minor, patch = (int(x) if x else 0 for x in m.group(1, 2, 3))
    pre = m.group(4)
    if pre is None:
        pre_key = (1,)  # a release sorts after any of its pre-releases
    else:
        ids = []
        for part in pre.split("."):
            # SemVer: numeric identifiers sort below alphanumeric ones
            ids.append((0, int(part), "") if part.isdigit() else (1, 0, part))
        pre_key = (0, tuple(ids))
    return (major, minor, patch, pre_key)


# ---------------------------------------------------------------- PEP 440 (PyPI)
_PEP440 = re.compile(
    r"""^v?
    (?:(?P<epoch>\d+)!)?
    (?P<release>\d+(?:\.\d+)*)
    (?P<pre>[-_.]?(?P<pre_l>alpha|beta|preview|pre|rc|a|b|c)[-_.]?(?P<pre_n>\d+)?)?
    (?P<post>(?:-(?P<post_n1>\d+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d+)?))?
    (?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    $""",
    re.VERBOSE | re.IGNORECASE,
)
_PRE_ORDER = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}


def _pep440_key(v: str):
    m = _PEP440.match(v)
    if not m:
        raise InvalidVersion(v)
    epoch = int(m.group("epoch") or 0)
    release = [int(x) for x in m.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:  # 1.0 == 1.0.0
        release.pop()
    pre_l = m.group("pre_l")
    has_post = m.group("post") is not None
    has_dev = m.group("dev") is not None
    if pre_l is None and not has_post and has_dev:
        pre_k = (-1, 0)  # 1.0.dev0 sorts before 1.0a1
    elif pre_l is None:
        pre_k = (3, 0)
    else:
        pre_k = (_PRE_ORDER[pre_l.lower()], int(m.group("pre_n") or 0))
    if has_post:
        post_k = (0, int(m.group("post_n1") or m.group("post_n2") or 0))
    else:
        post_k = (-1, 0)
    dev_k = (0, int(m.group("dev_n") or 0)) if has_dev else (1, 0)
    local = m.group("local")
    if local:
        local_k = tuple(
            (1, int(p), "") if p.isdigit() else (0, 0, p.lower()) for p in re.split(r"[-_.]", local)
        )
    else:
        local_k = ()
    return (epoch, tuple(release), pre_k, post_k, dev_k, local_k)


# ---------------------------------------------------------------- dpkg (Debian/Ubuntu)
def _deb_order(c: str) -> int:
    if c == "~":
        return -1
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _is_digit(c: str) -> bool:
    return "0" <= c <= "9"


def _deb_verrevcmp(a: str, b: str) -> int:
    """Port of dpkg's verrevcmp()."""
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        first_diff = 0
        while (i < la and not _is_digit(a[i])) or (j < lb and not _is_digit(b[j])):
            ac = _deb_order(a[i]) if i < la and not _is_digit(a[i]) else 0
            bc = _deb_order(b[j]) if j < lb and not _is_digit(b[j]) else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        while i < la and j < lb and _is_digit(a[i]) and _is_digit(b[j]):
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and _is_digit(a[i]):
            return 1
        if j < lb and _is_digit(b[j]):
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


def _deb_split(v: str):
    v = v.strip()
    epoch = 0
    if ":" in v:
        e, rest = v.split(":", 1)
        if e.isdigit():
            epoch, v = int(e), rest
    if "-" in v:
        upstream, revision = v.rsplit("-", 1)
    else:
        upstream, revision = v, ""
    return epoch, upstream, revision


def _deb_compare(a: str, b: str) -> int:
    ea, ua, ra = _deb_split(a)
    eb, ub, rb = _deb_split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = _deb_verrevcmp(ua, ub)
    if c:
        return c
    return _deb_verrevcmp(ra, rb)


# ---------------------------------------------------------------- apk (Alpine)
_APK = re.compile(
    r"^(\d+(?:\.\d+)*)([a-z])?((?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d*)*)(?:-r(\d+))?$"
)
_APK_SUFFIX = {"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}


def _apk_key(v: str):
    m = _APK.match(v)
    if not m:
        raise InvalidVersion(v)
    nums = tuple(int(x) for x in m.group(1).split("."))
    letter = m.group(2) or ""
    suffixes = []
    for name, num in re.findall(r"_([a-z]+)(\d*)", m.group(3) or ""):
        suffixes.append((_APK_SUFFIX[name], int(num or 0)))
    suffixes.append((0, 0))  # terminator: "1.0" > "1.0_rc1", "1.0" < "1.0_p1"
    return (nums, letter, tuple(suffixes), int(m.group(4) or 0))


# ---------------------------------------------------------------- generic fallback
_PRERELEASE_WORDS = {"alpha", "beta", "rc", "pre", "preview", "dev", "snapshot", "m"}


def _generic_key(v: str):
    v = str(v).strip().lstrip("vV=")
    parts = []
    for tok in re.findall(r"\d+|[A-Za-z]+", v):
        if tok.isdigit():
            parts.append((2, int(tok), ""))
        elif tok.lower() in _PRERELEASE_WORDS:
            parts.append((0, 0, tok.lower()))  # 1.0rc1 < 1.0
        else:
            parts.append((1, 0, tok.lower()))  # 1.0.1f > 1.0.1 (openssl style)
    parts.append((0.5, 0, ""))  # end-of-version marker sits between the two
    return tuple(parts)


_KEYS = {
    "npm": _semver_key,
    "Go": _semver_key,
    "crates.io": _semver_key,
    "PyPI": _pep440_key,
    "Alpine": _apk_key,
}


def compare(a: str, b: str, ecosystem: str = "") -> int:
    """Return -1, 0 or 1. Never compares versions as plain strings."""
    a, b = str(a).strip(), str(b).strip()
    if a == b:
        return 0
    if len(a) > MAX_LEN or len(b) > MAX_LEN:  # absurd input: linear fallback only
        ka, kb = _generic_key(a[:MAX_LEN]), _generic_key(b[:MAX_LEN])
        return (ka > kb) - (ka < kb)
    eco = normalize_ecosystem(ecosystem)
    if eco in ("Debian", "Ubuntu"):
        return _deb_compare(a, b)
    keyfn = _KEYS.get(eco)
    ka = kb = None
    if keyfn is not None:
        try:
            ka, kb = keyfn(a), keyfn(b)
        except InvalidVersion:
            ka = kb = None
    if ka is None:
        ka, kb = _generic_key(a), _generic_key(b)
    return (ka > kb) - (ka < kb)


_LEADING = re.compile(r"^\s*[vV=]*(?:\d+[!:])?(\d+(?:\.\d+)*)")


def _release_nums(v: str):
    m = _LEADING.match((v or "")[:MAX_LEN])
    if not m:
        return None
    nums = [int(x) for x in m.group(1).split(".")]
    while len(nums) < 3:
        nums.append(0)
    return nums


def bump_kind(installed: str, fixed, ecosystem: str = "") -> str:
    """Classify the upgrade as 'patch', 'minor', 'major', 'calver' or 'unknown'.

    0.x minor bumps count as major (SemVer: anything may change before 1.0).
    For Debian/Ubuntu/Alpine, a change that keeps the upstream version and only
    bumps the distro revision counts as 'patch'.
    """
    if not fixed or not installed:
        return "unknown"
    eco = normalize_ecosystem(ecosystem)
    if eco in ("Debian", "Ubuntu"):
        ea, ua, _ = _deb_split(installed)
        eb, ub, _ = _deb_split(fixed)
        if ea != eb:
            return "major"
        if ua == ub:
            return "patch"
        installed, fixed = ua, ub
    elif eco == "Alpine":
        ia, fa = installed.split("-r")[0], str(fixed).split("-r")[0]
        if ia == fa:
            return "patch"
    a, b = _release_nums(installed), _release_nums(str(fixed))
    if a is None or b is None:
        return "unknown"
    if a[0] >= 1990 and b[0] >= 1990:
        return "calver"  # 2022.12.7 -> 2023.7.22: the "major" is a year, not an API break
    if a[0] != b[0]:
        return "major"
    if a[0] == 0 and a[1] != b[1]:
        return "major"
    if a[1] != b[1]:
        return "minor"
    return "patch"
