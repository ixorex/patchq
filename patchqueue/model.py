"""Shared data shapes: findings, IDs, merging. Plain dicts so queue.json stays readable."""
from __future__ import annotations

import copy
import re

from .version import compare, normalize_ecosystem

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,80}$")


def norm_name(name: str, ecosystem: str) -> str:
    eco = normalize_ecosystem(ecosystem)
    n = (name or "").strip()
    if eco == "PyPI":
        return re.sub(r"[-_.]+", "-", n).lower()  # PEP 503
    return n.lower()


def is_cve(s: str) -> bool:
    return bool(s and CVE_RE.match(s))


def primary_id(record_id: str, aliases=()):
    """Prefer a CVE ID (that's what KEV and EPSS key on); keep the rest as aliases."""
    ids = [i for i in [record_id, *(aliases or [])] if i]
    cves = sorted({i.upper() for i in ids if is_cve(i)})
    if record_id and is_cve(record_id):
        pid = record_id.upper()
    elif cves:
        pid = cves[0]
    else:
        pid = record_id
    rest = sorted({(i.upper() if is_cve(i) else i) for i in ids} - {pid})
    return pid, rest


_REGISTRY_PREFIXES = (
    "docker.io/library/", "index.docker.io/library/", "registry-1.docker.io/library/",
    "docker.io/", "index.docker.io/", "registry-1.docker.io/", "library/",
)


def normalize_image(ref: str):
    """'docker.io/library/nginx' -> ('nginx:latest', 'nginx'). Returns (ref, repo)."""
    r = (ref or "").strip().lower()
    digest = ""
    if "@" in r:
        r, digest = r.split("@", 1)
    for p in _REGISTRY_PREFIXES:
        if r.startswith(p):
            r = r[len(p):]
            break
    last = r.rsplit("/", 1)[-1]
    if ":" in last:
        repo, tag = r.rsplit(":", 1)
    else:
        repo, tag = r, ""
    if tag:
        return f"{repo}:{tag}", repo
    if digest:
        return f"{repo}@{digest}", repo
    return f"{repo}:latest", repo


def new_finding(**kw) -> dict:
    f = {
        "id": "", "aliases": [], "ecosystem": "", "package": "", "installed": "",
        "fixed": None, "fix_unknown": False, "summary": "", "url": "",
        "cvss": None, "cvss_source": None, "epss": None, "epss_percentile": None, "epss_date": None,
        "kev": None, "poc": False, "origin": [], "locations": [], "match_keys": [],
    }
    f.update(kw)
    return f


def finding_key(f: dict):
    eco = normalize_ecosystem(f.get("ecosystem", ""))
    return (str(f.get("id", "")).upper(), eco, norm_name(f.get("package", ""), eco), str(f.get("installed", "")))


def _loc_key(loc: dict):
    return (loc.get("file"), loc.get("system"), loc.get("target"))


def _merge_fixed(a, b, eco):
    if not a:
        return b
    if not b:
        return a
    # Both sources name a fix: take the higher one so the upgrade clears both advisories.
    return a if compare(a, b, eco) >= 0 else b


def merge_findings(findings) -> list:
    """Merge the same vuln/package/version seen in several files or sources."""
    out = {}
    for f in findings:
        k = finding_key(f)
        if k not in out:
            out[k] = copy.deepcopy(f)
            continue
        m = out[k]
        seen = {_loc_key(l) for l in m["locations"]}
        for loc in f.get("locations", []):
            if _loc_key(loc) not in seen:
                m["locations"].append(copy.deepcopy(loc))
                seen.add(_loc_key(loc))
        m["match_keys"] = sorted(set(m.get("match_keys", [])) | set(f.get("match_keys", [])))
        m["aliases"] = sorted((set(m.get("aliases", [])) | set(f.get("aliases", []))) - {m["id"]})
        m["origin"] = sorted(set(m.get("origin", [])) | set(f.get("origin", [])))
        m["fixed"] = _merge_fixed(m.get("fixed"), f.get("fixed"), k[1])
        m["fix_unknown"] = bool(m.get("fix_unknown") and f.get("fix_unknown")) and not m["fixed"]
        for fld in ("summary", "url", "cvss", "cvss_source", "epss", "epss_percentile", "epss_date", "kev"):
            if m.get(fld) in (None, "") and f.get(fld) not in (None, ""):
                m[fld] = f[fld]
        m["poc"] = bool(m.get("poc") or f.get("poc"))
    return list(out.values())
