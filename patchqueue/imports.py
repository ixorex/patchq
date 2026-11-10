"""Import Trivy / Grype / OSV-Scanner JSON. PatchQ reuses those scanners instead of
re-implementing image scanning; their findings enter the same queue and ranking."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import discovery, model
from .sources import osv
from .version import compare, normalize_ecosystem


class ReportError(ValueError):
    pass


@dataclass
class ReportResult:
    kind: str
    findings: list = field(default_factory=list)
    images: set = field(default_factory=set)   # normalized image refs this report covers
    warnings: list = field(default_factory=list)


def _text(raw):
    """A string field from a report, or "" if it is the wrong type."""
    return raw if isinstance(raw, str) else ""


def _score(raw):
    """A CVSS score from report data: a float, or None if missing/malformed."""
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _pick_fix(raw, installed, eco):
    cands = [c.strip() for c in str(raw or "").split(",") if c.strip()]
    higher = [c for c in cands if compare(c, installed, eco) > 0]
    if not higher:
        return None
    best = higher[0]
    for c in higher[1:]:  # multi-branch fixes ("2.4.1, 2.3.5"): nearest one above installed
        if compare(c, best, eco) < 0:
            best = c
    return best


def _image_keys(ref):
    full, repo = model.normalize_image(ref)
    return full, [full, repo]


def _trivy(data, label):
    res = ReportResult("trivy")
    if not isinstance(data, dict):
        res.warnings.append("Trivy report is not a JSON object — skipped")
        return res
    artifact = str(data.get("ArtifactName") or label)
    is_image = data.get("ArtifactType") == "container_image"
    keys = []
    if is_image:
        full, keys = _image_keys(artifact)
        res.images.add(full)
    for r in data.get("Results") or []:
        if not isinstance(r, dict):
            res.warnings.append("skipped a malformed Trivy result entry (not an object)")
            continue
        eco = normalize_ecosystem(r.get("Type", ""))
        target = _text(r.get("Target"))
        for v in r.get("Vulnerabilities") or []:
            if not isinstance(v, dict):
                res.warnings.append("skipped a malformed Trivy vulnerability entry (not an object)")
                continue
            vid, name, inst = v.get("VulnerabilityID"), v.get("PkgName"), v.get("InstalledVersion")
            if not (isinstance(vid, str) and vid and isinstance(name, str) and name
                    and isinstance(inst, str) and inst):
                continue
            score = src = None
            cvss = v.get("CVSS")
            if isinstance(cvss, dict):
                for srcname in ("nvd", "ghsa", "redhat"):
                    srcdata = cvss.get(srcname)
                    if not isinstance(srcdata, dict):
                        continue
                    raw = srcdata.get("V3Score")
                    if raw is None:
                        continue
                    s = _score(raw)
                    if s is not None:
                        score, src = s, f"Trivy ({srcname})"
                        break
                    res.warnings.append(f"{vid}: ignoring non-numeric CVSS score {raw!r}")
            pid, aliases = model.primary_id(vid, [])
            res.findings.append(model.new_finding(
                id=pid, aliases=aliases, ecosystem=eco, package=name, installed=inst,
                fixed=_pick_fix(v.get("FixedVersion"), inst, eco),
                summary=(_text(v.get("Title")) or _text(v.get("Description")))[:300],
                url=_text(v.get("PrimaryURL")) or f"https://osv.dev/vulnerability/{vid}",
                cvss=score, cvss_source=src, origin=["trivy"], match_keys=list(keys),
                locations=[{"file": label, "system": artifact, "kind": "trivy", "target": target,
                            "image": artifact if is_image else None}],
            ))
    return res


def _grype(data, label):
    res = ReportResult("grype")
    if not isinstance(data, dict):
        res.warnings.append("Grype report is not a JSON object — skipped")
        return res
    src = data.get("source") if isinstance(data.get("source"), dict) else {}
    target = src.get("target")
    artifact = (target.get("userInput") if isinstance(target, dict) else target) or label
    artifact = _text(artifact) or label
    is_image = src.get("type") == "image"
    keys = []
    if is_image:
        full, keys = _image_keys(artifact)
        res.images.add(full)
    for m in data.get("matches") or []:
        if not isinstance(m, dict):
            res.warnings.append("skipped a malformed Grype match entry (not an object)")
            continue
        vul = m.get("vulnerability") if isinstance(m.get("vulnerability"), dict) else {}
        art = m.get("artifact") if isinstance(m.get("artifact"), dict) else {}
        vid, name, inst = vul.get("id"), art.get("name"), art.get("version")
        if not (isinstance(vid, str) and vid and isinstance(name, str) and name
                and isinstance(inst, str) and inst):
            continue
        eco = normalize_ecosystem(art.get("type", ""))
        related = [r.get("id") for r in m.get("relatedVulnerabilities") or []
                   if isinstance(r, dict) and isinstance(r.get("id"), str) and r.get("id")]
        fix = vul.get("fix") if isinstance(vul.get("fix"), dict) else {}
        versions = fix.get("versions")
        fixed = _pick_fix(",".join(v for v in versions if isinstance(v, str)), inst, eco) \
            if isinstance(versions, list) and fix.get("state") != "not-fixed" else None
        score = None
        cvss_entries = []
        if isinstance(vul.get("cvss"), list):
            cvss_entries += vul["cvss"]
        for r in m.get("relatedVulnerabilities") or []:
            if isinstance(r, dict) and isinstance(r.get("cvss"), list):
                cvss_entries += r["cvss"]
        for entry in cvss_entries:
            if not isinstance(entry, dict):
                continue
            if str(entry.get("version", "")).startswith("3"):
                metrics = entry.get("metrics") if isinstance(entry.get("metrics"), dict) else {}
                raw = metrics.get("baseScore")
                if raw is None:
                    continue
                s = _score(raw)
                if s is not None:
                    score = s
                    break
                res.warnings.append(f"{vid}: ignoring non-numeric CVSS score {raw!r}")
        pid, aliases = model.primary_id(vid, related)
        res.findings.append(model.new_finding(
            id=pid, aliases=aliases, ecosystem=eco, package=name, installed=inst, fixed=fixed,
            summary=_text(vul.get("description"))[:300],
            url=_text(vul.get("dataSource")) or f"https://osv.dev/vulnerability/{vid}",
            cvss=score, cvss_source="Grype" if score is not None else None, origin=["grype"],
            match_keys=list(keys),
            locations=[{"file": label, "system": artifact, "kind": "grype",
                        "target": ", ".join(_text(l.get("path")) for l in art.get("locations") or []
                                            if isinstance(l, dict))[:200],
                        "image": artifact if is_image else None}],
        ))
    return res


def _osv_scanner(data, label):
    res = ReportResult("osv-scanner")
    if not isinstance(data, dict):
        res.warnings.append("OSV-Scanner report is not a JSON object — skipped")
        return res
    for r in data.get("results") or []:
        if not isinstance(r, dict):
            res.warnings.append("skipped a malformed OSV-Scanner result entry (not an object)")
            continue
        source = r.get("source") if isinstance(r.get("source"), dict) else {}
        path = _text(source.get("path"))
        for pk in r.get("packages") or []:
            if not isinstance(pk, dict):
                res.warnings.append("skipped a malformed OSV-Scanner package entry (not an object)")
                continue
            p = pk.get("package") if isinstance(pk.get("package"), dict) else {}
            if not (isinstance(p.get("name"), str) and p.get("name")
                    and isinstance(p.get("version"), str) and p.get("version")):
                continue
            pkg = {"name": p["name"], "version": p["version"], "ecosystem": p.get("ecosystem", "")}
            loc = {"file": label, "system": Path(path).parent.name or label, "kind": "osv-scanner",
                   "target": path, "dir": str(Path(path).parent) if path else None}
            for rec in pk.get("vulnerabilities") or []:
                if not isinstance(rec, dict):
                    res.warnings.append("skipped a malformed OSV-Scanner vulnerability entry (not an object)")
                    continue
                if rec.get("withdrawn"):
                    continue
                res.findings.append(osv.finding_from_osv(rec, pkg, origin="osv-scanner", location=loc))
    return res


def load(path, label=None):
    path = Path(path)
    label = label or path.name
    try:
        if path.stat().st_size > discovery.MAX_REPORT_BYTES:
            raise ReportError(f"{label}: report larger than "
                              f"{discovery.MAX_REPORT_BYTES // (1024 * 1024)} MB — skipped")
    except OSError:
        pass
    kind, data = discovery.sniff_report(path)
    if kind is None:
        raise ReportError(f"{label}: not a Trivy, Grype or OSV-Scanner JSON report (SARIF isn't supported in v1)")
    res = {"trivy": _trivy, "grype": _grype, "osv-scanner": _osv_scanner}[kind](data, label)
    res.findings = model.merge_findings(res.findings)
    return res
