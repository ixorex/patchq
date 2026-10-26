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
    artifact = str(data.get("ArtifactName") or label)
    is_image = data.get("ArtifactType") == "container_image"
    keys = []
    if is_image:
        full, keys = _image_keys(artifact)
        res.images.add(full)
    for r in data.get("Results") or []:
        eco = normalize_ecosystem(r.get("Type", ""))
        target = r.get("Target", "")
        for v in r.get("Vulnerabilities") or []:
            vid, name, inst = v.get("VulnerabilityID"), v.get("PkgName"), v.get("InstalledVersion")
            if not (vid and name and inst):
                continue
            score = src = None
            for srcname in ("nvd", "ghsa", "redhat"):
                s = ((v.get("CVSS") or {}).get(srcname) or {}).get("V3Score")
                if s is not None:
                    score, src = float(s), f"Trivy ({srcname})"
                    break
            pid, aliases = model.primary_id(vid, [])
            res.findings.append(model.new_finding(
                id=pid, aliases=aliases, ecosystem=eco, package=name, installed=inst,
                fixed=_pick_fix(v.get("FixedVersion"), inst, eco),
                summary=(v.get("Title") or v.get("Description") or "")[:300],
                url=v.get("PrimaryURL") or f"https://osv.dev/vulnerability/{vid}",
                cvss=score, cvss_source=src, origin=["trivy"], match_keys=list(keys),
                locations=[{"file": label, "system": artifact, "kind": "trivy", "target": target,
                            "image": artifact if is_image else None}],
            ))
    return res


def _grype(data, label):
    res = ReportResult("grype")
    src = data.get("source") or {}
    target = src.get("target")
    artifact = (target.get("userInput") if isinstance(target, dict) else target) or label
    is_image = src.get("type") == "image"
    keys = []
    if is_image:
        full, keys = _image_keys(artifact)
        res.images.add(full)
    for m in data.get("matches") or []:
        vul, art = m.get("vulnerability") or {}, m.get("artifact") or {}
        vid, name, inst = vul.get("id"), art.get("name"), art.get("version")
        if not (vid and name and inst):
            continue
        eco = normalize_ecosystem(art.get("type", ""))
        related = [r.get("id") for r in m.get("relatedVulnerabilities") or [] if r.get("id")]
        fix = vul.get("fix") or {}
        fixed = _pick_fix(",".join(fix.get("versions") or []), inst, eco) if fix.get("state") != "not-fixed" else None
        score = None
        for entry in (vul.get("cvss") or []) + [c for r in m.get("relatedVulnerabilities") or [] for c in r.get("cvss") or []]:
            if str(entry.get("version", "")).startswith("3"):
                s = (entry.get("metrics") or {}).get("baseScore")
                if s is not None:
                    score = float(s)
                    break
        pid, aliases = model.primary_id(vid, related)
        res.findings.append(model.new_finding(
            id=pid, aliases=aliases, ecosystem=eco, package=name, installed=inst, fixed=fixed,
            summary=(vul.get("description") or "")[:300],
            url=vul.get("dataSource") or f"https://osv.dev/vulnerability/{vid}",
            cvss=score, cvss_source="Grype" if score is not None else None, origin=["grype"],
            match_keys=list(keys),
            locations=[{"file": label, "system": artifact, "kind": "grype",
                        "target": ", ".join(l.get("path", "") for l in art.get("locations") or [])[:200],
                        "image": artifact if is_image else None}],
        ))
    return res


def _osv_scanner(data, label):
    res = ReportResult("osv-scanner")
    for r in data.get("results") or []:
        path = (r.get("source") or {}).get("path", "")
        for pk in r.get("packages") or []:
            p = pk.get("package") or {}
            if not (p.get("name") and p.get("version")):
                continue
            pkg = {"name": p["name"], "version": p["version"], "ecosystem": p.get("ecosystem", "")}
            loc = {"file": label, "system": Path(path).parent.name or label, "kind": "osv-scanner",
                   "target": path, "dir": str(Path(path).parent) if path else None}
            for rec in pk.get("vulnerabilities") or []:
                if rec.get("withdrawn"):
                    continue
                res.findings.append(osv.finding_from_osv(rec, pkg, origin="osv-scanner", location=loc))
    return res


def load(path, label=None):
    path = Path(path)
    label = label or path.name
    kind, data = discovery.sniff_report(path)
    if kind is None:
        raise ReportError(f"{label}: not a Trivy, Grype or OSV-Scanner JSON report (SARIF isn't supported in v1)")
    res = {"trivy": _trivy, "grype": _grype, "osv-scanner": _osv_scanner}[kind](data, label)
    res.findings = model.merge_findings(res.findings)
    return res
