"""Scan pipeline: git -> discover -> parse -> import reports -> OSV -> KEV/EPSS/NVD.

Two entry points share one pipeline:
  scan(target)    a folder, file, or git URL
  scan_docker()   the containers running on this machine (via Trivy)
"""
from __future__ import annotations

import socket
from pathlib import Path

from . import discovery, dockerscan, gitops, imports, inventory, model, parsers
from .sources import cache, epss, kev, nvd, osv


class ScanError(RuntimeError):
    pass


def _rel(root: Path, p: Path) -> str:
    try:
        return str(Path(p).relative_to(root)) or Path(p).name
    except ValueError:
        return str(p)


def _system_name(root: Path, file: Path) -> str:
    rel_dir = _rel(root, file.parent) if root.is_dir() else "."
    return root.name if rel_dir in ("", ".") else rel_dir


def scan(target: str, extra_reports=(), offline=False, pull=False, use_nvd=True, nvd_max=None, log=None,
         covered_images=()):
    """Scan one folder / file / git URL. Returns a scan record (plain dict)."""
    log = log or (lambda _m: None)
    warnings = []
    label = target

    if gitops.is_git_url(target):
        try:
            root, msg = gitops.clone_or_pull(target, cache.home(), offline=offline)
        except gitops.GitError as e:
            raise ScanError(str(e))
        log(msg)
    else:
        root = Path(target).expanduser().resolve()
        if not root.exists():
            raise ScanError(f"{target}: no such file or folder")
        if pull and root.is_dir():
            try:
                log(gitops.pull_local(root))
            except gitops.GitError as e:
                warnings.append(f"--pull failed, scanning what's on disk: {e}")
        label = str(root)

    base = root if root.is_dir() else root.parent
    disc = discovery.discover(root)
    warnings += disc.errors

    packages, images, systems = [], [], []
    for f in disc.files:
        rel = _rel(base, f.path)
        res = parsers.parse(f.path, f.kind, root=base)
        system = _system_name(base, f.path)
        rel_dir = _rel(base, f.path.parent)
        for p in res.packages:
            file_abs = p.pop("file_abs", None)
            p.update(file=_rel(base, Path(file_abs)) if file_abs else rel, system=system,
                     dir=str(f.path.parent), kind=f.kind, keys=[system, rel_dir])
            packages.append(p)
        for im in res.images:
            im["file"] = rel
            im["system"] = im.get("service") or system
            images.append(im)
        warnings += [f"{rel}: {w}" for w in res.warnings]
        systems.append({"name": system, "file": rel, "kind": f.kind, "packages": len(res.packages),
                        "images": [i["image"] for i in res.images]})
    for p, reason in disc.unsupported:
        warnings.append(f"{_rel(base, p)}: {reason}")

    ginv, gwarn = inventory.load_global()
    finv, inv_warn = inventory.load(base)
    inv = {**ginv, **finv}  # the folder's own patchqueue.yml wins
    warnings += gwarn + inv_warn
    reports = [(rp, _rel(base, rp)) for rp in disc.reports]
    reports += [(Path(x).expanduser().resolve(), str(x)) for x in extra_reports]
    log(f"{label}: {len(disc.files)} files, {len(packages)} packages, {len(images)} images, "
        f"{len(reports)} scanner reports")
    return _assemble(str(root), label, packages, images, systems, warnings, inv, reports,
                     offline, use_nvd, nvd_max, missing_report_hint="folder", covered_images=covered_images)


def docker_root_key() -> str:
    return f"docker://{socket.gethostname()}"


def scan_docker(offline=False, use_nvd=True, nvd_max=None, inv=None, log=None):
    """Scan the images of containers running right now, via Trivy."""
    log = log or (lambda _m: None)
    containers, warnings = dockerscan.running_containers()
    images = [{"image": c["image"], "service": c.get("service") or c["name"],
               "system": c.get("service") or c["name"], "file": "running container",
               "aliases": [k for k in (c["name"], c.get("project")) if k],
               "published_ports": c["published"], "unresolved": False} for c in containers]
    reports = []
    if containers:
        log(f"running containers: {len(containers)} found")
        paths, w = dockerscan.trivy_reports(sorted({c["image"] for c in containers}), offline=offline, log=log)
        warnings += w
        reports = [(p, f"trivy: {img}") for img, p in paths.items()]
    systems = [{"name": c["name"], "file": "running container", "kind": "docker", "packages": 0,
                "images": [c["image"]]} for c in containers]
    ginv, gwarn = inventory.load_global()
    warnings += gwarn
    return _assemble(docker_root_key(), "Running containers", [], images, systems, warnings,
                     {**ginv, **(inv or {})}, reports, offline, use_nvd, nvd_max, missing_report_hint="docker")


def _assemble(root_key, label, packages, images, systems, warnings, inv, reports,
              offline, use_nvd, nvd_max, missing_report_hint="folder", covered_images=()):
    image_keys, image_system = {}, {}
    for im in images:
        full, repo = model.normalize_image(im["image"])
        image_keys.setdefault(full, set()).update({im["system"], full, repo, *im.get("aliases", [])})
        image_system.setdefault(full, set()).add(im["system"])

    report_findings, covered = [], {model.normalize_image(i)[0] for i in covered_images}
    for rp, label_rp in reports:
        try:
            rr = imports.load(rp, label=label_rp)
        except (imports.ReportError, OSError) as e:
            warnings.append(str(e))
            continue
        covered |= rr.images
        for fnd in rr.findings:
            for loc in fnd["locations"]:
                if loc.get("image"):
                    full, repo = model.normalize_image(loc["image"])
                    extra = image_keys.get(full)
                    if extra:
                        fnd["match_keys"] = sorted(set(fnd["match_keys"]) | extra)
                        loc["system"] = ", ".join(sorted(image_system[full]))
        report_findings += rr.findings
        if missing_report_hint == "folder":
            systems.append({"name": rr.kind + " report", "file": label_rp, "kind": rr.kind,
                            "packages": len({(f['package'], f['installed']) for f in rr.findings}),
                            "images": sorted(rr.images)})

    need_report = [im for im in images
                   if model.normalize_image(im["image"])[0] not in covered and not im.get("unresolved")]
    if need_report and missing_report_hint == "folder":
        cmds = "; ".join(f"`trivy image --format json -o trivy-{_safe(i['image'])}.json {i['image']}`"
                         for i in need_report[:5])
        warnings.append(f"{len(need_report)} image(s) found but NOT checked — PatchQ needs a Trivy/Grype "
                        f"report for image contents. Run {cmds}{' …' if len(need_report) > 5 else ''} "
                        "in this folder; PatchQ picks up trivy*/grype*.json automatically. "
                        "Or run `patchq scan --docker` to scan running containers automatically.")
    elif need_report:
        warnings.append(f"{len(need_report)} running container image(s) were NOT checked: "
                        + ", ".join(sorted({i['image'] for i in need_report})[:6]))
    for im in images:
        if im.get("published_ports"):
            keys = [im["system"], *im.get("aliases", []), *model.normalize_image(im["image"])]
            exposed, _, matched = inventory.lookup(inv, keys)
            if not exposed and not matched:
                where = "~/.patchqueue/patchqueue.yml" if missing_report_hint == "docker" else "patchqueue.yml"
                warnings.append(f"'{im['system']}' publishes ports — add it to {where} with `exposed: true` if it's "
                                "reachable from the internet (moves its items up a tier), or `exposed: false` to "
                                "silence this")

    results, osv_status = osv.lookup(packages, offline=offline)
    findings = []
    for p in packages:
        for rec in results.get(osv.key(p), []):
            if not rec.get("withdrawn"):
                findings.append(osv.finding_from_osv(rec, p))
    findings = model.merge_findings(findings + report_findings)

    kev_index, kev_status = kev.load(offline=offline)
    cve_ids = {i for f in findings for i in [f["id"], *f.get("aliases", [])] if model.is_cve(i)}
    scores, epss_status = epss.load(cve_ids, offline=offline)
    for f in findings:
        for i in [f["id"], *f.get("aliases", [])]:
            iu = str(i).upper()
            if f.get("kev") is None and iu in kev_index:
                f["kev"] = kev_index[iu]
            if f.get("epss") is None and scores.get(iu, {}).get("epss") is not None:
                s = scores[iu]
                f.update(epss=s["epss"], epss_percentile=s.get("percentile"), epss_date=s.get("date"))

    nvd_status = cache.Status("NVD")
    if use_nvd:
        wanted = []
        for f in findings:
            exposed, _, _ = inventory.lookup(inv, f.get("match_keys"))
            if model.is_cve(f["id"]) and (f.get("cvss") is None or (exposed and f.get("fixed"))):
                wanted.append((0 if exposed else 1, -(f.get("epss") or 0), f["id"]))
        nvd_data, nvd_status = nvd.load([w[2] for w in sorted(wanted)], offline=offline, max_lookups=nvd_max)
        for f in findings:
            d = nvd_data.get(f["id"])
            if d:
                if f.get("cvss") is None and d.get("cvss") is not None:
                    f["cvss"], f["cvss_source"] = d["cvss"], f"NVD (CVSS {d.get('version')})"
                f["poc"] = bool(f.get("poc") or d.get("exploit_ref"))
    else:
        nvd_status.note = "disabled (--no-nvd)"

    statuses = {s.name: s.to_dict() for s in (osv_status, kev_status, epss_status, nvd_status)}
    if osv_status.unchecked:
        warnings.insert(0, f"{osv_status.unchecked} package(s) were NOT checked against OSV (feed unreachable, "
                           "no cache) — vulnerability matching did NOT run for them. Missing items here do NOT "
                           "mean you're clean. Re-run when online.")
    return {
        "root": root_key, "label": label, "scanned_at": cache.now_iso(),
        "systems": systems, "items": findings, "inventory": inv,
        "warnings": warnings, "sources": statuses, "packages": len(packages), "images": len(images),
    }


def _safe(img):
    return "".join(c if c.isalnum() or c in "-_." else "-" for c in img)[:60]
