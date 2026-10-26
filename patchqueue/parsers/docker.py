"""Docker / homelab: compose files and Dockerfile FROM lines -> image references.

PatchQ does not scan image contents itself (Trivy and Grype already do that
well). Images found here are matched against Trivy/Grype JSON reports; any
image without a report is listed with the exact command to produce one.
"""
from __future__ import annotations

import re

from .. import miniyaml
from .base import ParseResult, read_text

_IMAGE_LINE = re.compile(r"""^\s*-?\s*image:\s*["']?([^"'\s#]+)""", re.M)


def parse_compose(path) -> ParseResult:
    res = ParseResult()
    text = read_text(path)
    try:
        data = miniyaml.loads(text)
    except Exception as e:  # noqa: BLE001 — fall back rather than drop the file
        data = None
        res.warnings.append(f"YAML not fully parsed ({e}); used line-based image extraction")
    if isinstance(data, dict):
        services = data.get("services")
        if not isinstance(services, dict):  # legacy v1 compose: services at top level
            services = {k: v for k, v in data.items() if isinstance(v, dict) and ("image" in v or "build" in v)}
        for svc, conf in services.items():
            if not isinstance(conf, dict):
                continue
            img = conf.get("image")
            if isinstance(img, str) and img.strip():
                img = img.strip()
                entry = {"image": img, "service": str(svc), "published_ports": bool(conf.get("ports")),
                         "unresolved": "$" in img}
                if entry["unresolved"]:
                    res.warnings.append(f"service '{svc}': image '{img}' uses a variable — "
                                        "PatchQ can't resolve it; scan the resolved image with Trivy and --import it")
                res.images.append(entry)
            elif conf.get("build") is not None:
                res.warnings.append(f"service '{svc}' is built locally (no image tag) — after building, run "
                                    f"`trivy image --format json -o trivy-{svc}.json <built-image>` next to this file")
    else:
        for m in _IMAGE_LINE.finditer(text):
            res.images.append({"image": m.group(1), "service": None, "published_ports": False,
                               "unresolved": "$" in m.group(1)})
    return res


_FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.I | re.M)


def parse_dockerfile(path) -> ParseResult:
    res = ParseResult()
    stages = set()
    for m in _FROM.finditer(read_text(path)):
        img, alias = m.group(1), m.group(2)
        if img.lower() == "scratch" or img in stages:
            if alias:
                stages.add(alias)
            continue
        if alias:
            stages.add(alias)
        res.images.append({"image": img, "service": None, "published_ports": False, "unresolved": "$" in img})
    return res
