from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ParseResult:
    """What a parser returns.

    packages: [{name, version, ecosystem, direct, dev, approx}] (+ optional "file")
    images:   [{image, service, published_ports, unresolved}]
    warnings: human-readable strings — shown to the user, never swallowed
    """
    packages: list = field(default_factory=list)
    images: list = field(default_factory=list)
    warnings: list = field(default_factory=list)


MAX_BYTES = 50 * 1024 * 1024


def read_text(path) -> str:
    if path.stat().st_size > MAX_BYTES:
        raise ValueError(f"file larger than {MAX_BYTES // (1024 * 1024)} MB — skipped")
    return path.read_text(encoding="utf-8", errors="replace")
