"""One parser per input type. To add one: write `parse(path) -> ParseResult`,
register it in PARSERS and in discovery.classify(), add a fixture + test."""
from __future__ import annotations

from . import docker, npm, python
from .base import ParseResult

PARSERS = {
    "npm-lock": npm.parse_lock,
    "npm-manifest": npm.parse_manifest,
    "requirements": python.parse_requirements,
    "poetry": python.parse_poetry,
    "pipenv": python.parse_pipfile_lock,
    "compose": docker.parse_compose,
    "dockerfile": docker.parse_dockerfile,
}


def parse(path, kind) -> ParseResult:
    """Never raises for a bad file: the failure becomes a visible warning."""
    try:
        return PARSERS[kind](path)
    except Exception as e:  # noqa: BLE001
        return ParseResult(warnings=[f"could not parse ({type(e).__name__}: {e}) — this file was NOT checked"])


__all__ = ["PARSERS", "ParseResult", "parse"]
