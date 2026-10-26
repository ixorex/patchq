"""CVSS v3.x base score from a published vector (FIRST spec formulas). Computing a
score from the advisory's own vector is not guessing; no vector -> no score."""
from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def base_score_v3(vector: str):
    if not vector or not vector.startswith("CVSS:3."):
        return None
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        s = m["S"]
        av, ac, ui = _AV[m["AV"]], _AC[m["AC"]], _UI[m["UI"]]
        pr = _PR[s][m["PR"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 6.42 * iss if s == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    expl = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if s == "U":
        return _roundup(min(impact + expl, 10))
    return _roundup(min(1.08 * (impact + expl), 10))
