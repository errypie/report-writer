"""CVSS v3.1 base score (FIRST specification). Mirrors the calculator in static/js/cvss.js."""
import math

WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def roundup(x):
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def severity(score):
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def parse(vector):
    parts = dict(p.split(":", 1) for p in vector.strip().split("/") if ":" in p)
    if parts.pop("CVSS", None) not in ("3.1", "3.0"):
        raise ValueError("not a CVSS v3 vector")
    return parts


def cvss31(vector):
    """Return (score, severity) for a CVSS:3.1 vector string. Raises ValueError if invalid."""
    m = parse(vector)
    try:
        scope = m["S"]
        iss = 1 - (1 - WEIGHTS["C"][m["C"]]) * (1 - WEIGHTS["I"][m["I"]]) * (1 - WEIGHTS["A"][m["A"]])
        if scope == "U":
            impact = 6.42 * iss
        elif scope == "C":
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            raise ValueError("bad scope")
        expl = 8.22 * WEIGHTS["AV"][m["AV"]] * WEIGHTS["AC"][m["AC"]] * PR[scope][m["PR"]] * WEIGHTS["UI"][m["UI"]]
    except KeyError as exc:
        raise ValueError("missing or invalid metric %s" % exc)
    if impact <= 0:
        score = 0.0
    elif scope == "U":
        score = roundup(min(impact + expl, 10))
    else:
        score = roundup(min(1.08 * (impact + expl), 10))
    return score, severity(score)
