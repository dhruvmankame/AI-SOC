from __future__ import annotations

import re

DETECTOR_FAMILY = {
    "R-NET-BRUTEFORCE": "brute_force",
    "R-NET-FLOOD": "flood",
    "flow_rate_zscore": "flood",
    "R-NET-BEACON": "beacon",
}

TECHNIQUE_FAMILY = {
    "T1110": "brute_force",
    "T1498": "flood",
    "T1499": "flood",
    "T1071": "beacon",
    "T1571": "beacon",
}

TITLE_FAMILY_RULES = [
    (re.compile(r"brute[\s-]?force|credential", re.I), "brute_force"),
    (re.compile(r"beacon|\bc2\b|command and control|botnet", re.I), "beacon"),
    (re.compile(r"flood|\bddos\b|denial of service", re.I), "flood"),
]


def families_of_techniques(techniques: list[str]) -> set[str]:
    return {TECHNIQUE_FAMILY[t] for t in techniques if t in TECHNIQUE_FAMILY}


def family_from_title(title: str | None) -> str | None:
    if not title:
        return None
    for pattern, family in TITLE_FAMILY_RULES:
        if pattern.search(title):
            return family
    return None


def technique_conflict(technique: str, behavioural_refs: list[str]) -> str | None:
    claimed = TECHNIQUE_FAMILY.get(technique)
    if not claimed:
        return None
    present = sorted({
        DETECTOR_FAMILY[ref]
        for ref in behavioural_refs
        if ref in DETECTOR_FAMILY
    })
    if not present or claimed in present:
        return None
    return (
        f"technique {technique} ({claimed}) is contradicted by the detectors behind "
        f"the cited evidence ({', '.join(present)}); the claim describes a different "
        "attack family than the flows it cites"
    )
