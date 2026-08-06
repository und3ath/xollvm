"""Aggregate AttackResults into per-case and overall resilience scores."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from .attacks import AttackResult


@dataclass
class CaseScore:
    case: str
    attack: str
    status: str            # worst status across seeds: FAIL > SKIP > PASS
    resilience: float | None  # mean over PASS seeds; None if no PASS seed
    n_pass: int
    n_skip: int
    n_fail: int
    detail: str             # first non-empty detail (usually enough context)
    tool: str                # concrete deobfuscation tool used (e.g. "z3-solver")
    technique: str           # one-line description of the attack technique


def score_case(case_name: str, attack: str, results: List[AttackResult]) -> CaseScore:
    passed = [r for r in results if r.status == "PASS"]
    skipped = [r for r in results if r.status == "SKIP"]
    failed = [r for r in results if r.status == "FAIL"]

    if failed:
        status = "FAIL"
    elif not passed and skipped:
        status = "SKIP"
    elif passed:
        status = "PASS"
    else:
        status = "SKIP"

    resilience = None
    if passed:
        resilience = sum(r.resilience for r in passed if r.resilience is not None) / len(passed)

    detail_source = failed or passed or skipped
    detail = detail_source[0].detail if detail_source else ""
    tool = results[0].tool if results else ""
    technique = results[0].technique if results else ""

    return CaseScore(case_name, attack, status, resilience, len(passed), len(skipped), len(failed),
                      detail, tool, technique)


def group_by_case(results: List[AttackResult]) -> List[CaseScore]:
    grouped: Dict[tuple[str, str], List[AttackResult]] = {}
    for r in results:
        grouped.setdefault((r.case, r.attack), []).append(r)
    return [score_case(case, attack, rs) for (case, attack), rs in grouped.items()]


def overall_resilience(scores: List[CaseScore]) -> float | None:
    vals = [s.resilience for s in scores if s.resilience is not None]
    if not vals:
        return None
    return sum(vals) / len(vals)
