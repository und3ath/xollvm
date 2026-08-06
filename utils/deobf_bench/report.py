"""Console table + JSON report for the deobfuscation bench."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from runner.fmt import DIM, RST, badge_fail, badge_pass, badge_skip, bold, dim

from . import cases as cases_mod
from .scorer import CaseScore, overall_resilience


def _badge(status: str) -> str:
    return {"PASS": badge_pass(), "SKIP": badge_skip(), "FAIL": badge_fail()}[status]


def _resilience_str(r: float | None) -> str:
    if r is None:
        return f"{DIM()}—{RST()}"
    pct = r * 100
    return f"{pct:5.1f}%"


def _config_str(case_name: str) -> str:
    case = cases_mod.find(case_name)
    if case is None:
        return ""
    # annotation is "obf: pass1(k=v,...), pass2(...)" — the "obf: " prefix
    # is redundant in a report column, drop it.
    return case.annotation[len("obf: "):] if case.annotation.startswith("obf: ") else case.annotation


def print_table(scores: List[CaseScore]) -> None:
    if not scores:
        print(dim("  (no results)"))
        return

    rows = sorted(scores, key=lambda s: (s.attack, s.case))
    name_w = max(len(s.case) for s in rows)
    tool_w = max(len(s.tool) for s in rows)

    print(bold(f"  {'case'.ljust(name_w)}  {'tool'.ljust(tool_w)}  status  resilience"))
    for s in rows:
        print(f"  {s.case.ljust(name_w)}  {s.tool.ljust(tool_w)}  "
              f"{_badge(s.status)}  {_resilience_str(s.resilience)}")
        print(f"  {' ' * name_w}  {dim(f'technique: {s.technique}')}")
        config = _config_str(s.case)
        if config:
            print(f"  {' ' * name_w}  {dim(f'config:    {config}')}")
        print(f"  {' ' * name_w}  {dim(f'detail:    {s.detail}')}")
        print()

    overall = overall_resilience(rows)
    if overall is None:
        print(dim("  overall resilience: — (no attack produced a score)"))
    else:
        print(bold(f"  overall resilience: {overall * 100:.1f}%"))


def write_json_report(scores: List[CaseScore], path: Path) -> None:
    data = {
        "summary": {
            "total_cases": len(scores),
            "pass": sum(1 for s in scores if s.status == "PASS"),
            "skip": sum(1 for s in scores if s.status == "SKIP"),
            "fail": sum(1 for s in scores if s.status == "FAIL"),
            "overall_resilience": overall_resilience(scores),
        },
        "cases": [
            {
                "case": s.case,
                "attack": s.attack,
                "tool": s.tool,
                "technique": s.technique,
                "config": _config_str(s.case),
                "status": s.status,
                "resilience": s.resilience,
                "n_pass": s.n_pass,
                "n_skip": s.n_skip,
                "n_fail": s.n_fail,
                "detail": s.detail,
            }
            for s in scores
        ],
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
