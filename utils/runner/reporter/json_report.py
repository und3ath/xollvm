"""Machine-readable JSON test report."""

from __future__ import annotations

import json
from pathlib import Path


def write_json_report(results: list, path: Path) -> None:
    data = {
        "summary": {
            "total":   len(results),
            "passed":  sum(1 for r in results if r.status == "PASS"),
            "failed":  sum(1 for r in results if r.status == "FAIL"),
            "skipped": sum(1 for r in results if r.status == "SKIP"),
            "elapsed": round(sum(r.elapsed for r in results), 3),
        },
        "tests": [
            {
                "name":       r.name,
                "category":   r.category,
                "status":     r.status,
                "elapsed":    round(r.elapsed, 3),
                "reason":     r.reason,
                "base_insts": r.base_insts,
                "obf_insts":  r.obf_insts,
                "growth":     round(r.obf_insts / r.base_insts, 2)
                              if r.base_insts > 0 and r.obf_insts > 0 else 0,
                "seeds":      r.seeds_run,
                "inputs":     r.inputs_run,
                "report_json": r.report_json,
                "report_html": r.report_html,
                "cross":       getattr(r, "cross", {}),
            }
            for r in results
        ],
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
