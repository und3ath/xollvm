"""IR-budget system gates (verbose, exhaustion, clamped, hardcap)."""

from __future__ import annotations

import re
from typing import Optional

from runner.util import count_fn_instructions

from . import register


@register("budget_verbose", needs="stderr")
def budget_verbose(stderr: str) -> Optional[str]:
    if "[budget]" not in stderr:
        return "no [budget] lines in verbose output"
    if not re.search(r"\[budget\].*->", stderr):
        return "no per-pass delta lines"
    return None


@register("budget_exhaustion", needs="stderr")
def budget_exhaustion(stderr: str) -> Optional[str]:
    if "EXHAUSTED" not in stderr and "skipping" not in stderr.lower():
        return "expected budget exhaustion (pass skipping) but none found"
    return None


# Parametric gates — dispatched directly from gates.run_gate via name match.

def budget_clamped(ir: str, base_ir: str, multiplier: int) -> Optional[str]:
    base_n = count_fn_instructions(base_ir, "obf_target")
    obf_n  = count_fn_instructions(ir, "obf_target")
    if base_n == 0:
        return "couldn't count base instructions"
    limit = base_n * multiplier
    if obf_n > limit * 1.3:
        return (f"budget overflow: {obf_n} > {limit} "
                f"(base={base_n}×{multiplier}, +30% tolerance)")
    return None


def budget_hardcap(ir: str, cap: int) -> Optional[str]:
    n = count_fn_instructions(ir, "obf_target")
    if n > cap * 1.3:
        return f"hard cap exceeded: {n} > {cap} (+30% tolerance)"
    return None
