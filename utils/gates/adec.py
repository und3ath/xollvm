"""Anti-decompiler IR gates."""

from __future__ import annotations

from typing import Optional

from . import register


@register("adec_patterns")
def adec_patterns(ir: str) -> Optional[str]:
    checks = {
        "asm":      ("asm sideeffect" in ir and (".byte" in ir or ".4byte" in ir or "b 1f" in ir)),
        "ibr":      "indirectbr" in ir or "adec.ibr" in ir,
        "dead":     "adec.dead" in ir or "adec.dk" in ir,
        "stack":    "adec.stk" in ir,
        "call":     "adec.fp" in ir,
        "alias":    "adec.al" in ir,
    }
    found = [k for k, v in checks.items() if v]
    if len(found) < 2:
        return f"only {len(found)}/6 adec techniques: {found or 'none'}"
    return None


@register("adec_type_confusion")
def adec_type_confusion(ir: str) -> Optional[str]:
    has_i2f = "sitofp" in ir or "uitofp" in ir
    has_f2i = "fptoui" in ir or "fptosi" in ir
    if not (has_i2f and has_f2i):
        return "missing int↔float cross-casts in dead-code decoys"
    return None


@register("adec_indirectbr")
def adec_indirectbr(ir: str) -> Optional[str]:
    if "indirectbr" not in ir:
        return "no indirectbr found"
    if "blockaddress" not in ir:
        return "no blockaddress found"
    return None
