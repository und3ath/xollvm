"""MBA / opaque-predicate IR gates."""

from __future__ import annotations

import re
from typing import Optional

from . import register


@register("mba_advanced")
def mba_advanced(ir: str) -> Optional[str]:
    mul  = len(re.findall(r"\bmul i32\b", ir))
    urem = len(re.findall(r"\burem i32\b", ir))
    ops  = sum(len(re.findall(rf"\b{op} i32\b", ir))
               for op in ("add", "sub", "xor", "and", "or", "shl", "lshr"))
    if ops < 60:
        return f"too few i32 ops ({ops}, need ≥60)"
    if mul < 8:
        return f"need ≥8 mul i32, got {mul}"
    if urem == 0 and mul < 20:
        return "no urem and insufficient mul for nonlinear MBA"
    return None


@register("opaque_families")
def opaque_families(ir: str) -> Optional[str]:
    if any(t in ir for t in ("obf.mba.", "obf.mod.", "obf.hash.", "obf.ptr.")):
        return None
    icmp = len(re.findall(r"\bicmp (eq|ne|ugt|ult|slt|sgt)\b", ir))
    vload = len(re.findall(r"load volatile i32", ir))
    if icmp < 20:
        return f"too few icmp ({icmp}, need ≥20)"
    if vload < 4:
        return f"too few volatile loads ({vload}, need ≥4)"
    return None
