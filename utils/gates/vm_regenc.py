"""VM pass v7 register-value-encryption gates (Step 05)."""

from __future__ import annotations

import re
from typing import Optional

from . import register
from ._ir import extract_fn_body


@register("vm_regenc_key_alloca")
def vm_regenc_key_alloca(ir: str) -> Optional[str]:
    if not re.search(r"vm\.regkeys\b", ir):
        return "vm.regkeys alloca not found — i32 register key array missing"
    if not re.search(r"vm\.reg64keys\b", ir):
        return "vm.reg64keys alloca not found — i64 register key array missing"
    return None


@register("vm_regenc_key_loads")
def vm_regenc_key_loads(ir: str) -> Optional[str]:
    engine = extract_fn_body(ir, "__vm_engine")
    if engine is None:
        return "__vm_engine not found"
    rk32 = len(re.findall(r"vm\.rk\.v", engine))
    rk64 = len(re.findall(r"vm\.rk64\.v", engine))
    total = rk32 + rk64
    if total < 4:
        return f"too few register key loads in __vm_engine ({total}, need >=4)"
    return None


@register("vm_regenc_key_geps")
def vm_regenc_key_geps(ir: str) -> Optional[str]:
    engine = extract_fn_body(ir, "__vm_engine")
    if engine is None:
        return "__vm_engine not found"
    rk_gep = len(re.findall(r"vm\.rk\.p", engine))
    rk64_gep = len(re.findall(r"vm\.rk64\.p", engine))
    total = rk_gep + rk64_gep
    if total < 4:
        return f"too few register key GEPs in __vm_engine ({total}, need >=4)"
    return None


@register("vm_regenc_pregs_exempt")
def vm_regenc_pregs_exempt(ir: str) -> Optional[str]:
    engine = extract_fn_body(ir, "__vm_engine")
    if engine is None:
        return "__vm_engine not found"
    pr_dec = len(re.findall(r"vm\.pg\.dec\b", engine))
    pr_enc = len(re.findall(r"vm\.pg\.enc\b", engine))
    if pr_dec > 0 or pr_enc > 0:
        return f"pointer registers must NOT be encrypted (found pr.dec={pr_dec}, pr.enc={pr_enc})"
    return None


@register("vm_regenc_freg_key")
def vm_regenc_freg_key(ir: str) -> Optional[str]:
    if not re.search(r"vm\.fregkeys\b", ir):
        return "vm.fregkeys alloca not found — float register key array missing"
    return None
