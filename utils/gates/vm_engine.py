"""VM pass v7 shared-engine gates (Step 06)."""

from __future__ import annotations

import re
from typing import Optional

from . import register
from ._ir import extract_fn_body


@register("vm_engine_exists")
def vm_engine_exists(ir: str) -> Optional[str]:
    if "define internal void @__vm_engine(" not in ir:
        return "@__vm_engine function not found — shared engine not created"
    return None


@register("vm_engine_singleton")
def vm_engine_singleton(ir: str) -> Optional[str]:
    count = ir.count("define internal void @__vm_engine(")
    if count == 0:
        return "@__vm_engine not found"
    if count != 1:
        return f"expected 1 __vm_engine definition, found {count}"
    return None


@register("vm_wrapper_calls_engine")
def vm_wrapper_calls_engine(ir: str) -> Optional[str]:
    fn = extract_fn_body(ir, "obf_target")
    if fn is None:
        return "obf_target function not found"
    has_direct   = "call void @__vm_engine(" in fn
    has_indirect = bool(re.search(r"call void %[\w.]+\(", fn))
    if not has_direct and not has_indirect:
        return "obf_target does not call __vm_engine (direct or indirect) -- wrapper not generated"
    return None


@register("vm_wrapper_is_thin")
def vm_wrapper_is_thin(ir: str) -> Optional[str]:
    fn = extract_fn_body(ir, "obf_target")
    if fn is None:
        return "obf_target function not found"
    handler_labels = re.findall(r"^vm\.opc\.\w+:", fn, re.MULTILINE)
    if handler_labels:
        return f"obf_target contains handler blocks: {handler_labels[:4]}"
    if "indirectbr" in fn:
        return "obf_target contains indirectbr — should only be in __vm_engine"
    return None


@register("vm_engine_has_handlers")
def vm_engine_has_handlers(ir: str) -> Optional[str]:
    engine = extract_fn_body(ir, "__vm_engine")
    if engine is None:
        return "__vm_engine function body not found"
    expected = ["loadi", "movr", "binop", "icmp", "cast", "ptrtoint", "inttoptr",
                "load32", "store32", "gep", "jmp", "jmpc",
                "ret_void", "ret_int", "ret_ptr",
                "call_void", "call_int", "call_ptr"]
    missing = [n for n in expected if not re.search(r"vm\.opc\." + n + r"\b", engine)]
    if missing:
        return f"__vm_engine missing handler blocks: {missing}"
    return None


@register("vm_engine_indirectbr")
def vm_engine_indirectbr(ir: str) -> Optional[str]:
    engine = extract_fn_body(ir, "__vm_engine")
    if engine is None:
        return "__vm_engine function body not found"
    if "indirectbr" not in engine:
        return "__vm_engine has no indirectbr — dispatch not indirect"
    return None


@register("vm_engine_dispatch")
def vm_engine_dispatch(ir: str) -> Optional[str]:
    engine = extract_fn_body(ir, "__vm_engine")
    if engine is None:
        return "__vm_engine function body not found"
    if not re.search(r"vm\.dispatch\b", engine):
        return "vm.dispatch not found in __vm_engine"
    return None


@register("vm_multi_fn_shared")
def vm_multi_fn_shared(ir: str) -> Optional[str]:
    handler_globals = re.findall(r"@\w+\.vm\.ophandlers\b", ir)
    engine_refs = ir.count("blockaddress(@__vm_engine,")
    if len(handler_globals) < 2:
        return f"expected 2+ per-function handler tables, found {len(handler_globals)}"
    if engine_refs < 2:
        return f"expected blockaddress(@__vm_engine) in multiple tables, found {engine_refs} refs"
    defcount = ir.count("define internal void @__vm_engine(")
    if defcount != 1:
        return f"expected 1 __vm_engine definition, found {defcount}"
    return None


@register("vm_handlers_permuted")
def vm_handlers_permuted(ir: str) -> Optional[str]:
    tables = re.findall(
        r"@(\w+)\.vm\.ophandlers\s*=[^[]*\[[^\]]*\]\s*\[([^\]]+)\]",
        ir,
    )
    if len(tables) < 2:
        return None
    entries_a = [x.strip() for x in tables[0][1].split(",")]
    entries_b = [x.strip() for x in tables[1][1].split(",")]
    if entries_a == entries_b:
        return f"handler tables for {tables[0][0]} and {tables[1][0]} identical"
    return None
