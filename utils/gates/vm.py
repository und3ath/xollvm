"""VM pass v7 core structural IR gates."""

from __future__ import annotations

import re
from typing import Optional

from . import register


@register("vm_dispatch_present")
def vm_dispatch_present(ir: str) -> Optional[str]:
    if not re.search(r"vm\.dispatch\b", ir):
        return "vm.dispatch block not found — virtualisation did not run"
    return None


@register("vm_entry_present")
def vm_entry_present(ir: str) -> Optional[str]:
    if not re.search(r"vm\.entry\b", ir):
        return "vm.entry block not found"
    return None


@register("vm_bytecode_global")
def vm_bytecode_global(ir: str) -> Optional[str]:
    if not re.search(r"vm\.bytecode\b", ir):
        return "no vm.bytecode global found — BytecodeEmitter did not run"
    return None


@register("vm_ophandlers_global")
def vm_ophandlers_global(ir: str) -> Optional[str]:
    if not re.search(r"vm\.ophandlers\b", ir):
        return "no vm.ophandlers global found"
    return None


@register("vm_indirectbr")
def vm_indirectbr(ir: str) -> Optional[str]:
    if "indirectbr" not in ir:
        return "no indirectbr found — opcode dispatch is not indirect"
    return None


@register("vm_regs_alloca")
def vm_regs_alloca(ir: str) -> Optional[str]:
    if not re.search(r"vm\.regs\b", ir):
        return "vm.regs alloca not found"
    return None


@register("vm_no_original_blocks")
def vm_no_original_blocks(ir: str) -> Optional[str]:
    labels = re.findall(r"^(\w[\w.]*):$", ir, re.MULTILINE)
    bad = [l for l in labels if not l.startswith("vm.") and l not in ("entry",)]
    if bad:
        return f"original blocks still present: {bad[:4]}"
    return None


@register("vm_opc_blocks")
def vm_opc_blocks(ir: str) -> Optional[str]:
    expected = ["loadi","movr","binop","icmp","cast","ptrtoint","inttoptr",
                "load32","store32","gep","jmp","jmpc",
                "ret_void","ret_int","ret_ptr",
                "call_void","call_int","call_ptr",
                "loadi_f","movr_f","binop_f","fcmp",
                "fcast_ff","fcast_fv","fcast_fv64","fcast_vf","fcast_v64f",
                "load_f","store_f","ret_f","select_f","fneg",
                "load_f32","store_f32",
                "call_int64","call_f",
                ]
    missing = [n for n in expected if not re.search(r"vm\.opc\." + n + r"\b", ir)]
    if missing:
        return f"missing opcode handler blocks: {missing}"
    return None


@register("vm_bytecode_nonempty")
def vm_bytecode_nonempty(ir: str) -> Optional[str]:
    m = re.search(r"vm\.bytecode[^[]*\[(\d+)\s*x\s*i8\]", ir)
    if not m:
        return "vm.bytecode global not found or malformed"
    size = int(m.group(1))
    if size == 0:
        return "vm.bytecode has 0 bytes — bytecode emitter produced nothing"
    return None


@register("vm_pregs_alloca")
def vm_pregs_alloca(ir: str) -> Optional[str]:
    if not re.search(r"vm\.pregs\b", ir):
        return "vm.pregs alloca not found — ptr register file not allocated"
    return None


@register("vm_salt_volatile")
def vm_salt_volatile(ir: str) -> Optional[str]:
    if not re.search(r"load volatile.*vm\.salt|volatile.*load.*vm\.salt", ir):
        if "vm.salt" not in ir:
            return "vm.salt alloca not found"
        return "vm.salt load is not volatile"
    return None


@register("vm_enc_ctor")
def vm_enc_ctor(ir: str) -> Optional[str]:
    if not (re.search(r"vm\.ctor\.aes\b", ir) or re.search(r"ctor\.loop\b", ir)):
        return "encryption constructor not found (neither AES nor LCG path)"
    return None


@register("vm_no_enc_ctor")
def vm_no_enc_ctor(ir: str) -> Optional[str]:
    if re.search(r"ctor\.loop\b", ir) or re.search(r"vm\.ctor\.aes\b", ir):
        return "encryption ctor found but encBytecode=0"
    return None


@register("vm_callees_global")
def vm_callees_global(ir: str) -> Optional[str]:
    if not re.search(r"vm\.callees\b", ir):
        return "vm.callees global not found (required for call virtualisation)"
    return None


@register("vm_fregs_alloca")
def vm_fregs_alloca(ir: str) -> Optional[str]:
    if not re.search(r"vm\.fregs\b", ir):
        return "vm.fregs alloca not found — float register file not allocated"
    return None


@register("vm_aes_ctor")
def vm_aes_ctor(ir: str) -> Optional[str]:
    if not re.search(r"vm\.ctor\.aes\b", ir):
        return "vm.ctor.aes block not found — AES ctor not built"
    return None


@register("vm_aes_no_lcg_constants")
def vm_aes_no_lcg_constants(ir: str) -> Optional[str]:
    for c in ("6364136223846793005", "1442695040888963407"):
        if c in ir:
            return f"LCG constant {c} found in IR — useAES should have replaced LCG"
    return None


@register("vm_aes_globals")
def vm_aes_globals(ir: str) -> Optional[str]:
    if not re.search(r"vm\.aes\.rk\b", ir):
        return "vm.aes.rk global not found — AES expanded key not emitted"
    if not re.search(r"vm\.aes\.nonce\b", ir):
        return "vm.aes.nonce global not found — AES nonce not emitted"
    return None


@register("vm_obf_aes_ctr_present")
def vm_obf_aes_ctr_present(ir: str) -> Optional[str]:
    if "__obf_aes_ctr_decrypt" not in ir:
        return "__obf_aes_ctr_decrypt not found — AES stub not linked"
    return None
