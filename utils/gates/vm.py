"""VM pass v7 core structural IR gates."""

from __future__ import annotations

import re
from typing import Optional

from . import register
from ._ir import extract_fn_body


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


@register("vm_lazydecrypt_keystream_call")
def vm_lazydecrypt_keystream_call(ir: str) -> Optional[str]:
    # The whole AES stub module (incl. the __obf_aes_ctr_keystream_block
    # *definition*) is linked in whenever useAES=1, lazy or not, so a bare
    # substring match on the callee name would always pass. Require an
    # actual `call` instruction instead — only the lazy fetch path emits one.
    if not re.search(r"\bcall\b[^\n]*@__obf_aes_ctr_keystream_block\s*\(", ir):
        return ("no call to __obf_aes_ctr_keystream_block found — "
                "lazy per-block fetch path not emitted")
    return None


@register("vm_lazydecrypt_ctor_no_bulk_decrypt")
def vm_lazydecrypt_ctor_no_bulk_decrypt(ir: str) -> Optional[str]:
    # Scoped to the .vm.ctor function bodies specifically: the linked-in AES
    # stub also contains __aes_decrypt (strenc's entry point), whose body
    # itself calls __obf_aes_ctr_decrypt — that call is unrelated and would
    # false-negative a whole-module substring/regex check.
    ctor_bodies = re.findall(
        r"define[^\n]*@\"?[\w.$]*\.vm\.ctor[\w.$]*\"?\s*\([^\n]*\{(.*?)\n\}",
        ir, re.DOTALL)
    if not ctor_bodies:
        return "no .vm.ctor function found — AES ctor not built"
    for body in ctor_bodies:
        if re.search(r"\bcall\b[^\n]*@__obf_aes_ctr_decrypt\s*\(", body):
            return ("vm ctor calls __obf_aes_ctr_decrypt — whole-buffer "
                     "decrypt was not removed under lazyDecrypt")
    return None


@register("vm_constinstream_no_plaintext_magic")
def vm_constinstream_no_plaintext_magic(ir: str) -> Optional[str]:
    # programs/vm/switch_dispatch.c.tmpl's obf_classify() case 1 does
    # `r = x ^ 0xABCDu;` (43981 decimal). Without constInStream this i32
    # constant is seeded by a plaintext `store i32 43981, ...` in vm.entry /
    # the shared-engine wrapper's preload section. Under constInStream it is
    # folded into the encrypted bytecode stream as an OP_LOADI prologue
    # instruction instead, so the plaintext store must be gone.
    if re.search(r"store i32 43981\b", ir):
        return ("plaintext `store i32 43981` (0xABCDu) found — constant "
                 "was not moved into the bytecode stream")
    return None


@register("vm_nestedvm_dual_engine")
def vm_nestedvm_dual_engine(ir: str) -> Optional[str]:
    # nestedVM=1 targets EngineId 1 (@__vm_engine.nest) for the outer
    # function, but every nested-eligible opcode's helper is always
    # inner-virtualized against EngineId 0 (@__vm_engine, plain) -- that's
    # what makes the depth-2 recursion terminate. Both engine functions must
    # therefore be present. Off (nestedVM=0) only @__vm_engine exists.
    if "@__vm_engine(" not in ir:
        return "@__vm_engine (plain) not found"
    if "@__vm_engine.nest(" not in ir:
        return "@__vm_engine.nest not found — nesting engine was not built"
    return None


@register("vm_nestedvm_helper_virtualized")
def vm_nestedvm_helper_virtualized(ir: str) -> Optional[str]:
    # At least one __vm_h_* pure helper (see kNestedHelperOrder in
    # VMPass_Impl.cpp) must exist, and it must itself have been virtualized
    # -- proven by its own per-function handler table (<name>.vm.ophandlers)
    # referencing the PLAIN engine (@__vm_engine), never the nesting engine.
    # A helper left un-virtualized would still be a bare switch/ret function
    # with no .vm.ophandlers table at all.
    tables = re.findall(r"@__vm_h_\w+\.vm\.ophandlers\s*=[^\n]*", ir)
    if not tables:
        return "no @__vm_h_*.vm.ophandlers table found — nested helper was never virtualized"
    for line in tables:
        if re.search(r"@__vm_engine(?!\.nest)\b", line):
            return None
    return "nested helper handler table(s) do not reference the plain @__vm_engine"


@register("vm_threaded_no_central_dispatch")
def vm_threaded_no_central_dispatch(ir: str) -> Optional[str]:
    # threadedDispatch: every handler inlines its own fetch/decode/indirectbr
    # tail (see emitThreadedTail() in VMPass_Impl.cpp) instead of routing
    # through one shared vm.dispatch/vm.fetch pair. Two independent signals:
    # no vm.fetch block anywhere, and __vm_engine ends up with far more than
    # the single indirectbr a central-dispatch build has (one per handler).
    if re.search(r"\bvm\.fetch\b", ir):
        return "vm.fetch block found — central dispatch was not threaded away"
    engine = extract_fn_body(ir, "__vm_engine")
    if engine is None:
        return "__vm_engine function body not found"
    n = len(re.findall(r"\bindirectbr\b", engine))
    if n <= 1:
        return f"__vm_engine has only {n} indirectbr(s) — dispatch was not inlined per-handler"
    return None


@register("vm_no_threaded_dispatch")
def vm_no_threaded_dispatch(ir: str) -> Optional[str]:
    # Inverse of vm_threaded_no_central_dispatch — proves the central
    # vm.dispatch/vm.fetch pair (and its single indirectbr) is intact when
    # threadedDispatch=0.
    if not re.search(r"\bvm\.fetch\b", ir):
        return "vm.fetch block not found — central dispatch pair missing"
    engine = extract_fn_body(ir, "__vm_engine")
    if engine is None:
        return "__vm_engine function body not found"
    n = len(re.findall(r"\bindirectbr\b", engine))
    if n != 1:
        return f"__vm_engine has {n} indirectbr(s), expected exactly 1 (central dispatch)"
    return None


@register("vm_keyeddisp_ip_xor")
def vm_keyeddisp_ip_xor(ir: str) -> Optional[str]:
    # keyedDispatch: VMImpl::opKeyByteIR computes a per-IP XOR key (named
    # ...vm.opk*) that emitThreadedTail/buildDispatch XOR into the raw fetched
    # opcode byte (result named ...vm.opd) before it's mapped to a handler.
    # Both name fragments only appear when keyedDispatch=1 emits the
    # un-XOR sequence.
    if not re.search(r"vm\.opk", ir):
        return "no vm.opk value found — opKeyByteIR key mix not emitted"
    if not re.search(r"vm\.opd", ir):
        return "no vm.opd value found — opcode-byte un-XOR not emitted"
    return None


@register("vm_no_keyeddisp")
def vm_no_keyeddisp(ir: str) -> Optional[str]:
    # Inverse of vm_keyeddisp_ip_xor — proves the per-IP opcode-byte XOR is
    # absent when keyedDispatch=0.
    if re.search(r"vm\.opk|vm\.opd", ir):
        return "vm.opk/vm.opd found but keyedDispatch=0"
    return None
