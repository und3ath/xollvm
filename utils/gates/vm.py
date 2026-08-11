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


@register("vm_superops_muladd_present")
def vm_superops_muladd_present(ir: str) -> Optional[str]:
    # superOps: eligible i32 mul+add chains fuse into a single OP_MULADD
    # handler (vm.opc.muladd.*) instead of two OP_BINOP handlers. The handler
    # block itself is always built (dormant, like every other opcode in the
    # shared engine) regardless of the knob, so its mere presence doesn't
    # prove fusion fired -- this gate only asserts the block exists at all,
    # i.e. the ISA/handler machinery is wired up; differential-output gates
    # elsewhere prove the fused bytecode still computes the right answer.
    if not re.search(r"vm\.opc\.muladd\.", ir):
        return "no vm.opc.muladd.* handler block found — OP_MULADD handler missing"
    return None


@register("vm_superops_shladd_present")
def vm_superops_shladd_present(ir: str) -> Optional[str]:
    # superOps: eligible i32 shl+add chains fuse into a single OP_SHLADD
    # handler (vm.opc.shladd.*). The handler block is always built (dormant,
    # like every opcode in the shared engine) regardless of the knob, so its
    # presence only proves the ISA/handler machinery is wired; differential-
    # output gates prove the fused bytecode computes the right answer.
    if not re.search(r"vm\.opc\.shladd\.", ir):
        return "no vm.opc.shladd.* handler block found — OP_SHLADD handler missing"
    return None


@register("vm_superops_cmpsel_present")
def vm_superops_cmpsel_present(ir: str) -> Optional[str]:
    # superOps: eligible i32 icmp+select chains fuse into a single OP_CMPSEL
    # handler (vm.opc.cmpsel.*). The handler block is always built (dormant,
    # like every opcode in the shared engine) regardless of the knob, so its
    # presence only proves the ISA/handler machinery is wired; differential-
    # output gates prove the fused bytecode computes the right answer.
    if not re.search(r"vm\.opc\.cmpsel\.", ir):
        return "no vm.opc.cmpsel.* handler block found — OP_CMPSEL handler missing"
    return None


@register("vm_superops_andcmpz_present")
def vm_superops_andcmpz_present(ir: str) -> Optional[str]:
    # superOps: eligible i32 and+icmp-zero bit-tests fuse into a single
    # OP_ANDCMPZ handler (vm.opc.andcmpz.*). The handler block is always built
    # (dormant, like every opcode in the shared engine) regardless of the knob,
    # so its presence only proves the ISA/handler machinery is wired;
    # differential-output gates prove the fused bytecode computes the answer.
    if not re.search(r"vm\.opc\.andcmpz\.", ir):
        return "no vm.opc.andcmpz.* handler block found — OP_ANDCMPZ handler missing"
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


@register("vm_bindadeb_ctor_present")
def vm_bindadeb_ctor_present(ir: str) -> Optional[str]:
    # bindAntiDebug: buildAntiDebugKeyBindCtor() emits a per-function
    # .init_array constructor (name suffix .vm.adbind.ctor, priority 100 --
    # ahead of the AES decrypt ctor at 65535) that computes a debugger-
    # detection bit via IsDebuggerPresent/CheckRemoteDebuggerPresent/
    # NtQueryInformationProcess and XORs it into the masked AES round-key
    # global in the vm.adbind.combine block. Both the ctor and the detection
    # call must be present together, or this could just be buildAntiDebugGate's
    # unrelated dispatch-level gate (which also calls IsDebuggerPresent under
    # plain hardened+antiDebug, independent of bindAntiDebug).
    m = re.search(r"define[^\n]*@([\w.]+\.vm\.adbind\.ctor)\b", ir)
    if not m:
        return "no .vm.adbind.ctor constructor found"
    body = extract_fn_body(ir, m.group(1))
    if body is None:
        return "vm.adbind.ctor matched but function body extraction failed"
    if "IsDebuggerPresent" not in body:
        return "vm.adbind.ctor found but no IsDebuggerPresent call inside it"
    if not re.search(r"vm\.adbind\.combine\b", body):
        return "vm.adbind.ctor found but no vm.adbind.combine (mask-XOR) block"
    return None


@register("vm_no_bindadeb_ctor")
def vm_no_bindadeb_ctor(ir: str) -> Optional[str]:
    # Inverse of vm_bindadeb_ctor_present — proves the ctor is absent when
    # bindAntiDebug=0.
    if re.search(r"vm\.adbind\.", ir):
        return "vm.adbind.* found but bindAntiDebug=0"
    return None


# Canonical (identity) BinSubop byte encoding, straight from enum VMOp/BinSubop.
# The OP_BINOP / OP_BINOP64 handler's switch routes each subop byte value to a
# named case block; without randISA those case values equal these constants.
_RANDISA_IDENTITY = {
    "sub": 1, "mul": 2, "and": 3, "or": 4, "xor": 5, "shl": 6,
    "lshr": 7, "ashr": 8, "sdiv": 9, "udiv": 10, "srem": 11, "urem": 12,
}


def _binsubop_case_map(ir: str) -> dict:
    # Extract {case-block-name -> switch case value} from the OP_BINOP (vm.bo.*)
    # and OP_BINOP64 (vm.bo64.*) handler switches. First occurrence wins (the K
    # handler-variant copies all share the same module-uniform encoding). ADD is
    # the switch default (no explicit case), so it never appears here.
    # NB: LLVM uniquifies colliding block names by appending digits
    # (e.g. %vm.bo.sub -> %vm.bo.sub343, and the K handler-variant copies), so
    # allow a trailing \d* before the word boundary.
    out: dict = {}
    for val, name in re.findall(
        r"i32 (\d+), label %vm\.bo(?:64)?\.(sub|mul|and|or|xor|shl|lshr|ashr|sdiv|udiv|srem|urem)\d*\b",
        ir,
    ):
        out.setdefault(name, int(val))
    return out


@register("vm_randisa_permuted")
def vm_randisa_permuted(ir: str) -> Optional[str]:
    # randISA: the BinSubop byte encoding is permuted module-uniformly per build,
    # so the OP_BINOP/OP_BINOP64 handler switch routes named case blocks from
    # NON-canonical byte values. Proves the permutation actually reached the
    # handler switch-case constants (not a silent no-op). Deterministic per seed;
    # the astronomically-unlikely case of a seed reproducing the full identity
    # is guarded by checking the whole present subset at once.
    m = _binsubop_case_map(ir)
    if not m:
        return "no OP_BINOP subop switch found — cannot verify randISA permutation"
    if all(_RANDISA_IDENTITY.get(name) == val for name, val in m.items()):
        return ("OP_BINOP subop encoding is the canonical identity "
                f"({sorted(m.items())}) — randISA permutation not applied")
    return None


# Canonical ICmp predicate dispatch sequence: the OP_ICMP / OP_ICMP64 handler
# select-chain tests the decoded predicate byte against each CmpInst::Predicate
# value in the fixed emission order EQ,NE,UGT,UGE,ULT,ULE,SGT,SGE,SLT,SLE =
# 32..41. Without randISA that sequence is exactly this ascending run.
_RANDISA_ICMP_CANON = [32, 33, 34, 35, 36, 37, 38, 39, 40, 41]


def _icmp_pred_sequence(ir: str):
    # Extract the predicate-dispatch constants (icmp eq against a value in
    # 32..41, constant on the RHS = the CreateICmpEQ(Pred, k) tests) in textual
    # emission order, then return the first block of 10 IF it is a permutation of
    # the canonical set (a sanity check that we actually captured the predicate
    # dispatch and not stray comparisons). Returns None if no clean block found.
    seq = [int(n) for n in re.findall(r"icmp eq i32 %[^,\n]+, (3[2-9]|4[01])\b", ir)]
    if len(seq) < 10:
        return None
    first10 = seq[:10]
    if sorted(first10) != _RANDISA_ICMP_CANON:
        return None
    return first10


@register("vm_no_randisa")
def vm_no_randisa(ir: str) -> Optional[str]:
    # Inverse of vm_randisa_permuted — with randISA off the BinSubop encoding is
    # the canonical identity and the ICmp predicate dispatch is the ascending
    # 32..41 run. Empty maps (a program with no int binops / no icmp) trivially
    # pass: absence can't be a permutation.
    m = _binsubop_case_map(ir)
    bad = {name: val for name, val in m.items()
           if _RANDISA_IDENTITY.get(name) != val}
    if bad:
        return f"OP_BINOP subop encoding is permuted but randISA=0: {sorted(bad.items())}"
    seq = _icmp_pred_sequence(ir)
    if seq is not None and seq != _RANDISA_ICMP_CANON:
        return f"ICmp predicate dispatch is permuted but randISA=0: {seq}"
    cseq = _cast_kind_sequence(ir)
    if cseq is not None and cseq != _RANDISA_CAST_CANON:
        return f"OP_CAST kind dispatch is permuted but randISA=0: {cseq}"
    fb = _labeled_case_map(ir, "vm.bof.", _RANDISA_FBINSUBOP_CANON)
    fbbad = {k: v for k, v in fb.items() if _RANDISA_FBINSUBOP_CANON.get(k) != v}
    if fbbad:
        return f"OP_BINOP_F subop is permuted but randISA=0: {sorted(fbbad.items())}"
    fc = _labeled_case_map(ir, "vm.fcp.", _RANDISA_FCMP_CANON)
    fcbad = {k: v for k, v in fc.items() if _RANDISA_FCMP_CANON.get(k) != v}
    if fcbad:
        return f"OP_FCMP predicate is permuted but randISA=0: {sorted(fcbad.items())}"
    return None


@register("vm_randisa_icmp_permuted")
def vm_randisa_icmp_permuted(ir: str) -> Optional[str]:
    # randISA broadening: the ICmp predicate byte encoding is permuted module-
    # uniformly per build, so the OP_ICMP/OP_ICMP64 handler select-chain tests
    # the decoded predicate against a NON-canonical ordering of 32..41. Proves
    # the predicate permutation reached the handler (not a silent no-op).
    seq = _icmp_pred_sequence(ir)
    if seq is None:
        return "no OP_ICMP predicate dispatch found — cannot verify randISA permutation"
    if seq == _RANDISA_ICMP_CANON:
        return (f"ICmp predicate dispatch is the canonical order {seq} — "
                "randISA predicate permutation not applied")
    return None


# Canonical encodings for the switch/select-chain families broadened after ICmp.
# CAST is a select-chain over the kind byte 0..7 in ascending emission order.
_RANDISA_CAST_CANON = [0, 1, 2, 3, 4, 5, 6, 7]
# OP_BINOP_F switch: label -> FBinSubop value (FADD=0 is the default, no case).
_RANDISA_FBINSUBOP_CANON = {"sub": 1, "mul": 2, "div": 3, "rem": 4}
# OP_FCMP switch: label -> raw CmpInst::Predicate value (FCMP_FALSE=0 default).
_RANDISA_FCMP_CANON = {
    "oeq": 1, "ogt": 2, "oge": 3, "olt": 4, "ole": 5, "one": 6, "ord": 7,
    "uno": 8, "ueq": 9, "ugt": 10, "uge": 11, "ult": 12, "ule": 13, "une": 14,
}


def _labeled_case_map(ir: str, prefix: str, names) -> dict:
    # {label-suffix -> switch case value} for `i32 N, label %<prefix><suffix>`.
    # Allow a trailing \d* — LLVM uniquifies colliding block names (e.g.
    # %vm.bof.sub -> %vm.bof.sub343) and appends digits to variant copies.
    alt = "|".join(names)
    out: dict = {}
    for val, name in re.findall(
        rf"i32 (\d+), label %{re.escape(prefix)}({alt})\d*\b", ir):
        out.setdefault(name, int(val))
    return out


def _cast_kind_sequence(ir: str):
    # OP_CAST is a select-chain: `icmp eq i32 %vm.ca.k<...>, K` for K = the
    # permuted kind of each of the 8 slots, in ascending emission order. Return
    # the first block of 8 IF it is a permutation of 0..7 (sanity).
    seq = [int(n) for n in re.findall(r"icmp eq i32 %vm\.ca\.k[^,\n]*, ([0-7])\b", ir)]
    if len(seq) < 8:
        return None
    first8 = seq[:8]
    if sorted(first8) != _RANDISA_CAST_CANON:
        return None
    return first8


@register("vm_randisa_cast_permuted")
def vm_randisa_cast_permuted(ir: str) -> Optional[str]:
    # randISA broadening: the CastKind byte is permuted, so OP_CAST's kind
    # select-chain tests the decoded kind against a NON-canonical ordering of
    # 0..7.
    seq = _cast_kind_sequence(ir)
    if seq is None:
        return "no OP_CAST kind dispatch found — cannot verify randISA permutation"
    if seq == _RANDISA_CAST_CANON:
        return f"OP_CAST kind dispatch is the canonical order {seq} — randISA not applied"
    return None


@register("vm_randisa_fbinsubop_permuted")
def vm_randisa_fbinsubop_permuted(ir: str) -> Optional[str]:
    # randISA broadening: the FBinSubop (OP_BINOP_F) sub-opcode is permuted, so
    # the handler switch routes vm.bof.<op> blocks from non-canonical values.
    m = _labeled_case_map(ir, "vm.bof.", _RANDISA_FBINSUBOP_CANON)
    if not m:
        return "no OP_BINOP_F subop switch found — cannot verify randISA permutation"
    if all(_RANDISA_FBINSUBOP_CANON.get(k) == v for k, v in m.items()):
        return f"OP_BINOP_F subop encoding is canonical ({sorted(m.items())}) — randISA not applied"
    return None


@register("vm_randisa_fcmp_permuted")
def vm_randisa_fcmp_permuted(ir: str) -> Optional[str]:
    # randISA broadening: the FCmp predicate byte is permuted, so the OP_FCMP
    # handler switch routes vm.fcp.<pred> blocks from non-canonical values.
    m = _labeled_case_map(ir, "vm.fcp.", _RANDISA_FCMP_CANON)
    if not m:
        return "no OP_FCMP predicate switch found — cannot verify randISA permutation"
    if all(_RANDISA_FCMP_CANON.get(k) == v for k, v in m.items()):
        return f"OP_FCMP predicate encoding is canonical ({sorted(m.items())}) — randISA not applied"
    return None


# ── P10 engine pool ──────────────────────────────────────────────────────────
# The shared engine is @__vm_engine (plain) or @__vm_engine.nest (nestedVM's
# inner layer). With enginePoolSize>1 the pass emits additional pool members by
# appending .p<N> to either layer -- @__vm_engine.p1, @__vm_engine.nest.p2, ...
# -- and each virtualized function's handler table targets whichever engine its
# name+seed hash selected. A .pN suffix is emitted ONLY when pooling is active
# and some function hashed to pool>=1, so its presence is unambiguous proof of
# pooling (distinct from the plain/nest split nestedVM produces on its own).
_POOL_MEMBER_RE = r"^define\b[^\n]*@__vm_engine(?:\.nest)?\.p\d+\("


@register("vm_enginepool_multi")
def vm_enginepool_multi(ir: str) -> Optional[str]:
    # enginePoolSize>1: prove the pool actually materialised by finding at least
    # one .pN pool-member engine (on either the plain or the nest layer). The
    # exact per-function split is a hash of the name + module seed and is asserted
    # correct by the differential-output gate, not here.
    if not re.search(_POOL_MEMBER_RE, ir, re.M):
        return ("no .pN pool-member engine found — engine pool did not "
                "materialise multiple engines")
    return None


@register("vm_no_enginepool")
def vm_no_enginepool(ir: str) -> Optional[str]:
    # Inverse: with pooling off (enginePoolSize=1, the default) no .pN pool
    # members exist on either layer.
    pool = re.findall(_POOL_MEMBER_RE, ir, re.M)
    if pool:
        return f"found {len(pool)} pool-member engine(s) but enginePoolSize=1 — pool leaked when off"
    return None


@register("vm_metamorph_engines")
def vm_metamorph_engines(ir: str) -> Optional[str]:
    # metamorphicEngines rewrites each pool clone's integer handler arithmetic
    # with per-clone-seeded MBA identities (metamorphRewriteEngine), tagging the
    # result `me.noise`. The marker is emitted nowhere else, so its presence
    # proves the per-clone rewrite fired. The seed is keyed on EngineId, so any
    # two engines that both carry it necessarily diverge (different identity
    # picks); the companion vm_enginepool_multi gate proves >=2 engines exist,
    # and the differential-output gate proves the rewrite stayed correct.
    if not re.search(r"me\.noise", ir):
        return "no me.noise marker — per-clone metamorphic engine rewrite did not run"
    return None


@register("vm_no_metamorph_engines")
def vm_no_metamorph_engines(ir: str) -> Optional[str]:
    n = len(re.findall(r"me\.noise", ir))
    if n:
        return f"found {n} me.noise marker(s) but metamorphicEngines=0 — leaked when off"
    return None


@register("vm_perfn_engine")
def vm_perfn_engine(ir: str) -> Optional[str]:
    # perFnEngine gives every virtualized function its own dedicated engine, so
    # the number of distinct @__vm_engine* definitions is at least the number of
    # per-function handler tables (@<fn>.vm.ophandlers, excluding the shared
    # __vm_h_* nested helpers). A pooled build has far fewer engines than
    # functions, so this only holds under perFnEngine.
    engines = set(re.findall(r"^define\b[^\n]*@(__vm_engine(?:\.nest)?(?:\.p\d+)?)\(", ir, re.M))
    tables = set(re.findall(r"@(\w+)\.vm\.ophandlers\b", ir))
    userfns = {t for t in tables if not t.startswith("__vm_h_")}
    if len(engines) < len(userfns):
        return (f"{len(engines)} distinct engines for {len(userfns)} virtualized "
                "functions — not a per-function engine build")
    return None
