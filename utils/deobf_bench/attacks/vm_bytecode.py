"""VM bytecode-extraction resilience attack — recovers the plaintext
bytecode blob VMPass hides behind AES-CTR encryption + an LCG-XOR'd round
key, for `encBytecode=1` configs.

Unlike strenc's decrypt-at-function-entry pattern, the VM's bytecode
decrypt runs once in a *static initializer* (`<fn>.vm.ctor`, registered via
MSVC's `.CRT$XCU`/`.init_array`-equivalent mechanism, invoked before
`main()` — not called from `obf_target` at all, so the "find the first call
in obf_target" trick from string_extract.py doesn't apply here). Locating
it (validated by hand against real `-obf-verbose` output and disassembly
before writing this):

  1. The ciphertext blob (`<fn>.vm.bytecode`, a `private constant` global —
     same PE-strips-local-symbols problem as strenc's decrypt function) is
     parsed directly out of the case's own obf.ll text (its bytes are a
     compile-time literal, no need to run anything to know them).
  2. Byte-scan the compiled binary's memory for those exact ciphertext
     bytes — cheap (<1ms observed) and locates it without needing a symbol.
  3. Linear-scan `.text` with Capstone for a `lea reg, [rip+disp]`
     instruction whose resolved target is the ciphertext address — that
     instruction sits inside `.vm.ctor`, right before the memcpy that
     stages it for decryption.
  4. Whole-binary `CFGFast(force_complete_scan=True)` (~4s observed) finds
     that instruction's *containing function* — `.vm.ctor`'s true entry,
     needed so its own prologue (which sets up the stack-resident,
     LCG-XOR-decoded AES round key) runs for real before the decrypt call,
     rather than starting execution mid-function with garbage key material.
  5. The constructor's last `call` before its `ret` is
     `__obf_aes_ctr_decrypt(rt_buf, len, roundkey, nonce)` — tap it exactly
     like string_extract.py's dynamic decrypt-hook.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import List, Optional

from . import AttackResult, register
from .. import cases as cases_mod
from ..runner_glue import compile_and_obfuscate, compile_and_obfuscate_exe

_DISASM_WINDOW = 4096
_STEP_BUDGET = 4000  # measured ~2200 steps needed with Unicorn for a 331-457 byte blob
_MAX_ACTIVE_STATES = 16
_CIPHERTEXT_RE = re.compile(
    r'@(\w+)\.vm\.bytecode = private unnamed_addr constant \[(\d+) x i8\] c"((?:\\..|[^"])*)"')


def _unescape_llvm_string(raw: str) -> bytes:
    out = bytearray()
    i = 0
    while i < len(raw):
        if raw[i] == "\\":
            if raw[i + 1] == "\\":
                out.append(0x5C)
                i += 2
            elif raw[i + 1] == '"':
                out.append(0x22)
                i += 2
            else:
                out.append(int(raw[i + 1:i + 3], 16))
                i += 3
        else:
            out.append(ord(raw[i]))
            i += 1
    return bytes(out)


def _find_ciphertext(obf_ir: str, fn_name: str) -> Optional[bytes]:
    m = _CIPHERTEXT_RE.search(obf_ir)
    if not m or m.group(1) != fn_name:
        return None
    n = int(m.group(2))
    data = _unescape_llvm_string(m.group(3))
    return data if len(data) == n else None


def _find_ref_addr(cs_mod, angr_mod, proj, ciphertext_addr: int) -> Optional[int]:
    text_sec = next((s for s in proj.loader.main_object.sections if s.name == ".text"), None)
    if text_sec is None:
        return None
    code = proj.loader.memory.load(text_sec.min_addr, text_sec.max_addr - text_sec.min_addr)
    md = cs_mod.Cs(cs_mod.CS_ARCH_X86, cs_mod.CS_MODE_64)
    md.detail = True
    for insn in md.disasm(code, text_sec.min_addr):
        if insn.mnemonic != "lea" or len(insn.operands) != 2:
            continue
        op = insn.operands[1]
        if (op.type == cs_mod.x86.X86_OP_MEM and
                op.mem.base == cs_mod.x86.X86_REG_RIP):
            target = insn.address + insn.size + op.mem.disp
            if target == ciphertext_addr:
                return insn.address
    return None


def _find_calls_in_range(cs_mod, code: bytes, base_addr: int) -> List[int]:
    md = cs_mod.Cs(cs_mod.CS_ARCH_X86, cs_mod.CS_MODE_64)
    calls = []
    for insn in md.disasm(code, base_addr):
        if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
            calls.append(int(insn.op_str, 16))
    return calls


def _dynamic_decrypt(angr_mod, exe_path: Path, ctor_addr: int, decrypt_addr: int,
                      buf_len_hint: int) -> Optional[bytes]:
    proj = angr_mod.Project(str(exe_path), auto_load_libs=False)
    recovered = {}

    def tap(state):
        buf_ptr = state.solver.eval(state.regs.rcx)
        length = state.solver.eval(state.regs.rdx)
        if not (0 < length <= buf_len_hint * 4):
            return
        ret_addr = state.solver.eval(
            state.memory.load(state.regs.rsp, 8, endness=state.arch.memory_endness))

        def post(state2):
            data = state2.memory.load(buf_ptr, length)
            recovered["bytes"] = state2.solver.eval(data, cast_to=bytes)

        if not proj.is_hooked(ret_addr):
            proj.hook(ret_addr, post, length=0)

    proj.hook(decrypt_addr, tap, length=0)

    # AES-CTR over a ~300-450 byte bytecode blob is ~20-30 full AES-128
    # rounds — measured ~4300 pure-VEX steps / 45s vs. ~2200 steps / 25s
    # with Unicorn concrete-execution acceleration. Safe here because
    # everything downstream of the ctor's own args is concrete (ZERO_FILL
    # only backstops truly unconstrained reads, nothing here should hit it).
    opts = {angr_mod.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            angr_mod.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr_mod.options.UNICORN}
    call_state = proj.factory.call_state(ctor_addr, add_options=opts)
    simgr = proj.factory.simgr(call_state)
    steps = 0
    while simgr.active and steps < _STEP_BUDGET:
        if len(simgr.active) > _MAX_ACTIVE_STATES:
            break
        simgr.step()
        steps += 1
    return recovered.get("bytes")


_TOOL = "angr+capstone"
_TECHNIQUE = "ciphertext byte-scan + whole-binary CFGFast + dynamic constructor-decrypt-hook"


@register("vmbc")
def run(case: "cases_mod.BenchCase", tools, work: Path, seed: int, *,
        verbose: bool = False, progress=None) -> AttackResult:
    t0 = time.monotonic()
    prog = progress or (lambda msg: None)

    def mk(status: str, resilience, detail: str, extra: dict | None = None) -> AttackResult:
        return AttackResult(case.name, "vmbc", seed, status, resilience, detail,
                             _TOOL, _TECHNIQUE, time.monotonic() - t0, extra or {})

    try:
        import angr
        import capstone
        import logging
        logging.getLogger("angr").setLevel(logging.ERROR)
        logging.getLogger("cle").setLevel(logging.ERROR)
        logging.getLogger("pyvex").setLevel(logging.ERROR)
    except ImportError as e:
        return mk("SKIP", None, f"angr/capstone not importable: {e}")

    try:
        prog("compiling + obfuscating (need obf.ll for ciphertext bytes)")
        obf_ll = compile_and_obfuscate(tools, case, work, seed, verbose=verbose)
        obf_ir = obf_ll.read_text(encoding="utf-8", errors="replace")
        ciphertext = _find_ciphertext(obf_ir, "obf_target")
        if ciphertext is None:
            return mk("FAIL", None,
                       "no obf_target.vm.bytecode constant found (encBytecode=0, or vm pass didn't run)")

        prog("compiling native exe")
        _, obf_exe = compile_and_obfuscate_exe(tools, case, work, seed, verbose=verbose)
        proj = angr.Project(str(obf_exe), auto_load_libs=False)

        prog(f"byte-scanning binary for {len(ciphertext)}-byte ciphertext blob")
        main_obj = proj.loader.main_object
        blob = proj.loader.memory.load(main_obj.min_addr, main_obj.max_addr - main_obj.min_addr)
        idx = blob.find(ciphertext)
        if idx < 0:
            return mk("FAIL", None, "ciphertext bytes not found in compiled binary")
        ciphertext_addr = main_obj.min_addr + idx

        prog("scanning .text for the rip-relative reference to the ciphertext")
        ref_addr = _find_ref_addr(capstone, angr, proj, ciphertext_addr)
        if ref_addr is None:
            return mk("FAIL", None, "no code references the ciphertext blob")

        prog("whole-binary CFGFast to find the constructor's true entry point")
        cfg = proj.analyses.CFGFast(force_complete_scan=True, normalize=True)
        ctor_fn = next((fn for addr, fn in cfg.kb.functions.items()
                         if fn.size and addr <= ref_addr < addr + fn.size), None)
        if ctor_fn is None:
            return mk("FAIL", None, "could not recover the constructor's containing function")

        code = proj.loader.memory.load(ctor_fn.addr, max(ctor_fn.size, 16))
        calls = _find_calls_in_range(capstone, code, ctor_fn.addr)
        if not calls:
            return mk("FAIL", None, "no calls found in the bytecode constructor")
        decrypt_addr = calls[-1]  # decrypt runs last, after the memcpy staging steps

        prog(f"dynamic decrypt: call_state(ctor@0x{ctor_fn.addr:x}) + tap decrypt@0x{decrypt_addr:x}")
        recovered = _dynamic_decrypt(angr, obf_exe, ctor_fn.addr, decrypt_addr, len(ciphertext))

        if recovered is None:
            return mk("PASS", 1.0, "dynamic decrypt-hook produced no plaintext bytecode")

        extracted = recovered != ciphertext and any(b != 0 for b in recovered)
        resilience = 0.0 if extracted else 1.0
        detail = (f"ctor@0x{ctor_fn.addr:x}, decrypt@0x{decrypt_addr:x}, "
                  f"{'recovered' if extracted else 'failed to recover'} {len(recovered)} bytes of plaintext bytecode")
        extra = {
            "ciphertext_addr": hex(ciphertext_addr),
            "ctor_addr": hex(ctor_fn.addr),
            "decrypt_addr": hex(decrypt_addr),
            "recovered_hex_head": recovered[:32].hex() if recovered else "",
            "ciphertext_hex_head": ciphertext[:32].hex(),
        }
        return mk("PASS", resilience, detail, extra)

    except Exception as e:
        return mk("FAIL", None, f"attack crashed: {e}")
