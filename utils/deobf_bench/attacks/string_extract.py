"""String-extraction resilience attack — dynamic decrypt-hook vs. strenc.

Locates the injected `__aes_decrypt(buf, len, nonce)` call inside
`obf_target` and taps it dynamically: a non-replacing angr hook (`length=0`,
so real execution falls through) captures the call's `(buf_ptr, len)`
arguments, then installs a second tap at the return address to snapshot the
now-decrypted buffer. This is the standard "instrument, don't reimplement"
dynamic string-recovery technique — real AES-CTR decryption executes
natively; the attack just watches memory before/after.

The decrypt function has *private* LLVM linkage, so it has no name in the
compiled PE (Windows strips local/non-exported symbols; `/EXPORT` doesn't
apply to private-linkage functions either — LNK2001). Locating it by
CFGFast's function/call-site recovery is unreliable on this heavily
obfuscated code (observed CFGFast misclassifying call targets as no-return
and truncating `obf_target` to 1 basic block). Instead: linearly disassemble
`obf_target` with Capstone and take the *first* direct-call target — the
StringEncryption pass injects all of a function's decrypt calls at function
entry, before any real logic runs (see StringEncryption.cpp), so the first
call is always the decrypt site regardless of how many distinct secrets the
function uses.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import List

from . import AttackResult, register
from .. import cases as cases_mod
from ..runner_glue import compile_and_obfuscate_exe_exported

_SYMBOL = "obf_target"
_DISASM_WINDOW = 4096
# Kept small deliberately: the working (AES) cases finish in well under 100
# steps. A much bigger budget doesn't help a case that's actually stuck —
# angr symbolic exploration can runaway into multi-GB memory long before
# hitting a step count in the thousands (observed on strenc_xor_fallback) —
# it just makes the eventual case-timeout burn more RAM on the way there.
_STEP_BUDGET = 1500
_MAX_ACTIVE_STATES = 16


def _find_decrypt_addr(cs_mod, code: bytes, base_addr: int):
    md = cs_mod.Cs(cs_mod.CS_ARCH_X86, cs_mod.CS_MODE_64)
    for insn in md.disasm(code, base_addr):
        if insn.mnemonic == "ret":
            break
        if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
            return int(insn.op_str, 16)
    return None


_MAX_PLAUSIBLE_LEN = 4096  # sanity cap: buffer lengths here are all <100 bytes


def _run_dynamic_extraction(angr_mod, exe_path: Path, decrypt_addr: int, target_addr: int,
                             *, decrypt_abi: str = "aes") -> List[bytes]:
    """decrypt_abi is a *hint*, not authoritative: the AES and legacy-XOR
    decrypt helpers don't share a signature (StringEncryption.cpp) —
      "aes": __aes_decrypt(buf: rcx, len: edx, nonce: r8)
      "xor": __decrypt_string(str: rcx, key: dl, len: r8d)
    — so the length lands in rdx for one and r8 for the other. But
    StringEncryptionConfig's AES/XOR merge has a real bug (Acc.useAES
    defaults true and is only ever OR'd true by per-function configs, never
    reset false — see StringEncryption.cpp ~L211-224): a function-level
    `aes=0` is silently ignored, so the compiled binary can still be running
    the AES path even when the case *asked* for XOR. Trusting the hint
    blindly means treating a genuine pointer arg as a byte count — which is
    exactly what caused a multi-GB memory-load hang here. So: try the hinted
    register first, but only accept it if it's a plausible length; otherwise
    fall back to the other slot.
    """
    proj = angr_mod.Project(str(exe_path), auto_load_libs=False)
    recovered: List[bytes] = []
    hinted_reg = "rdx" if decrypt_abi == "aes" else "r8"
    other_reg = "r8" if decrypt_abi == "aes" else "rdx"

    def tap(state):
        buf_ptr = state.solver.eval(state.regs.rcx)
        hinted = state.solver.eval(getattr(state.regs, hinted_reg))
        length = hinted if 0 < hinted <= _MAX_PLAUSIBLE_LEN else \
            state.solver.eval(getattr(state.regs, other_reg))
        if not (0 < length <= _MAX_PLAUSIBLE_LEN):
            return  # neither slot looks like a length — don't attempt the read
        ret_addr = state.solver.eval(
            state.memory.load(state.regs.rsp, 8, endness=state.arch.memory_endness))

        def post(state2):
            data = state2.memory.load(buf_ptr, length)
            recovered.append(state2.solver.eval(data, cast_to=bytes))

        if not proj.is_hooked(ret_addr):
            proj.hook(ret_addr, post, length=0)

    proj.hook(decrypt_addr, tap, length=0)

    # This is meant to be a pure concrete replay (obf_target's own args are
    # hardcoded 0/0, everything the decrypt call touches comes from
    # initialized data) — ZERO_FILL keeps any register/memory angr can't
    # otherwise resolve from silently going symbolic and forking the state
    # space. Step manually (not simgr.run(n=...)) so a state-count blowup
    # aborts immediately instead of running to the full step budget at
    # however many forked states each step costs.
    opts = {angr_mod.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            angr_mod.options.ZERO_FILL_UNCONSTRAINED_MEMORY}
    call_state = proj.factory.call_state(target_addr, 0, 0, add_options=opts)
    simgr = proj.factory.simgr(call_state)
    steps = 0
    while simgr.active and steps < _STEP_BUDGET:
        if len(simgr.active) > _MAX_ACTIVE_STATES:
            break
        simgr.step()
        steps += 1
    return recovered


_TOOL = "angr+capstone"
_TECHNIQUE = "dynamic decrypt-hook (memory tap on decrypt call, no crypto attacked)"


@register("strenc")
def run(case: "cases_mod.BenchCase", tools, work: Path, seed: int, *,
        verbose: bool = False, progress=None) -> AttackResult:
    t0 = time.monotonic()
    prog = progress or (lambda msg: None)

    def mk(status: str, resilience, detail: str, extra: dict | None = None) -> AttackResult:
        return AttackResult(case.name, "strenc", seed, status, resilience, detail,
                             _TOOL, _TECHNIQUE, time.monotonic() - t0, extra or {})

    try:
        import logging
        import angr
        import capstone
        logging.getLogger("angr").setLevel(logging.ERROR)
        logging.getLogger("cle").setLevel(logging.ERROR)
        logging.getLogger("pyvex").setLevel(logging.ERROR)
    except ImportError as e:
        return mk("SKIP", None, f"angr/capstone not importable: {e}")

    try:
        prog("compiling obfuscated exe (with obf_target exported)")
        _, obf_exe = compile_and_obfuscate_exe_exported(
            tools, case, work, seed, symbol=_SYMBOL, verbose=verbose)

        prog("loading exe in angr")
        proj = angr.Project(str(obf_exe), auto_load_libs=False)
        sym = proj.loader.find_symbol(_SYMBOL)
        if sym is None:
            return mk("FAIL", None, f"{_SYMBOL} not resolvable in obf exe")
        target_addr = sym.rebased_addr

        prog("locating decrypt call site (capstone linear disasm)")
        code = proj.loader.memory.load(target_addr, _DISASM_WINDOW)
        decrypt_addr = _find_decrypt_addr(capstone, code, target_addr)
        if decrypt_addr is None:
            # No locatable decrypt call site. This is a DEFENSE WIN, not an
            # infra failure: the strenc ChaCha redesign (A-E) inlines the
            # decrypt (no choke-point call, no named __*_decrypt symbol) and
            # buries any residual call under inlined cipher bulk, so this
            # attack's "first direct call in obf_target = decrypt" locator
            # finds nothing to hook. Score full resilience against THIS attack.
            # NOTE (ceiling): a smarter attack that taps the plaintext
            # CONSUMER (strcmp/printf) at point-of-use could still read the
            # decrypted bytes — see project_deobf_bench. This 100% reflects
            # defeating the dynamic decrypt-hook technique specifically, not
            # absolute string-recovery resistance.
            return mk("PASS", 1.0,
                      "decrypt site not locatable (inlined, no choke call / "
                      "symbol) — dynamic decrypt-hook attack defeated")

        decrypt_abi = case.ground_truth.get("decrypt_abi", "aes")
        prog(f"dynamic sim: call_state(obf_target) + tap decrypt@0x{decrypt_addr:x} "
             f"(abi={decrypt_abi}, step budget={_STEP_BUDGET})")
        t_sim0 = time.monotonic()
        recovered = _run_dynamic_extraction(angr, obf_exe, decrypt_addr, target_addr,
                                             decrypt_abi=decrypt_abi)
        sim_ms = (time.monotonic() - t_sim0) * 1000

        expected = case.ground_truth["secrets"]
        recovered_texts = [b.split(b"\x00", 1)[0].decode("latin1") for b in recovered]
        found = [s for s in expected if s in recovered_texts]
        resilience = 1.0 - (len(found) / len(expected))

        detail = (f"decrypt@0x{decrypt_addr:x}, recovered {len(recovered)} buffer(s), "
                  f"{len(found)}/{len(expected)} secret(s) matched exactly")
        extra = {
            "decrypt_addr": hex(decrypt_addr),
            "decrypt_abi": decrypt_abi,
            "sim_ms": f"{sim_ms:.0f}",
            "recovered_hex": ", ".join(b.hex() for b in recovered),
            "recovered_text": ", ".join(repr(t) for t in recovered_texts),
        }
        return mk("PASS", resilience, detail, extra)

    except Exception as e:
        return mk("FAIL", None, f"attack crashed: {e}")
