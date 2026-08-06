"""Call-target-recovery resilience attack — vcall vs. static disassembly.

`vcall` ("virtualize calls") rewrites direct calls into indirect dispatch
through a hidden table, so a call that was `call 0x140001234` (target in
plain sight in the instruction stream) becomes `call rax` or `call
[rax+off]` (target only known at runtime). Linearly disassembles
`obf_target` (same proven Capstone technique as attacks/string_extract.py —
CFGFast's own function/call-site recovery was unreliable on this codebase's
private helper functions, see that module's docstring) and classifies each
`call` instruction as direct (immediate operand) or indirect (register/
memory operand). Resilience = fraction of call sites that are no longer
statically visible.
"""

from __future__ import annotations

import time
from pathlib import Path

from . import AttackResult, register
from .. import cases as cases_mod
from ..runner_glue import compile_and_obfuscate_exe_exported

_SYMBOL = "obf_target"
_DISASM_WINDOW = 4096


def _classify_calls(cs_mod, code: bytes, base_addr: int) -> tuple[int, int]:
    """Returns (direct_calls, indirect_calls) seen before the first ret."""
    md = cs_mod.Cs(cs_mod.CS_ARCH_X86, cs_mod.CS_MODE_64)
    direct = indirect = 0
    for insn in md.disasm(code, base_addr):
        if insn.mnemonic == "ret":
            break
        if insn.mnemonic == "call":
            if insn.op_str.startswith("0x"):
                direct += 1
            else:
                indirect += 1
    return direct, indirect


_TOOL = "capstone"
_TECHNIQUE = "static disassembly: direct vs. indirect call-site classification"


@register("vcall")
def run(case: "cases_mod.BenchCase", tools, work: Path, seed: int, *,
        verbose: bool = False, progress=None) -> AttackResult:
    t0 = time.monotonic()
    prog = progress or (lambda msg: None)

    def mk(status: str, resilience, detail: str, extra: dict | None = None) -> AttackResult:
        return AttackResult(case.name, "vcall", seed, status, resilience, detail,
                             _TOOL, _TECHNIQUE, time.monotonic() - t0, extra or {})

    try:
        import capstone
        import angr  # only used to load the PE and resolve obf_target's address
        import logging
        logging.getLogger("angr").setLevel(logging.ERROR)
        logging.getLogger("cle").setLevel(logging.ERROR)
    except ImportError as e:
        return mk("SKIP", None, f"angr/capstone not importable: {e}")

    try:
        prog("compiling baseline + vcall-obfuscated exe (with obf_target exported)")
        base_exe, obf_exe = compile_and_obfuscate_exe_exported(
            tools, case, work, seed, symbol=_SYMBOL, verbose=verbose)

        prog("disassembling baseline (ground truth)")
        base_proj = angr.Project(str(base_exe), auto_load_libs=False)
        base_sym = base_proj.loader.find_symbol(_SYMBOL)
        if base_sym is None:
            return mk("FAIL", None, f"{_SYMBOL} not resolvable in baseline exe")
        base_code = base_proj.loader.memory.load(base_sym.rebased_addr, _DISASM_WINDOW)
        base_direct, base_indirect = _classify_calls(capstone, base_code, base_sym.rebased_addr)

        prog("disassembling vcall-obfuscated exe")
        obf_proj = angr.Project(str(obf_exe), auto_load_libs=False)
        obf_sym = obf_proj.loader.find_symbol(_SYMBOL)
        if obf_sym is None:
            return mk("FAIL", None, f"{_SYMBOL} not resolvable in obf exe")
        obf_code = obf_proj.loader.memory.load(obf_sym.rebased_addr, _DISASM_WINDOW)
        obf_direct, obf_indirect = _classify_calls(capstone, obf_code, obf_sym.rebased_addr)

        obf_total = obf_direct + obf_indirect
        if obf_total == 0:
            return mk("FAIL", None, "no call instructions found in obfuscated obf_target")

        resilience = obf_indirect / obf_total
        detail = (f"baseline calls: {base_direct} direct / {base_indirect} indirect; "
                  f"obfuscated calls: {obf_direct} direct / {obf_indirect} indirect")
        extra = {
            "base_direct_calls": str(base_direct), "base_indirect_calls": str(base_indirect),
            "obf_direct_calls": str(obf_direct), "obf_indirect_calls": str(obf_indirect),
        }
        return mk("PASS", resilience, detail, extra)

    except Exception as e:
        return mk("FAIL", None, f"attack crashed: {e}")
