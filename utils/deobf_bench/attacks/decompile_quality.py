"""Decompiler-quality resilience attack — angr's real decompiler vs. adec.

adec (AntiDecompiler)'s stated purpose is defeating decompilers, so this is
the one attack in the bench that judges *readability* rather than raw
recoverability: does `proj.analyses.Decompiler` crash, and if it doesn't,
how far does its pseudo-C output diverge from the clean, loop-structured
form it produces on an unhardened baseline?

Confirmed by manual inspection (not just theory) that adec's output makes
angr's decompiler choke: baseline decompiles to clean nested for-loops;
adec-hardened output collapses to raw `goto`s, leaks internal decompiler
error text directly into the pseudocode (`[D] Unsupported jumpkind
Ijk_NoDecode at address ...`), and blows up line count several-fold.
"""

from __future__ import annotations

import math
import time
from pathlib import Path

from . import AttackResult, register
from .. import cases as cases_mod
from ..runner_glue import compile_and_obfuscate_exe_exported

_SYMBOL = "obf_target"
_LINE_GROWTH_SATURATION_LOG2 = 3.0  # 8x more pseudocode lines -> full score on that component
_ERROR_MARKERS = ("[D] Unsupported", "DecompilationError", "Unsupported jumpkind",
                   "CorruptedAssembly", "UnsupportedNodeTypeError")


def _decompile(angr_mod, exe_path: Path, symbol: str):
    """Returns (pseudocode_text_or_None, crashed: bool, crash_reason: str)."""
    proj = angr_mod.Project(str(exe_path), auto_load_libs=False)
    sym = proj.loader.find_symbol(symbol)
    if sym is None:
        return None, True, f"symbol {symbol!r} not resolvable"
    addr = sym.rebased_addr
    try:
        cfg = proj.analyses.CFGFast(function_starts=[addr], normalize=True)
        fn = cfg.kb.functions.get(addr)
        if fn is None:
            return None, True, "CFGFast found no function at symbol address"
        dec = proj.analyses.Decompiler(fn, cfg=cfg.model)
        text = dec.codegen.text if dec.codegen else None
        return text, False, ""
    except Exception as e:
        return None, True, f"{type(e).__name__}: {e}"


def _score(base_text: str, obf_text: str | None, obf_crashed: bool) -> tuple[float, dict]:
    if obf_crashed or not obf_text:
        return 1.0, {"crashed": "true"}

    base_lines = base_text.splitlines()
    obf_lines = obf_text.splitlines()
    base_loops = base_text.count("for (") + base_text.count("while (")
    obf_loops = obf_text.count("for (") + obf_text.count("while (")
    has_error_marker = any(m in obf_text for m in _ERROR_MARKERS)

    # Structural collapse: baseline had readable loop constructs, obf lost them.
    structure_score = 1.0 if (base_loops > 0 and obf_loops == 0) else \
        max(0.0, 1.0 - (obf_loops / base_loops)) if base_loops > 0 else 0.0

    error_score = 1.0 if has_error_marker else 0.0

    ratio = len(obf_lines) / max(1, len(base_lines))
    growth_score = max(0.0, min(1.0, math.log2(max(ratio, 1e-9)) / _LINE_GROWTH_SATURATION_LOG2)) \
        if ratio > 1 else 0.0

    resilience = 0.4 * structure_score + 0.3 * error_score + 0.3 * growth_score
    extra = {
        "crashed": "false",
        "base_lines": str(len(base_lines)), "obf_lines": str(len(obf_lines)),
        "base_loops": str(base_loops), "obf_loops": str(obf_loops),
        "has_decompiler_error_marker": str(has_error_marker),
        "structure_score": f"{structure_score:.2f}",
        "error_score": f"{error_score:.2f}",
        "growth_score": f"{growth_score:.2f}",
    }
    return resilience, extra


_TOOL = "angr (Decompiler)"
_TECHNIQUE = "real decompiler run: crash rate + loop-structure collapse + pseudocode blowup"


@register("decompile")
def run(case: "cases_mod.BenchCase", tools, work: Path, seed: int, *,
        verbose: bool = False, progress=None) -> AttackResult:
    t0 = time.monotonic()
    prog = progress or (lambda msg: None)

    def mk(status: str, resilience, detail: str, extra: dict | None = None) -> AttackResult:
        return AttackResult(case.name, "decompile", seed, status, resilience, detail,
                             _TOOL, _TECHNIQUE, time.monotonic() - t0, extra or {})

    try:
        import angr
        import logging
        logging.getLogger("angr").setLevel(logging.ERROR)
        logging.getLogger("cle").setLevel(logging.ERROR)
        logging.getLogger("pyvex").setLevel(logging.ERROR)
    except ImportError as e:
        return mk("SKIP", None, f"angr not importable: {e}")

    try:
        prog("compiling baseline + adec-hardened exe (with obf_target exported)")
        base_exe, obf_exe = compile_and_obfuscate_exe_exported(
            tools, case, work, seed, symbol=_SYMBOL, verbose=verbose)

        prog("decompiling baseline exe (ground truth)")
        base_text, base_crashed, base_reason = _decompile(angr, base_exe, _SYMBOL)
        if base_crashed or not base_text:
            return mk("FAIL", None,
                       f"decompiler crashed on unobfuscated baseline: {base_reason}")

        prog("decompiling adec-hardened exe")
        obf_text, obf_crashed, obf_reason = _decompile(angr, obf_exe, _SYMBOL)

        resilience, extra = _score(base_text, obf_text, obf_crashed)
        if extra.get("crashed") == "true":
            reason = obf_reason if obf_crashed else "decompiler produced no usable pseudocode " \
                "(failed internally without raising — see angr's own error log)"
            detail = f"decompiler defeated on adec-hardened function: {reason}"
        else:
            detail = (f"lines {extra['base_lines']}->{extra['obf_lines']}, "
                      f"loops {extra['base_loops']}->{extra['obf_loops']}, "
                      f"error_marker={extra['has_decompiler_error_marker']}")
        return mk("PASS", resilience, detail, extra)

    except Exception as e:
        return mk("FAIL", None, f"attack crashed: {e}")
