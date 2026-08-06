"""CFG-recovery resilience attack — angr CFGFast vs. bcf/flattening/vm.

Compiles both the baseline and obfuscated IR to native executables (with
`obf_target` kept resolvable in the symbol/export table — see
runner_glue.compile_and_obfuscate_exe_exported), runs angr's static CFGFast
recovery scoped to that one function on each, and compares block/edge counts.

Two different obfuscation strategies show up as two different signals here:
  - bcf/flattening *inflate* the recovered CFG (more blocks/edges than the
    true function — CFGFast dutifully recovers all the bogus paths).
  - vm *shrinks* the recovered CFG to near nothing — the real logic moves
    into interpreted bytecode data, so the visible native function becomes a
    thin dispatch stub CFGFast has almost nothing to analyze.
Both are "the static recovery tool's picture diverged from the truth", so
resilience is scored on absolute log-ratio deviation from 1.0 in either
direction, not on growth alone.
"""

from __future__ import annotations

import math
import time
from pathlib import Path

from . import AttackResult, register
from .. import cases as cases_mod
from ..runner_glue import compile_and_obfuscate_exe_exported

_SYMBOL = "obf_target"
# log2-ratio deviation that saturates the resilience score at 1.0 (an 8x
# blowup or 8x shrink of the recovered block/edge count vs. ground truth).
_SATURATION_LOG2 = 3.0


def _cfg_metrics(angr_mod, exe_path: Path, symbol: str):
    proj = angr_mod.Project(str(exe_path), auto_load_libs=False)
    sym = proj.loader.find_symbol(symbol)
    if sym is None:
        raise RuntimeError(f"symbol {symbol!r} not resolvable in {exe_path.name}")
    addr = sym.rebased_addr
    cfg = proj.analyses.CFGFast(function_starts=[addr], normalize=True)
    fn = cfg.kb.functions.get(addr)
    if fn is None:
        return 0, 0
    return len(fn.block_addrs_set), fn.graph.number_of_edges()


def _deviation_score(base: int, obf: int) -> float:
    if base <= 0:
        return 1.0 if obf != base else 0.0
    if obf <= 0:
        return 1.0
    ratio = obf / base
    dev = abs(math.log2(ratio))
    return max(0.0, min(1.0, dev / _SATURATION_LOG2))


_TOOL = "angr (CFGFast)"
_TECHNIQUE = "static CFG recovery, block/edge deviation vs. baseline ground truth"


@register("cfg")
def run(case: "cases_mod.BenchCase", tools, work: Path, seed: int, *,
        verbose: bool = False, progress=None) -> AttackResult:
    t0 = time.monotonic()
    prog = progress or (lambda msg: None)

    def mk(status: str, resilience, detail: str, extra: dict | None = None) -> AttackResult:
        return AttackResult(case.name, "cfg", seed, status, resilience, detail,
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
        prog("compiling baseline + obfuscated exe (with obf_target exported)")
        t_compile0 = time.monotonic()
        base_exe, obf_exe = compile_and_obfuscate_exe_exported(
            tools, case, work, seed, symbol=_SYMBOL, verbose=verbose)
        compile_ms = (time.monotonic() - t_compile0) * 1000

        prog("angr CFGFast on baseline exe (ground truth)")
        t_base0 = time.monotonic()
        base_blocks, base_edges = _cfg_metrics(angr, base_exe, _SYMBOL)
        base_cfg_ms = (time.monotonic() - t_base0) * 1000

        prog("angr CFGFast on obfuscated exe")
        t_obf0 = time.monotonic()
        obf_blocks, obf_edges = _cfg_metrics(angr, obf_exe, _SYMBOL)
        obf_cfg_ms = (time.monotonic() - t_obf0) * 1000

        block_score = _deviation_score(base_blocks, obf_blocks)
        edge_score = _deviation_score(base_edges, obf_edges)
        resilience = (block_score + edge_score) / 2.0

        detail = (f"blocks {base_blocks}->{obf_blocks}, edges {base_edges}->{obf_edges} "
                  f"(block_score={block_score:.2f}, edge_score={edge_score:.2f})")
        extra = {
            "base_blocks": str(base_blocks), "obf_blocks": str(obf_blocks),
            "base_edges": str(base_edges), "obf_edges": str(obf_edges),
            "block_ratio": f"{(obf_blocks / base_blocks) if base_blocks else float('inf'):.2f}",
            "edge_ratio": f"{(obf_edges / base_edges) if base_edges else float('inf'):.2f}",
            "compile_ms": f"{compile_ms:.0f}",
            "base_cfgfast_ms": f"{base_cfg_ms:.0f}",
            "obf_cfgfast_ms": f"{obf_cfg_ms:.0f}",
        }
        return mk("PASS", resilience, detail, extra)

    except Exception as e:
        return mk("FAIL", None, f"attack crashed: {e}")
