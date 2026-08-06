"""Dynamic symbolic execution (DSE) coverage attack — the real anti-DSE metric.

The Z3 tautology attack (opaque_predicate.py / latopq_opaque.py) asks a static
question ("is this one guard a provable constant?") and cannot distinguish a
convergent-diamond guard from a genuinely solver-hard one — both come back
"not constant". This attack runs an actual symbolic-execution engine (angr)
over `obf_target` and measures how much of the function it can *cover* within
a wall-clock budget, mirroring the coverage metric used by the anti-DSE
opaque-predicate literature (Cao et al., CMC 2025).

Method:
  1. Compile baseline + obfuscated native exes with `obf_target` exported.
  2. CFGFast on each to get the function's static basic-block set (the blocks
     a complete exploration would have to reach).
  3. Symbolically execute `obf_target` from a call_state with symbolic i32
     args, stepping under a time + state budget, recording every basic block
     any state actually visits.
  4. coverage = visited_func_blocks / total_func_blocks.
     resilience  = 1 - (obf_coverage / base_coverage), clamped to [0, 1].

A defense that stalls DSE — an uninvertible-constraint guard the solver can't
push past, or a path-explosion loop that buries the engine in states — drives
obf_coverage down and resilience up. A guard DSE walks straight through leaves
coverage ~ baseline and resilience ~ 0.
"""

from __future__ import annotations

import time
from pathlib import Path

from . import AttackResult, register
from .. import cases as cases_mod
from ..runner_glue import compile_and_obfuscate_exe_exported

_SYMBOL = "obf_target"
_DSE_BUDGET_S = 60.0        # per-exe symbolic-exploration wall-clock budget
_MAX_ACTIVE = 400           # cap concurrent states (path-explosion guard)
_ARG_WIDTH = 32


def _func_blocks(angr_mod, exe_path: Path, symbol: str):
    proj = angr_mod.Project(str(exe_path), auto_load_libs=False)
    sym = proj.loader.find_symbol(symbol)
    if sym is None:
        raise RuntimeError(f"symbol {symbol!r} not resolvable in {exe_path.name}")
    addr = sym.rebased_addr
    cfg = proj.analyses.CFGFast(function_starts=[addr], normalize=True)
    fn = cfg.kb.functions.get(addr)
    blocks = set(fn.block_addrs_set) if fn is not None else set()
    return proj, addr, blocks


def _dse_coverage(angr_mod, claripy_mod, exe_path: Path, symbol: str, budget_s: float):
    """Returns (coverage_frac, visited_count, total_count, timed_out, states)."""
    proj, addr, func_blocks = _func_blocks(angr_mod, exe_path, symbol)
    total = len(func_blocks)
    if total == 0:
        return 0.0, 0, 0, False, 0

    args = [claripy_mod.BVS(f"arg{i}", _ARG_WIDTH) for i in range(2)]
    state = proj.factory.call_state(addr, *args)
    simgr = proj.factory.simulation_manager(state)

    visited = set()
    states_seen = 0
    t0 = time.monotonic()
    timed_out = False
    while simgr.active:
        if time.monotonic() - t0 > budget_s:
            timed_out = True
            break
        for st in simgr.active:
            states_seen += 1
            try:
                visited.add(st.addr)
                for a in st.history.bbl_addrs:
                    visited.add(a)
            except Exception:
                pass
        if len(simgr.active) > _MAX_ACTIVE:
            # path explosion — keep the metric honest: we already counted
            # these blocks as "reached", but stop fanning out so a Fib/Collatz
            # bomb doesn't OOM the run. This still records low coverage of the
            # *post-guard* real logic the engine never got to.
            simgr.move(from_stash="active", to_stash="stashed",
                       filter_func=lambda s, keep=_MAX_ACTIVE: True)
            timed_out = True
            break
        try:
            simgr.step()
        except Exception:
            break

    covered = len(visited & func_blocks)
    return (covered / total if total else 0.0), covered, total, timed_out, states_seen


_TOOL = "angr (symbolic execution)"
_TECHNIQUE = "DSE block-coverage of obf_target under a wall-clock budget vs. baseline"


@register("dse")
def run(case: "cases_mod.BenchCase", tools, work: Path, seed: int, *,
        verbose: bool = False, progress=None) -> AttackResult:
    t0 = time.monotonic()
    prog = progress or (lambda msg: None)

    def mk(status: str, resilience, detail: str, extra: dict | None = None) -> AttackResult:
        return AttackResult(case.name, "dse", seed, status, resilience, detail,
                             _TOOL, _TECHNIQUE, time.monotonic() - t0, extra or {})

    try:
        import angr
        import claripy
        import logging
        for lg in ("angr", "cle", "pyvex", "claripy"):
            logging.getLogger(lg).setLevel(logging.ERROR)
    except ImportError as e:
        return mk("SKIP", None, f"angr not importable: {e}")

    try:
        prog("compiling baseline + obfuscated exe (obf_target exported)")
        base_exe, obf_exe = compile_and_obfuscate_exe_exported(
            tools, case, work, seed, symbol=_SYMBOL, verbose=verbose)

        prog(f"DSE baseline exe (budget {_DSE_BUDGET_S:.0f}s)")
        base_cov, base_c, base_t, base_to, base_states = _dse_coverage(
            angr, claripy, base_exe, _SYMBOL, _DSE_BUDGET_S)

        prog(f"DSE obfuscated exe (budget {_DSE_BUDGET_S:.0f}s)")
        obf_cov, obf_c, obf_t, obf_to, obf_states = _dse_coverage(
            angr, claripy, obf_exe, _SYMBOL, _DSE_BUDGET_S)

        # Normalize against the baseline the same engine achieves, so a small
        # base_coverage (leaf fn angr can't fully model even unobfuscated)
        # doesn't inflate the score.
        if base_cov <= 0:
            resilience = 1.0 if obf_cov <= 0 else 0.0
        else:
            resilience = max(0.0, min(1.0, 1.0 - (obf_cov / base_cov)))

        detail = (f"coverage base {obf_c if False else base_c}/{base_t}={base_cov:.0%} "
                  f"-> obf {obf_c}/{obf_t}={obf_cov:.0%}"
                  + (" [obf DSE timed out]" if obf_to else ""))
        extra = {
            "base_coverage": f"{base_cov:.3f}",
            "obf_coverage": f"{obf_cov:.3f}",
            "base_blocks_covered": f"{base_c}/{base_t}",
            "obf_blocks_covered": f"{obf_c}/{obf_t}",
            "obf_timed_out": str(obf_to),
            "base_states": str(base_states),
            "obf_states": str(obf_states),
            "budget_s": f"{_DSE_BUDGET_S:.0f}",
        }
        return mk("PASS", resilience, detail, extra)

    except Exception as e:
        return mk("FAIL", None, f"attack crashed: {e}")
