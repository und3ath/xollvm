"""latopq opaque-predicate resilience attack — SMT tautology proof.

Same technique as `attacks/opaque_predicate.py` (which targets bcf), pointed
at latopq's guard instead. latopq splits a block into a convergent diamond
guarded by an LWR predicate `T_k(x) = (round(A . expand(x)) == target)`,
branching to `latopq.real<N>` / `latopq.bogus<N>` labels. Both arms rejoin
the real continuation, so — exactly like bcf — the program stays correct no
matter how the guard resolves.

The deobfuscation question is identical to the bcf case: can an SMT solver
prove the guard condition is *constant* (a tautology) regardless of the
values it is built from? If yes, the bogus edge is provably dead and can be
pruned (resilience 0.0). If no, neither edge can be statically removed and
the diamond survives (resilience 1.0).

The contrast with bcf is the whole point of the experiment: bcf's guard is
engineered to be an always-true tautology (its opacity is only apparent, and
Z3 folds it), whereas latopq's guard genuinely depends on a live program
value through a lattice projection, so there is no tautology to prove.

`extra.free_vars` records how many non-argument unknowns the lift produced.
When latopq's coefficients (A[i], target) sit behind volatile opaque anchors
the lifter models them as free variables, so "not a tautology" holds under
the same attack model the bcf attack uses. `extra.free_vars` makes that
visible so the result is not mistaken for a stronger claim than it is.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Dict, List

from . import AttackResult, register
from .. import cases as cases_mod
from .mba_smt import Lifter, UnsupportedIR, _extract_fn_body, _strip_flags
from .opaque_predicate import _split_blocks, _INSTR_RE
from ..runner_glue import compile_and_obfuscate

_SOLVER_TIMEOUT_MS = 5000


def _is_latopq_guard(label_a: str, label_b: str) -> bool:
    return any(t.startswith("latopq.real") or t.startswith("latopq.bogus")
               for t in (label_a, label_b))


def _find_latopq_predicate(z3mod, blocks: Dict[str, List[str]], arg_names: List[str]):
    """Scan blocks for the first latopq-guarded conditional branch and lift
    just that block's instructions to reach the condition. latopq builds the
    whole predicate chain (expand / MAC / round / icmp) in the head block
    immediately before the CondBr, so a per-block fresh Lifter reaches it
    without inter-block dataflow — same modeling choice as the bcf attack.
    """
    for label, lines in blocks.items():
        lifter = Lifter(z3mod, arg_names)
        for line in lines:
            if line.startswith(";"):
                continue
            if line.startswith("br i1 "):
                rest = line[len("br i1 "):].strip()
                parts = [p.strip() for p in rest.split(",")]
                if len(parts) != 3 or not parts[0].startswith("%"):
                    break
                cond_reg = parts[0][1:]
                label_a = parts[1].split("%", 1)[1] if "%" in parts[1] else ""
                label_b = parts[2].split("%", 1)[1] if "%" in parts[2] else ""
                if not _is_latopq_guard(label_a, label_b) or cond_reg not in lifter.env:
                    break
                return lifter.env[cond_reg], lifter
            if line.startswith(("br label", "ret ", "switch ", "indirectbr",
                                 "unreachable", "invoke ", "resume ", "call void")):
                break
            if line.startswith("store "):
                try:
                    lifter._eval_def("<store>", _strip_flags(line))
                except UnsupportedIR:
                    break
                continue
            m = _INSTR_RE.match(line)
            if not m:
                continue
            dst, expr = m.group(1), _strip_flags(m.group(2))
            try:
                lifter.env[dst] = lifter._eval_def(dst, expr)
            except UnsupportedIR:
                break
    return None, None


_TOOL = "z3-solver"
_TECHNIQUE = "SMT tautology proof on latopq's LWR opaque-predicate branch condition"


@register("latopq_opaque")
def run(case: "cases_mod.BenchCase", tools, work: Path, seed: int, *,
        verbose: bool = False, progress=None) -> AttackResult:
    t0 = time.monotonic()
    prog = progress or (lambda msg: None)

    def mk(status: str, resilience, detail: str, extra: dict | None = None) -> AttackResult:
        return AttackResult(case.name, "latopq_opaque", seed, status, resilience, detail,
                             _TOOL, _TECHNIQUE, time.monotonic() - t0, extra or {})

    try:
        import z3
    except ImportError as e:
        return mk("SKIP", None, f"z3-solver not importable: {e}")

    try:
        prog("compiling + obfuscating (clang -O0, opt -passes=obfuscation)")
        obf_ll = compile_and_obfuscate(tools, case, work, seed, verbose=verbose)
        obf_ir = obf_ll.read_text(encoding="utf-8", errors="replace")
        body = _extract_fn_body(obf_ir, "obf_target")
        if body is None:
            return mk("FAIL", None, "obf_target not found in obfuscated IR")

        blocks = _split_blocks(body)
        prog(f"scanning {len(blocks)} basic blocks for one ending in a latopq-guarded branch")
        cond, lifter = _find_latopq_predicate(z3, blocks, ["a", "b"])
        if cond is None:
            return mk("FAIL", None,
                       "no block found ending in a latopq-guarded (latopq.real/latopq.bogus) branch")

        s = z3.Solver()
        s.set("timeout", _SOLVER_TIMEOUT_MS)
        prog(f"Z3 proving predicate is a tautology, timeout={_SOLVER_TIMEOUT_MS}ms")
        s.push()
        s.add(cond != 1)
        always_true = s.check() == z3.unsat
        s.pop()
        s.push()
        s.add(cond == 1)
        always_false = s.check() == z3.unsat
        s.pop()

        extra = {
            "always_true_proven": str(always_true),
            "always_false_proven": str(always_false),
            "free_vars": str(len(lifter._fresh_cache)),
        }
        if always_true or always_false:
            which = "always-true" if always_true else "always-false"
            return mk("PASS", 0.0,
                       f"proved latopq predicate is {which} — bogus edge is prunable "
                       f"({_SOLVER_TIMEOUT_MS}ms budget)", extra)
        return mk("PASS", 1.0,
                   f"could not prove latopq predicate constant within {_SOLVER_TIMEOUT_MS}ms budget "
                   f"— bogus edge is not statically prunable", extra)

    except UnsupportedIR as e:
        return mk("FAIL", None, f"IR lifter hit unsupported construct: {e}")
    except Exception as e:
        return mk("FAIL", None, f"attack crashed: {e}")
