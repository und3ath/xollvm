"""BCF opaque-predicate resilience attack — SMT proof, not CFG-size proxy.

`attacks/cfg_recovery.py` scores bcf on how much it inflates the *recovered*
CFG's block/edge count — a reasonable static-analysis-difficulty proxy, but
not the actual academic technique for defeating bogus control flow. The
real technique: bcf guards its injected junk block with a condition
(`%obf.ob<N>` in this codebase's IR, branching to `bcf.real<N>` /
`bcf.bogus.hdr<N>` labels — confirmed by inspecting real `-obf-verify`d IR
before writing this) that must always evaluate the same way for the
program to stay correct. If that invariant is provable by SMT regardless
of the "unknown" runtime values (stack-address entropy, salted per-loop
mixing) it's built from, the predicate is opaque only in *appearance* —
this module reuses `mba_smt.py`'s straight-line-IR-to-Z3 lifter (same
free-variable-for-unknowns model, same reasoning as that module's
docstring), scanning each basic block for one that ends in a
`bcf.real`/`bcf.bogus`-guarded conditional branch and lifting just that
block's own instructions to reach the condition, then asks Z3 whether it's
a tautology.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Dict, List

from . import AttackResult, register
from .. import cases as cases_mod
from .mba_smt import Lifter, UnsupportedIR, _extract_fn_body, _strip_flags
from ..runner_glue import compile_and_obfuscate

_SOLVER_TIMEOUT_MS = 5000


def _split_blocks(body: str) -> Dict[str, List[str]]:
    blocks: Dict[str, List[str]] = {}
    cur = "entry"
    blocks[cur] = []
    for raw in body.splitlines():
        line = raw.strip()
        if not line:
            continue
        # Label lines carry a trailing `; preds = ...` comment — strip it
        # before checking for the terminating `:` (labels never contain
        # `=` in the pre-comment part; instructions always do).
        head = line.split(";", 1)[0].strip()
        if head.endswith(":") and "=" not in head and " " not in head[:-1]:
            cur = head.rstrip(":")
            blocks.setdefault(cur, [])
            continue
        blocks[cur].append(line)
    return blocks


def _is_bcf_guard(label_a: str, label_b: str) -> bool:
    return any(t.startswith("bcf.real") or t.startswith("bcf.bogus") for t in (label_a, label_b))


_INSTR_RE = re.compile(r"^%([\w.]+)\s*=\s*(.+)$")


def _find_bcf_predicate(z3mod, blocks: Dict[str, List[str]], arg_names: List[str]):
    """Scans every block (in file order) for the first bcf-guarded
    conditional branch and lifts just that block's own instructions to
    reach it — bcf's opaque-predicate computation is self-contained within
    a single block (confirmed by inspection: it re-loads its salt/entropy
    sources fresh rather than depending on values threaded in from other
    blocks), so a per-block fresh Lifter is sufficient and avoids needing
    full inter-block dataflow. A fresh lifter per block also means a stack
    slot loaded here that *was* written in another block (e.g. the salt
    alloca, itself initialized from the same kind of entropy) resolves to
    its own free variable instead — a conservative modeling choice, not a
    hole: the salt is unconstrained runtime entropy either way, so treating
    it as one more free unknown is not a knowledge advantage the model is
    incorrectly withholding from the attacker.
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
                if not _is_bcf_guard(label_a, label_b) or cond_reg not in lifter.env:
                    break  # not a bcf guard (or condition wasn't locally defined) — try next block
                return lifter.env[cond_reg]
            if line.startswith(("br label", "ret ", "switch ", "indirectbr",
                                 "unreachable", "invoke ", "resume ", "call void")):
                break  # terminator reached without a usable bcf guard in this block
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
    return None


_TOOL = "z3-solver"
_TECHNIQUE = "SMT tautology proof on bcf's opaque-predicate branch condition"


@register("opaque")
def run(case: "cases_mod.BenchCase", tools, work: Path, seed: int, *,
        verbose: bool = False, progress=None) -> AttackResult:
    t0 = time.monotonic()
    prog = progress or (lambda msg: None)

    def mk(status: str, resilience, detail: str, extra: dict | None = None) -> AttackResult:
        return AttackResult(case.name, "opaque", seed, status, resilience, detail,
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
        prog(f"scanning {len(blocks)} basic blocks for one ending in a bcf-guarded branch")
        cond = _find_bcf_predicate(z3, blocks, ["a", "b"])
        if cond is None:
            return mk("FAIL", None,
                       "no block found ending in a bcf-guarded (bcf.real/bcf.bogus) branch")

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

        extra = {"always_true_proven": str(always_true), "always_false_proven": str(always_false)}
        if always_true or always_false:
            which = "always-true" if always_true else "always-false"
            return mk("PASS", 0.0,
                       f"proved bcf opaque predicate is {which} regardless of runtime entropy "
                       f"({_SOLVER_TIMEOUT_MS}ms budget)", extra)
        return mk("PASS", 1.0,
                   f"could not prove predicate constant within {_SOLVER_TIMEOUT_MS}ms budget", extra)

    except UnsupportedIR as e:
        return mk("FAIL", None, f"IR lifter hit unsupported construct: {e}")
    except Exception as e:
        return mk("FAIL", None, f"attack crashed: {e}")
