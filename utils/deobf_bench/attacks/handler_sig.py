"""Cross-function handler-signature collision attack — VMPass handler
polymorphism (handlerVariants=K).

Pure static IR analysis (no angr/z3): parses the obfuscated .ll, models a
cumulative-learning attacker who reverse-engineers one virtualised
function's opcode handlers then reuses that knowledge on the others.

signature(head block) = hash of its normalized instruction-opcode sequence
(operands / SSA names / types stripped), so two handler heads collide iff
they are structurally identical. At handlerVariants=1 every function's table
points at the same shared handler blocks => full collision => resilience
0.0. At K>1 the per-variant MBA metamorphism makes heads structurally
distinct => the attacker must re-analyze => resilience rises with K. This
attack therefore also validates that the metamorphism actually diversifies
(identical variant bodies would collide and resilience would stay ~0).
"""

from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path
from typing import Dict, List, Tuple

from . import AttackResult, register
from .. import cases as cases_mod
from ..runner_glue import compile_and_obfuscate

_ENGINE_NAME = "__vm_engine"

# ---- pure helpers (unit-testable on a raw IR string) -----------------------


def _normalize_instr(line: str) -> str | None:
    """Return the structural opcode token of one IR instruction line, or
    None for non-instruction lines (labels, blank, comments, braces)."""
    s = line.strip()
    if not s or s.startswith(";") or s.endswith(":") or s in ("{", "}"):
        return None
    # strip a leading 'ret'/'br'/... or '%name = <opcode> ...'
    if "=" in s:
        s = s.split("=", 1)[1].strip()
    tok = s.split(" ", 1)[0].strip()
    # ignore metadata-only / debug lines
    if not tok or tok.startswith("!") or tok.startswith("#"):
        return None
    return tok


def parse_engine_blocks(ir: str) -> Dict[str, List[str]]:
    """Map every basic-block label inside @__vm_engine to its normalized
    instruction-opcode sequence."""
    # isolate the @__vm_engine define{...} body
    m = re.search(r'define[^\n]*@' + re.escape(_ENGINE_NAME) + r'\b[^\n]*\{',
                  ir)
    if not m:
        return {}
    start = m.end()
    # brace-match to find the function body end
    depth = 1
    i = start
    while i < len(ir) and depth:
        c = ir[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
        i += 1
    body = ir[start:i - 1]
    blocks: Dict[str, List[str]] = {}
    cur = None
    # a label line looks like `LABEL:` possibly with trailing `; preds=...`
    label_re = re.compile(r'^\s*([%"]?[\w$.\-]+"?):(\s|$)')
    for line in body.splitlines():
        lm = label_re.match(line)
        if lm and not line.strip().startswith(";"):
            cur = lm.group(1).strip('%"')
            blocks[cur] = []
            continue
        op = _normalize_instr(line)
        if op is not None and cur is not None:
            blocks[cur].append(op)
    return blocks


def parse_handler_tables(ir: str) -> List[Tuple[str, List[str]]]:
    """Return [(fn_name, [ordered head-block labels]) ...] for each
    @<fn>.vm.ophandlers table, in IR appearance order. Skips the trailing
    engine-pointer slot (which is `ptr @__vm_engine`, not a blockaddress)."""
    out: List[Tuple[str, List[str]]] = []
    tbl_re = re.compile(r'@([\w$.\-]+)\.vm\.ophandlers\s*=\s*[^\n]*')
    ba_re = re.compile(
        r'blockaddress\(\s*@' + re.escape(_ENGINE_NAME) +
        r'\s*,\s*%"?([\w$.\-]+)"?\s*\)')
    for tm in tbl_re.finditer(ir):
        fn = tm.group(1)
        labels = ba_re.findall(tm.group(0))
        if labels:
            out.append((fn, labels))
    return out


def _sig(blocks: Dict[str, List[str]], label: str) -> str:
    seq = blocks.get(label, [])
    h = hashlib.sha1(("|".join(seq)).encode("utf-8")).hexdigest()
    return h


def score(tables, blocks) -> Tuple[float, dict]:
    """Cumulative-novelty resilience across functions 2..F."""
    db = set()
    total = 0
    novel = 0
    for i, (fn, labels) in enumerate(tables):
        sigs = [_sig(blocks, L) for L in labels]
        if i == 0:
            db.update(sigs)
            continue
        for s in sigs:
            total += 1
            if s not in db:
                novel += 1
                db.add(s)
    resilience = (novel / total) if total else 0.0
    stats = {
        "fns": str(len(tables)),
        "distinct_head_sigs": str(len(db)),
        "total_slots_scored": str(total),
        "novel_slots": str(novel),
    }
    return resilience, stats


# ---- attack entry point ----------------------------------------------------

_TOOL = "static IR parser"
_TECHNIQUE = "cross-function handler-signature collision (cumulative novelty)"


@register("hsig")
def run(case: "cases_mod.BenchCase", tools, work: Path, seed: int, *,
        verbose: bool = False, progress=None) -> AttackResult:
    t0 = time.monotonic()
    prog = progress or (lambda msg: None)

    def mk(status, resilience, detail, extra=None):
        return AttackResult(case.name, "hsig", seed, status, resilience,
                             detail, _TOOL, _TECHNIQUE,
                             time.monotonic() - t0, extra or {})

    try:
        prog("compiling + obfuscating (need obf.ll handler tables)")
        obf_ll = compile_and_obfuscate(tools, case, work, seed, verbose=verbose)
        ir = obf_ll.read_text(encoding="utf-8", errors="replace")

        if ("@" + _ENGINE_NAME) not in ir:
            return mk("FAIL", None, "no @__vm_engine in obf IR (vm pass didn't run?)")
        blocks = parse_engine_blocks(ir)
        if not blocks:
            return mk("FAIL", None, "could not parse @__vm_engine basic blocks")
        tables = parse_handler_tables(ir)
        if len(tables) < 2:
            return mk("FAIL", None,
                       f"handler_sig needs >=2 virtualised functions; found {len(tables)}")

        prog(f"scoring cumulative novelty across {len(tables)} handler tables")
        resilience, stats = score(tables, blocks)
        detail = (f"{stats['fns']} fns, {stats['distinct_head_sigs']} distinct head sigs, "
                  f"{stats['novel_slots']}/{stats['total_slots_scored']} slots forced fresh analysis")
        return mk("PASS", resilience, detail, stats)
    except Exception as e:
        return mk("FAIL", None, f"attack crashed: {e}")
