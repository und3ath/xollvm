"""V1 prototype demo (self-contained; no bench templates needed).

Compiles a leaf `obf_target(a,b) = a + b`, obfuscates it three ways via the
freshly built opt, then runs the repo's own Z3 MBA attack (mba_smt lifter +
solver) against each. resilience 1.0 = Z3 could not recover `a + b` in 5s.
Also counts emitted `mba.idz.*` ops to confirm the input-derived-zero path fired.
"""
import re
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent          # utils/
sys.path.insert(0, str(HERE))

import z3                                         # noqa: E402
from runner.config import detect_tools           # noqa: E402
from runner import pipeline                       # noqa: E402
from deobf_bench.attacks.mba_smt import (         # noqa: E402
    _extract_fn_body, Lifter, _canonical, _SOLVER_TIMEOUT_MS,
)

BUILD_DIR = r"C:\Users\und3ath\Desktop\llvm-o\xollvm-windows\build"
CONFIG = "Release"
SEED = 1

SRC_TMPL = '''#include <stdint.h>
__attribute__((noinline, annotate("{ann}")))
uint32_t obf_target(uint32_t a, uint32_t b) {{ return a + b; }}
int main(void) {{ return 0; }}
'''

VARIANTS = {
    "baseline_strong":   "obf: mba(prob=100,depth=2,maxSites=50,enableNonLinear=1,nonLinearWeight=80,enableLayered=1)",
    "inputzero_augment": "obf: mba(prob=100,depth=2,maxSites=50,enableNonLinear=1,nonLinearWeight=80,enableLayered=1,inputZero=1,inputZeroWeight=100)",
    "inputzero_replace": "obf: mba(prob=100,depth=1,maxSites=50,inputZero=1,inputZeroReplace=1,inputZeroWeight=100,inputZeroCount=2)",
}


def attack(obf_ir: str):
    body = _extract_fn_body(obf_ir, "obf_target")
    if body is None:
        return "no-body", None, 0
    lifter = Lifter(z3, ["a", "b"])
    recovered = lifter.run(body)
    a, b = lifter.env["a"], lifter.env["b"]
    canonical = _canonical(z3, "add", a, b)
    s = z3.Solver()
    s.set("timeout", _SOLVER_TIMEOUT_MS)
    s.add(recovered != canonical)
    v = s.check()
    resil = 0.0 if v == z3.unsat else 1.0
    return str(v), resil, len(body.splitlines())


def main():
    tools = detect_tools(Path(BUILD_DIR), CONFIG)
    work = Path(tempfile.mkdtemp(prefix="v1demo_"))
    print(f"work: {work}\n")
    print(f"{'variant':<18} {'z3_verdict':<18} {'resil':<6} {'idz_ops':<8} {'ir_lines':<8} {'solve_s':<8}")
    print("-" * 74)
    for name, ann in VARIANTS.items():
        d = work / name
        d.mkdir(parents=True, exist_ok=True)
        src = d / "src.c"
        src.write_text(SRC_TMPL.format(ann=ann), encoding="utf-8")
        base_ll = d / "base.ll"
        obf_ll = d / "obf.ll"
        pipeline.compile_src_to_ll(tools, src, base_ll, is_cpp=False)
        pipeline.run_obfuscation(tools, base_ll, obf_ll, SEED)
        ir = obf_ll.read_text(encoding="utf-8", errors="replace")
        idz = len(re.findall(r"mba\.idz\.", ir))
        t0 = time.monotonic()
        verdict, resil, lines = attack(ir)
        dt = time.monotonic() - t0
        r = "-" if resil is None else f"{resil:.1f}"
        print(f"{name:<18} {verdict:<18} {r:<6} {idz:<8} {lines:<8} {dt:<8.1f}")


if __name__ == "__main__":
    main()
