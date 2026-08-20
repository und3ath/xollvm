"""V2 demo: SLE-pool obfuscation — correctness + Z3/SiMBA resilience + diversity.

For each variant: build obf_target(a,b)=a+b, then
  * correctness: compile a self-checking exe (asserts obf_target==a+b over 100k
    inputs) at -O2, run, require exit 0;
  * Z3 attack (mba_smt lifter) -> resilience;
  * SiMBA attack (StringLifter + check_linear_mba) -> resilience;
  * count emitted sle.zero forms.
Also: pool-swap check (fallback vs $XOLLVM_SLE_POOL) changes the output.
"""
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(Path(r"C:\Users\und3ath\Desktop\llvm-o\SiMBA\src")))

import z3
from runner.config import detect_tools
from runner import pipeline
from runner.util import exe_name
from deobf_bench.attacks.mba_smt import _extract_fn_body, Lifter, _canonical, _SOLVER_TIMEOUT_MS
from deobf_bench.attacks.simba import StringLifter, _Nonlinear
from check_linear_mba import check_linear_mba
from simplify import simplify_linear_mba

BUILD = Path(r"C:\Users\und3ath\Desktop\llvm-o\xollvm-windows\build")
CFG = "Release"
SEED = 1

CHECK_SRC = '''#include <stdint.h>
#include <stdio.h>
__attribute__((noinline, annotate("{ann}")))
uint32_t obf_target(uint32_t a, uint32_t b) {{ return a + b; }}
int main(void) {{
    uint32_t s = 0x12345678u, t = 0x9abcdef0u;
    for (int i = 0; i < 100000; i++) {{
        if (obf_target(s, t) != (uint32_t)(s + t)) {{ printf("MISMATCH\\n"); return 1; }}
        s = s*1664525u + 1013904223u; t = t*22695477u + 1u;
    }}
    printf("OK\\n"); return 0;
}}
'''

VARIANTS = {
    "none":        "",
    "sle_augment": "obf: mba(prob=100,depth=2,maxSites=50,enableNonLinear=1,nonLinearWeight=60,sle=1,sleWeight=100,sleCount=2)",
    "sle_replace": "obf: mba(prob=100,depth=1,maxSites=50,sle=1,sleReplace=1,sleWeight=100,sleCount=2)",
}


def z3_attack(body):
    try:
        L = Lifter(z3, ["a", "b"]); rec = L.run(body)
        a, b = L.env["a"], L.env["b"]
        s = z3.Solver(); s.set("timeout", _SOLVER_TIMEOUT_MS); s.add(rec != _canonical(z3, "add", a, b))
        v = s.check()
        return 0.0 if v == z3.unsat else 1.0, str(v)
    except Exception as e:
        return None, f"err:{e}"


def simba_attack(body):
    try:
        L = StringLifter(["a", "b"]); expr = L.run(body)
    except _Nonlinear:
        return 1.0, "nonlinear"
    except Exception as e:
        return None, f"lift-err:{e}"
    if not check_linear_mba(expr):
        return 1.0, "nonlinear-check"
    if len(L.free) > 4:
        return 1.0, "too-many-vars"
    got = simplify_linear_mba(expr, 32, False)
    want = simplify_linear_mba("a + b", 32, False)
    return (0.0, f"->{got[:30]}") if got.strip() == want.strip() else (1.0, "not-canon")


def main():
    tools = detect_tools(BUILD, CFG)
    work = Path(tempfile.mkdtemp(prefix="v2demo_"))
    print(f"work: {work}\n")
    print(f"{'variant':<14} {'correct':<8} {'z3':<18} {'simba':<16} {'sle_forms':<10} {'ir':<5}")
    print("-" * 78)
    for name, ann in VARIANTS.items():
        d = work / name; d.mkdir(parents=True, exist_ok=True)
        src = d / "s.c"; src.write_text(CHECK_SRC.format(ann=ann), encoding="utf-8")
        base = d / "b.ll"; pipeline.compile_src_to_ll(tools, src, base, is_cpp=False)
        if ann:
            obf = d / "o.ll"; pipeline.run_obfuscation(tools, base, obf, SEED); use = obf
        else:
            use = base
        ir = use.read_text(encoding="utf-8", errors="replace")
        # correctness
        exe = d / exe_name("chk")
        pipeline.compile_ll_to_exe(tools, use, exe, "O2", is_cpp=False)
        r = subprocess.run([str(exe)], capture_output=True, text=True)
        correct = "OK" if r.returncode == 0 else f"FAIL({r.returncode})"
        # attacks
        body = _extract_fn_body(ir, "obf_target")
        if ann and body:
            zr, zv = z3_attack(body); sr, sv = simba_attack(body)
            z3s = f"{zr}={zv[:12]}" if zr is not None else zv[:16]
            sim = f"{sr}={sv[:8]}" if sr is not None else sv[:14]
            forms = len(re.findall(r"sle\.zero", ir))
        else:
            z3s = sim = "-"; forms = 0
        irn = len(body.splitlines()) if body else 0
        print(f"{name:<14} {correct:<8} {z3s:<18} {sim:<16} {forms:<10} {irn:<5}")

    # pool-swap: fallback vs env file
    print("\npool-swap (sle_replace, seed 1):")
    ann = VARIANTS["sle_replace"]
    def build_ir(env):
        d = work / f"swap_{'file' if env else 'fallback'}"; d.mkdir(exist_ok=True)
        src = d / "s.c"; src.write_text(CHECK_SRC.format(ann=ann), encoding="utf-8")
        base = d / "b.ll"; pipeline.compile_src_to_ll(tools, src, base, is_cpp=False)
        obf = d / "o.ll"
        e = dict(os.environ); e.pop("XOLLVM_SLE_POOL", None)
        if env: e["XOLLVM_SLE_POOL"] = env
        cmd = [str(tools.opt), "-passes=obfuscation", f"-obf-seed={SEED}", "-S", str(base), "-o", str(obf)]
        subprocess.run(cmd, env=e, capture_output=True, check=True)
        return _extract_fn_body(obf.read_text(encoding="utf-8", errors="replace"), "obf_target")
    fb = build_ir(None)
    fl = build_ir(str((HERE / "sle_pool.txt")))
    print(f"  fallback pool  -> {len(fb.splitlines())} IR lines")
    print(f"  file pool (256)-> {len(fl.splitlines())} IR lines")
    print(f"  differ = {fb != fl}  (expected True: bigger pool -> different form picked)")


if __name__ == "__main__":
    main()
