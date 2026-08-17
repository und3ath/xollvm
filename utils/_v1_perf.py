"""V1 perf tradeoff: runtime cost of input-derived zeros in the SHIPPED binary.

obf_target(a,b) = a + b, called in a hot noinline loop. Each variant's obf.ll is
compiled to an exe at -O2 (realistic release) and timed. Because input-derived
zeros are fold-resistant, they SURVIVE the -O2 and execute every call — that is
the cost we are measuring. Memory zeros, by contrast, may fold under -O2.

Reports: IR line count (compile-time proxy), wall time (best of 3), and ns/call.
"""
import re
import sys
import subprocess
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from runner.config import detect_tools           # noqa: E402
from runner import pipeline                       # noqa: E402
from runner.util import exe_name                  # noqa: E402

BUILD_DIR = r"C:\Users\und3ath\Desktop\llvm-o\xollvm-windows\build"
CONFIG = "Release"
SEED = 1
OPT = "O2"
N = 100_000_000          # loop iterations
REPEATS = 3

SRC_TMPL = '''#include <stdint.h>
#include <stdio.h>
__attribute__((noinline, annotate("{ann}")))
uint32_t obf_target(uint32_t a, uint32_t b) {{ return a + b; }}
int main(void) {{
    volatile uint32_t sink = 0;
    uint32_t a = 1u, b = 2u;
    for (uint64_t i = 0; i < {N}ULL; i++) {{
        sink += obf_target(a, b);
        a += (uint32_t)sink; b ^= a;
    }}
    printf("%u\\n", (uint32_t)sink);
    return 0;
}}
'''

# "none" = no obfuscation pass at all (pure a+b baseline).
VARIANTS = {
    "none":              None,
    "memory_strong":     "obf: mba(prob=100,depth=2,maxSites=50,enableNonLinear=1,nonLinearWeight=80,enableLayered=1)",
    "inputzero_augment": "obf: mba(prob=100,depth=2,maxSites=50,enableNonLinear=1,nonLinearWeight=80,enableLayered=1,inputZero=1,inputZeroWeight=100)",
    "inputzero_replace": "obf: mba(prob=100,depth=1,maxSites=50,inputZero=1,inputZeroReplace=1,inputZeroWeight=100,inputZeroCount=2)",
}


def time_exe(exe: Path):
    best = None
    for _ in range(REPEATS):
        t0 = time.monotonic()
        subprocess.run([str(exe)], capture_output=True, check=True)
        dt = time.monotonic() - t0
        best = dt if best is None else min(best, dt)
    return best


def main():
    tools = detect_tools(Path(BUILD_DIR), CONFIG)
    work = Path(tempfile.mkdtemp(prefix="v1perf_"))
    print(f"work: {work}   N={N:,}  opt=-{OPT}  best-of-{REPEATS}\n")
    print(f"{'variant':<18} {'ir_lines':>8} {'wall_s':>8} {'ns/call':>9} {'vs none':>8}")
    print("-" * 56)
    base_ns = None
    for name, ann in VARIANTS.items():
        d = work / name
        d.mkdir(parents=True, exist_ok=True)
        src = d / "src.c"
        src.write_text(SRC_TMPL.format(ann=ann or "", N=N), encoding="utf-8")
        base_ll = d / "base.ll"
        pipeline.compile_src_to_ll(tools, src, base_ll, is_cpp=False)
        if ann is None:
            use_ll = base_ll
            ir_lines = 0
        else:
            obf_ll = d / "obf.ll"
            pipeline.run_obfuscation(tools, base_ll, obf_ll, SEED)
            use_ll = obf_ll
            body = obf_ll.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"define[^\n]*@obf_target[^{]*\{(.*?)\n\}", body, re.S)
            ir_lines = len(m.group(1).strip().splitlines()) if m else -1
        exe = d / exe_name("bench")
        pipeline.compile_ll_to_exe(tools, use_ll, exe, OPT, is_cpp=False)
        wall = time_exe(exe)
        ns = wall / N * 1e9
        if base_ns is None:
            base_ns = ns
        mult = ns / base_ns if base_ns else 0
        print(f"{name:<18} {ir_lines:>8} {wall:>8.3f} {ns:>9.2f} {mult:>7.1f}x")


if __name__ == "__main__":
    main()
