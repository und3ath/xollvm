#!/usr/bin/env python3
"""
obf_cross_arch.py — Cross-architecture testing for WSL + Windows-built LLVM.
Fix: Added assembly post-processing to strip modern RISC-V attributes.
"""

from __future__ import annotations
import argparse, os, platform, shutil, subprocess, sys, textwrap, time
from dataclasses import dataclass, field
from pathlib import Path

# ═════════════════════════════════════════════════════════════════════════════
#  ANSI Color & UI Helpers
# ═════════════════════════════════════════════════════════════════════════════

class _ColorState:
    enabled: bool = True
    def __init__(self): self.enabled = self._detect()
    @staticmethod
    def _detect() -> bool:
        return not os.environ.get("NO_COLOR") and sys.stdout.isatty()

_cs = _ColorState()
def _c(code: str) -> str: return code if _cs.enabled else ""
RST, BOLD, DIM = lambda: _c("\033[0m"), lambda: _c("\033[1m"), lambda: _c("\033[2m")
RED, GREEN, CYAN, GRAY, WHITE = lambda: _c("\033[31m"), lambda: _c("\033[32m"), lambda: _c("\033[36m"), lambda: _c("\033[90m"), lambda: _c("\033[97m")
BG_RED, BG_GREEN = lambda: _c("\033[41m"), lambda: _c("\033[42m")

def badge_pass(): return f"{BG_GREEN()}{BOLD()}{WHITE()} PASS {RST()}"
def badge_fail(): return f"{BG_RED()}{BOLD()}{WHITE()} FAIL {RST()}"
def head(s): return f"{BOLD()}{CYAN()}{s}{RST()}"

# ═════════════════════════════════════════════════════════════════════════════
#  C-Program Template
# ═════════════════════════════════════════════════════════════════════════════

def render_program(annotation: str, *, want_strenc: bool = False) -> str:
    maybe_puts = f'  puts("OBF_RUNTIME_SECRET_2026");\n' if want_strenc else ""
    return textwrap.dedent(f"""\
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>
    extern int puts(const char*);
    __attribute__((noinline, annotate("{annotation}")))
    uint32_t obf_target(uint32_t x, uint32_t y) {{
      uint32_t r = (x ^ 0xA5A5A5A5u) + (y ^ 0x12345678u);
      for (uint32_t i = 0; i < 4u; ++i) r += (i * 3u);
      {maybe_puts.rstrip()}
      return r;
    }}
    int main(int argc, char** argv) {{
      uint32_t x = (argc > 1) ? (uint32_t)strtoul(argv[1], 0, 0) : 123u;
      uint32_t y = (argc > 2) ? (uint32_t)strtoul(argv[2], 0, 0) : 456u;
      printf("R=%u\\n", obf_target(x, y));
      return 0;
    }}
    """)

# ═════════════════════════════════════════════════════════════════════════════
#  Architecture Definitions
# ═════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Target:
    name: str
    triple: str
    llc_arch: str
    cross_gcc: str
    qemu_bin: str
    llc_flags: list[str] = field(default_factory=list)

TARGETS = {
    "aarch64": Target("aarch64", "aarch64-linux-gnu", "aarch64", "aarch64-linux-gnu-gcc", "qemu-aarch64"),
    "arm32":   Target("arm32", "arm-linux-gnueabi", "arm", "arm-linux-gnueabi-gcc", "qemu-arm"),
    "riscv64": Target(
        name="riscv64",
        triple="riscv64-unknown-linux-gnu", 
        llc_arch="riscv64",
        cross_gcc="riscv64-linux-gnu-gcc",
        qemu_bin="qemu-riscv64",
        llc_flags=[
            "-target-abi=lp64d",
            "-mattr=+m,+a,+f,+d,+c,-relax", # Use base 'gc' features and disable relaxation
            "-relocation-model=static",
            "-code-model=medium",
        ]
    ),
}

PASS_ANN = {
    "flattening": "flattening(minBlocks=3)",
    "bcf":        "bcf(prob=100)",
    "mba":        "mba(prob=100)",
    "strenc":     "strenc(minlen=4)",
    "adec":       "adec(prob=100)",
}

# ═════════════════════════════════════════════════════════════════════════════
#  Execution Logic
# ═════════════════════════════════════════════════════════════════════════════

def resolve_tools(build_dir: str, config: str) -> dict[str, str]:
    bd = Path(build_dir)
    search_dirs = [bd / config / "bin", bd / "bin" / config, bd / "bin", bd / config]
    tools = {}
    for name in ["clang", "opt", "llc"]:
        found = False
        for d in search_dirs:
            exe_path = d / f"{name}.exe"
            if exe_path.exists():
                tools[name] = str(exe_path)
                found = True
                break
        if not found:
            print(f"{RED()}Error: Could not find {name}.exe in {build_dir}{RST()}")
            sys.exit(1)
    return tools

def run_cmd(args: list[str], verbose: bool = False):
    if verbose: print(f"    {GRAY()}$ {' '.join(args)}{RST()}")
    cp = subprocess.run(args, capture_output=True, text=True)
    if cp.returncode != 0:
        raise RuntimeError(f"Return {cp.returncode}\n{cp.stderr}")
    return cp

def run_arch_test(target: Target, p_name: str, tools: dict, work: Path, seed: int, verbose: bool):
    t_dir = work / f"{target.name}_{p_name}_s{seed}"
    t_dir.mkdir(parents=True, exist_ok=True)

    # 1. IR Generation
    c_file, base_ll = t_dir / "test.c", t_dir / "base.ll"
    c_file.write_text(render_program(f"obf: {PASS_ANN[p_name]}", want_strenc=(p_name == "strenc")))
    run_cmd([tools['clang'], "--target=" + target.triple, "-O0", "-S", "-emit-llvm", 
             "-Xclang", "-disable-O0-optnone", str(c_file), "-o", str(base_ll)], verbose)

    # 2. Obfuscation
    obf_ll = t_dir / "obf.ll"
    run_cmd([tools['opt'], "-passes=obfuscation", f"-obf-seed={seed}", "-S", str(base_ll), "-o", str(obf_ll)], verbose)

    # 3. Compile & Link (With Post-Processor)
    def build(ir, name):
        asm, exe = t_dir / f"{name}.s", t_dir / name
        
        # Windows LLC -> ASM
        run_cmd([tools['llc'], f"-mtriple={target.triple}", f"-march={target.llc_arch}"] + 
                target.llc_flags + [str(ir), "-o", str(asm)], verbose)
        
        # THE HACK: Strip problematic RISC-V metadata attributes
        if target.name == "riscv64":
            lines = asm.read_text().splitlines()
            # Deletes '.attribute' lines that confuse older GCC assemblers
            filtered = [l for l in lines if not l.strip().startswith(".attribute")]
            asm.write_text("\n".join(filtered))

        # Linux Cross-GCC -> EXE
        run_cmd([target.cross_gcc, "-static", str(asm), "-o", str(exe)], verbose)
        return exe

    base_exe, obf_exe = build(base_ll, "base"), build(obf_ll, "obf")

    # 4. QEMU Execution
    for x, y in [(10, 20), (123, 456)]:
        res_b = subprocess.run([target.qemu_bin, str(base_exe), str(x), str(y)], capture_output=True, text=True).stdout
        res_o = subprocess.run([target.qemu_bin, str(obf_exe), str(x), str(y)], capture_output=True, text=True).stdout
        if res_b != res_o:
            return False, f"Mismatch: {res_b.strip()} vs {res_o.strip()}"
    return True, ""

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", required=True)
    parser.add_argument("--config", default="Release")
    parser.add_argument("--seeds", default="1")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    tools = resolve_tools(args.build_dir, args.config)
    seeds = [int(s) for s in args.seeds.split(",")]
    work = Path.cwd() / "cross_work"
    if work.exists(): shutil.rmtree(work)
    work.mkdir()

    print(head("\n╔═══════════════════════════════════════════════════════════╗"))
    print(head("║       LLVM Obfuscator — Cross-Architecture Suite          ║"))
    print(head("╚═══════════════════════════════════════════════════════════╝\n"))

    for arch_name, arch in TARGETS.items():
        if not shutil.which(arch.cross_gcc) or not shutil.which(arch.qemu_bin):
            print(f"  {GRAY()}Architecture: {arch_name} (Skipped: missing toolchain){RST()}")
            continue

        print(f"  {BOLD()}Architecture: {arch_name}{RST()}")
        for p_name in PASS_ANN:
            for seed in seeds:
                sys.stdout.write(f"    • {p_name:<12} (s={seed}) ")
                sys.stdout.flush()
                try:
                    ok, msg = run_arch_test(arch, p_name, tools, work, seed, args.verbose)
                    print(badge_pass() if ok else f"{badge_fail()} {msg}")
                except Exception as e:
                    print(f"{badge_fail()} {str(e)[:100]}")

if __name__ == "__main__":
    main()