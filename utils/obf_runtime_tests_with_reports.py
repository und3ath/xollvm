#!/usr/bin/env python3
"""
obf_runtime_tests.py — Runtime differential correctness suite for the LLVM obfuscator.

Verifies:
  • Every obfuscation pass preserves program semantics (differential testing)
  • IR budget system limits instruction growth correctly
  • Anti-decompiler pass emits expected IR patterns
  • Seed determinism: same seed → bitwise-identical IR
  • Seed divergence: different seeds → different IR
  • O2 survival: obfuscated IR survives -O2 without breaking semantics

Cross-platform (Windows / Linux / macOS).

Examples:
  python obf_runtime_tests.py --build-dir ./build
  python obf_runtime_tests.py --build-dir ./build --seeds 1,2,3 --o2-gate
  python obf_runtime_tests.py --build-dir ./build --filter adec -v
  python obf_runtime_tests.py --build-dir ./build --quick --json-report report.json
  python obf_runtime_tests.py --build-dir ./build --list
  python obf_runtime_tests.py --build-dir ./build --category budget
"""

from __future__ import annotations

import argparse
import html
import json
import os
import platform
import random
import re
import shutil
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Any, Dict
# ═════════════════════════════════════════════════════════════════════════════
#  ANSI Color Support
# ═════════════════════════════════════════════════════════════════════════════

class _ColorState:
    """Mutable singleton so --no-color can be applied after import."""
    enabled: bool = True

    def __init__(self):
        self.enabled = self._detect()

    @staticmethod
    def _detect() -> bool:
        if os.environ.get("NO_COLOR"):
            return False
        if os.environ.get("FORCE_COLOR"):
            return True
        if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
            return False
        if platform.system() == "Windows":
            try:
                import ctypes
                k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
                h = k32.GetStdHandle(-11)
                m = ctypes.c_ulong()
                k32.GetConsoleMode(h, ctypes.byref(m))
                k32.SetConsoleMode(h, m.value | 0x0004)
                return True
            except Exception:
                return False
        return True


_cs = _ColorState()


def _c(code: str) -> str:
    """Return ANSI code if color enabled, else empty string."""
    return code if _cs.enabled else ""

# Styles
RST   = lambda: _c("\033[0m")
BOLD  = lambda: _c("\033[1m")
DIM   = lambda: _c("\033[2m")

# Foreground
RED     = lambda: _c("\033[31m")
GREEN   = lambda: _c("\033[32m")
YELLOW  = lambda: _c("\033[33m")
BLUE    = lambda: _c("\033[34m")
MAGENTA = lambda: _c("\033[35m")
CYAN    = lambda: _c("\033[36m")
WHITE   = lambda: _c("\033[37m")
GRAY    = lambda: _c("\033[90m")

BRED   = lambda: _c("\033[91m")
BGREEN = lambda: _c("\033[92m")
BYELLOW= lambda: _c("\033[93m")
BCYAN  = lambda: _c("\033[96m")

# Backgrounds
BG_RED   = lambda: _c("\033[41m")
BG_GREEN = lambda: _c("\033[42m")
BG_YELLOW= lambda: _c("\033[43m")


# ── Semantic formatters ───────────────────────────────────────────────────

def badge_pass()  -> str: return f"{BG_GREEN()}{BOLD()}{WHITE()} PASS {RST()}"
def badge_fail()  -> str: return f"{BG_RED()}{BOLD()}{WHITE()} FAIL {RST()}"
def badge_skip()  -> str: return f"{BG_YELLOW()}{BOLD()}{WHITE()} SKIP {RST()}"
def info(s: str)  -> str: return f"{CYAN()}[•]{RST()} {s}"
def warn(s: str)  -> str: return f"{YELLOW()}[!]{RST()} {s}"
def err(s: str)   -> str: return f"{RED()}[✗]{RST()} {s}"
def ok(s: str)    -> str: return f"{GREEN()}[✓]{RST()} {s}"
def head(s: str)  -> str: return f"{BOLD()}{BCYAN()}{s}{RST()}"
def dim(s: str)   -> str: return f"{DIM()}{s}{RST()}"
def bold(s: str)  -> str: return f"{BOLD()}{s}{RST()}"

def fmt_time(s: float) -> str:
    if s < 1.0:
        return f"{GRAY()}{s*1000:.0f}ms{RST()}"
    if s < 60.0:
        return f"{GRAY()}{s:.1f}s{RST()}"
    m, sec = divmod(s, 60)
    return f"{GRAY()}{int(m)}m{sec:.0f}s{RST()}"

def fmt_growth(ratio: float) -> str:
    if ratio <= 0:
        return f"{DIM()}—{RST()}"
    if ratio > 20:
        return f"{RED()}{ratio:.0f}×{RST()}"
    if ratio > 10:
        return f"{YELLOW()}{ratio:.0f}×{RST()}"
    return f"{GREEN()}{ratio:.1f}×{RST()}"

def _stripped_len(s: str) -> int:
    """Length of string with ANSI escape codes removed."""
    return len(re.sub(r"\033\[[0-9;]*m", "", s))


# ═════════════════════════════════════════════════════════════════════════════
#  Pass Definitions & Annotations
# ═════════════════════════════════════════════════════════════════════════════

PASSES = [
    "mba",
    "substitution",
    "vcall",
    "split",
    "sdiff",
    "bcf",
    "flattening",
    "shield",
    "strenc",  # module-only
]

ALL_PASSES_WITH_ADEC = PASSES + ["adec"]

PASS_ANN = {
    "flattening":   "flattening(minBlocks=3,maxBlocks=200,opaqueState=1,"
                    "fakeTransitions=1,fakeCases=2,domain=1,ptr=1,alias=1)",
    "bcf":          "bcf(prob=100,loop=1)",
    "split":        "split(num=3)",
    "substitution": "substitution(loop=1)",
    "mba":          "mba(prob=100,depth=2,maxSites=200)",
    "sdiff":        "sdiff(prob=100,slots=2,maxSites=40)",
    "shield":       "shield(maxSites=200,volatile=1,identity=1,dse=1,cfg=1)",
    "vcall":        "vcall(prob=100)",
    "strenc":       "strenc(minlen=4)",
    "adec":         "adec(prob=80,strength=2,maxSites=30)",
}

EXTRA_ANN = {
    "mba_advanced": (
        "mba(prob=100,depth=4,maxSites=400,"
        "termsMin=12,termsMax=20,"
        "enableNonLinear=1,nonLinearProb=70,"
        "enableLayered=1,layeredBudget=4,layeredWindow=72)"
    ),
    "opaque_families": (
        "flattening(minBlocks=3,maxBlocks=250,opaqueState=1,"
        "fakeTransitions=1,fakeCases=4,domain=1,ptr=1,alias=1), "
        "bcf(prob=100,loop=1)"
    ),
    "budget_low": (
        "mba(prob=100,depth=3,maxSites=300), "
        "bcf(prob=100,loop=2), "
        "substitution(loop=2)"
    ),
    "adec_full":  "adec(prob=90,strength=3,maxSites=50)",
    "adec_combo": (
        "mba(prob=80,depth=2), "
        "bcf(prob=60,loop=1), "
        "adec(prob=70,strength=2,maxSites=30)"
    ),
    "adec_selective": "adec(prob=100,strength=2,maxSites=40,asm=0,alias=0)",
    "adec_with_flat": (
        "flattening(minBlocks=3,maxBlocks=120), "
        "adec(prob=70,strength=2,maxSites=25)"
    ),
    "kitchen_sink": (
        "mba(prob=80,depth=2,maxSites=150), "
        "substitution(loop=1), "
        "split(num=2), "
        "bcf(prob=60,loop=1), "
        "sdiff(prob=80,slots=2,maxSites=30), "
        "flattening(minBlocks=3,maxBlocks=120), "
        "adec(prob=50,strength=1,maxSites=20)"
    ),
}


# ═════════════════════════════════════════════════════════════════════════════
#  Utilities
# ═════════════════════════════════════════════════════════════════════════════

def die(msg: str, code: int = 1) -> None:
    print(err(msg), file=sys.stderr)
    raise SystemExit(code)


def _quote(a: str) -> str:
    if any(c in a for c in (" ", "\t", '"')):
        return '"' + a.replace('"', '\\"') + '"'
    return a


def run_cmd(
    args: list[str], *,
    cwd: Path | None = None,
    capture: bool = True,
    verbose: bool = False,
    timeout: int = 180,
) -> subprocess.CompletedProcess[str]:
    pretty = " ".join(_quote(a) for a in args)
    if verbose:
        print(f"    {DIM()}$ {pretty}{RST()}")
    try:
        cp = subprocess.run(
            args, cwd=str(cwd) if cwd else None,
            text=True, capture_output=capture, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"TIMEOUT ({timeout}s): {pretty}")
    if cp.returncode != 0:
        tail = ""
        if capture:
            if cp.stderr: tail += cp.stderr[-600:]
            elif cp.stdout: tail += cp.stdout[-600:]
        raise RuntimeError(f"exit {cp.returncode}: {pretty}\n{tail.strip()}")
    return cp


# ── Tool detection ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Tools:
    clang: Path
    opt: Path


def detect_tools(build_dir: Path, config: str) -> Tools:
    exe = ".exe" if platform.system() == "Windows" else ""
    search = [build_dir / "bin", build_dir / config / "bin"]
    bin_dir = None
    for d in search:
        if (d / f"opt{exe}").exists():
            bin_dir = d
            break
    if not bin_dir:
        die(f"Cannot find opt in: {', '.join(str(d) for d in search)}")

    clang = bin_dir / f"clang{exe}"
    if not clang.exists():
        clang = bin_dir / f"clang-cl{exe}"
    if not clang.exists():
        die(f"clang not found in: {bin_dir}")

    return Tools(clang=clang, opt=bin_dir / f"opt{exe}")

# ── Obfuscation Report Helpers ────────────────────────────────────────────

def _is_subpath(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except Exception:
        return False


def find_obf_report_html_tool(build_dir: Path) -> Optional[Path]:
    # Best-effort locator for llvm/utils/obf_report_html.py.
    here = Path(__file__).resolve().parent
    candidates: list[Path] = [
        here / "obf_report_html.py",
        here / "llvm" / "utils" / "obf_report_html.py",
    ]

    b = build_dir.resolve()
    for p in [b] + list(b.parents):
        candidates.append(p / "llvm" / "utils" / "obf_report_html.py")
        candidates.append(p / "llvm-project" / "llvm" / "utils" / "obf_report_html.py")

    for c in candidates:
        if c.exists():
            return c
    return None


def _gen_obf_report_html(tool: Path, report_json: Path, out_html: Path, report_dir: Path, *, verbose: bool) -> Optional[str]:
    # Return error string on failure, else None.
    try:
        run_cmd(
            [
                sys.executable,
                str(tool),
                "--json", str(report_json),
                "--out", str(out_html),
                "--report-dir", str(report_dir),
                "--rendered", "wasm"
            ],
            verbose=verbose,
            capture=True,
        )
        return None
    except Exception as e:
        return str(e)


def write_obf_reports_index(report_root: Path, results: list['TestResult']) -> Path:
    # Write a simple index.html linking to all per-test reports.
    rows = []
    for r in results:
        status = r.status
        st_cls = "pass" if status == "PASS" else "fail" if status == "FAIL" else "skip"

        links = []
        for label, rel in sorted(r.report_html.items(), key=lambda kv: kv[0]):
            href = html.escape(rel, quote=True)
            links.append(f'<a href="{href}">{html.escape(label)}</a>')
        links_html = " ".join(links) if links else "&mdash;"

        rows.append(
            "<tr>"
            f"<td class='test'>{html.escape(r.name)}</td>"
            f"<td class='cat'>{html.escape(r.category)}</td>"
            f"<td class='st {st_cls}'>{html.escape(status)}</td>"
            f"<td class='t'>{r.elapsed:.2f}s</td>"
            f"<td class='links'>{links_html}</td>"
            "</tr>"
        )

    doc = '''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>LLVM Obfuscator — Test Reports</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;margin:24px;}
    h1{font-size:20px;margin:0 0 12px 0;}
    .meta{color:#555;margin-bottom:16px;}
    table{border-collapse:collapse;width:100%;}
    th,td{border:1px solid #ddd;padding:8px;vertical-align:top;}
    th{background:#f6f6f6;text-align:left;}
    td.st.pass{background:#e7f7ee;}
    td.st.fail{background:#ffe8e8;}
    td.st.skip{background:#fff6db;}
    td.links a{margin-right:10px;white-space:nowrap;}
    .small{font-size:12px;color:#666;}
  </style>
</head>
<body>
  <h1>LLVM Obfuscator — Runtime Test Reports</h1>
  <div class="meta small">Generated by obf_runtime_tests.py</div>
  <table>
    <thead>
      <tr>
        <th>Test</th><th>Category</th><th>Status</th><th>Time</th><th>Reports</th>
      </tr>
    </thead>
    <tbody>
''' + "\n".join(rows) + '''
    </tbody>
  </table>
</body>
</html>
'''

    out = report_root / "index.html"
    out.write_text(doc, encoding="utf-8", newline="\n")
    return out



# ── Annotation helpers ────────────────────────────────────────────────────

def ann_for(passes: list[str]) -> str:
    frags = [PASS_ANN[p] for p in passes if p in PASS_ANN]
    return "obf: " + ", ".join(frags)

def ann_extra(key: str) -> str:
    return "obf: " + EXTRA_ANN[key]


def pass_spec(pass_name: str, params: Optional[Dict[str, Any]] = None) -> str:
    """Render a pass spec like mba(prob=100,depth=2)."""
    if not params:
        return pass_name
    items = [f"{k}={params[k]}" for k in sorted(params.keys())]
    return f"{pass_name}({','.join(items)})"

def ann_specs(specs: List[str]) -> str:
    """Render a full annotation string from pass specs."""
    return "obf: " + ", ".join(specs)


# ── File / IR helpers ─────────────────────────────────────────────────────

def write_text(p: Path, s: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(s, encoding="utf-8", newline="\n")

def read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def count_fn_instructions(ir: str, fn_name: str = "obf_target") -> int:
    """Count instructions inside a specific function in textual LLVM IR."""
    pattern = re.compile(
        rf"^define\s[^@]*@{re.escape(fn_name)}\s*\(",
        re.MULTILINE,
    )
    m = pattern.search(ir)
    if not m:
        return 0
    depth = 0
    count = 0
    in_fn = False
    for line in ir[m.start():].splitlines():
        stripped = line.strip()
        if "{" in stripped:
            depth += stripped.count("{") - stripped.count("}")
            in_fn = True
            continue
        if "}" in stripped:
            depth += stripped.count("{") - stripped.count("}")
            if depth <= 0:
                break
            continue
        if not in_fn or not stripped or stripped.startswith(";"):
            continue
        if stripped.endswith(":") and "=" not in stripped:
            continue
        if ("=" in stripped or
            stripped.startswith(("store ", "br ", "ret ", "switch ",
                                "indirectbr ", "unreachable", "call void",
                                "invoke ", "resume "))):
            count += 1
    return count


def count_all_instructions(ir: str) -> int:
    """Rough global instruction count (fallback)."""
    count = 0
    for line in ir.splitlines():
        s = line.strip()
        if not s or s.startswith(";") or s.endswith(":"):
            continue
        if ("=" in s or
            s.startswith(("store ", "br ", "ret ", "switch ",
                          "indirectbr ", "unreachable", "call void"))):
            count += 1
    return count


# ═════════════════════════════════════════════════════════════════════════════
#  Test Program Template
# ═════════════════════════════════════════════════════════════════════════════

def render_program(annotation: str, *, want_strenc: bool = False) -> str:
    secret = "OBF_RUNTIME_SECRET_2026"
    maybe_puts = f'  puts("{secret}");\n' if want_strenc else ""

    return textwrap.dedent(f"""\
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>

    extern int puts(const char*);

    static __attribute__((noinline)) uint32_t calleeA(uint32_t x) {{
      x ^= 0xA5A5A5A5u;
      x = (x * 3u) + 1u;
      return x;
    }}

    static __attribute__((noinline)) uint32_t calleeB(uint32_t x) {{
      x ^= 0x12345678u;
      x = (x * 5u) - 7u;
      return x;
    }}

    static __attribute__((noinline)) uint32_t calleeC(uint32_t x) {{
      return (x ^ (x >> 7)) + 0x9E3779B9u;
    }}

    __attribute__((noinline, annotate("{annotation}")))
    uint32_t obf_target(uint32_t x, uint32_t y) {{
      volatile uint32_t vx = x;
      uint32_t r = calleeA(vx) + calleeB(y);

      uint32_t sx = x & 0xFFFFu;
      uint32_t sy = y & 0xFFFFu;
      r += (sx + 17u) ^ (sy * 3u);
      r ^= ((sx << 3) | (sy >> 2));

      if (r == (x + 42u)) r += 7u;
      if ((r ^ x) < (y + 3u)) r -= x;

      r = r + (x - y);
      r = r * 7u;
      r = r ^ calleeC(r);

      for (uint32_t i = 0; i < 4u; ++i) {{
        r += (i * 3u);
        if ((r + i) == (123u + x)) r -= x;
        if ((r ^ i) > (777u + y)) r += y;
      }}

      r = (r + (x ^ 0x13579BDFu)) * (uint32_t)(3u + (y & 7u));
      r ^= (r >> 5);
      r += (sx * sy) + 11u;

      switch (r & 3u) {{
        case 0: r += 1u; break;
        case 1: r ^= 0x55u; break;
        case 2: r -= 3u; break;
        default: r += 7u; break;
      }}

    {maybe_puts.rstrip()}
      return r;
    }}

    int main(int argc, char** argv) {{
      uint32_t x = (argc > 1) ? (uint32_t)strtoul(argv[1], 0, 0) : 123u;
      uint32_t y = (argc > 2) ? (uint32_t)strtoul(argv[2], 0, 0) : 456u;

      uint32_t acc = 0u;
      for (uint32_t i = 0u; i < 5u; ++i) {{
        acc ^= obf_target(x + i, y ^ i);
      }}

      printf("R=%u\\n", acc);
      return (int)(acc & 0xFFu);
    }}
    """)

def render_cpp_eh_program(annotation: str) -> str:
    """C++ Exception Handling and RAII test."""
    return textwrap.dedent(f"""\
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdexcept>

    struct Guard {{
        uint32_t* val;
        Guard(uint32_t* v) : val(v) {{ *val += 10; }}
        ~Guard() {{ *val += 5; }}
    }};

    __attribute__((noinline, annotate("{annotation}")))
    uint32_t obf_target(uint32_t x, uint32_t y) {{
        uint32_t status = 0;
        try {{
            Guard g(&status); // Test RAII/Unwinding
            if (x == 0) throw std::runtime_error("zero");
            if (x > y) {{
                status += (x ^ y);
                if (status % 2 == 0) throw 42;
            }}
            status += (x * y);
        }} catch (const std::runtime_error& e) {{
            status += 100;
        }} catch (int ecode) {{
            status += ecode;
        }} catch (...) {{
            status += 1;
        }}
        return status;
    }}

    int main(int argc, char** argv) {{
        uint32_t x = (argc > 1) ? (uint32_t)atoi(argv[1]) : 10;
        uint32_t y = (argc > 2) ? (uint32_t)atoi(argv[2]) : 5;
        printf("R=%u\\n", obf_target(x, y));
        return 0;
    }}
    """)

def render_complex_logic_program(annotation: str) -> str:
    """High cyclomatic complexity test with nested loops and deep switching."""
    return textwrap.dedent(f"""\
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>

    __attribute__((noinline, annotate("{annotation}")))
    uint32_t obf_target(uint32_t x, uint32_t y) {{
        uint32_t res = x;
        for (int i = 0; i < 5; ++i) {{
            switch ((res + i) % 4) {{
                case 0: 
                    for(int j=0; j<x%5; j++) res ^= (y + j);
                    break;
                case 1:
                    if (res > y) res -= y; else res += x;
                    break;
                case 2:
                    res = (res << 3) | (res >> 29);
                    break;
                case 3:
                    res *= 31;
                    break;
            }}
            if (res & 0x80000000) res >>= 1;
        }}
        return res;
    }}

    int main(int argc, char** argv) {{
        uint32_t x = (argc > 1) ? (uint32_t)atoi(argv[1]) : 123;
        uint32_t y = (argc > 2) ? (uint32_t)atoi(argv[2]) : 456;
        printf("R=%u\\n", obf_target(x, y));
        return 0;
    }}
    """)
# ═════════════════════════════════════════════════════════════════════════════
#  Compile / Run Helpers
# ═════════════════════════════════════════════════════════════════════════════

def compile_c_to_ll(tools: Tools, src: Path, out: Path, v: bool = False):
    run_cmd([
        str(tools.clang), "-O0", "-Xclang", "-disable-O0-optnone",
        "-fno-discard-value-names", "-S", "-emit-llvm",
        str(src), "-o", str(out),
    ], verbose=v)

def compile_ll_to_exe(tools: Tools, ll: Path, exe: Path, opt: str, v: bool = False):
    run_cmd([str(tools.clang), f"-{opt}", str(ll), "-o", str(exe)], verbose=v)


def clang_for_lang(tools: Tools, is_cpp: bool) -> str:
    """Select clang/clang++ for compilation and linking."""
    if not is_cpp:
        return str(tools.clang)
    if platform.system() == "Windows":
        return str(tools.clang)
    clang = Path(str(tools.clang))
    name = clang.name
    cands = []
    if name.startswith("clang-"):
        cands.append(clang.with_name(name.replace("clang-", "clang++-", 1)))
    cands.append(clang.with_name(name.replace("clang", "clang++", 1)))
    for c in cands:
        if c.exists():
            return str(c)
    return "clang++"

def compile_c_to_ll(tools: Tools, src: Path, out: Path, is_cpp: bool = False, v: bool = False):
    compiler = clang_for_lang(tools, is_cpp)
    extra = ["-std=c++17"] if (is_cpp and platform.system() != "Windows") else []
    run_cmd([
        compiler, "-O0", "-Xclang", "-disable-O0-optnone",
        "-fno-discard-value-names", "-S", "-emit-llvm",
        *extra, str(src), "-o", str(out),
    ], verbose=v)

def compile_ll_to_exe_lang(tools: Tools, ll: Path, exe: Path, opt: str, is_cpp: bool, v: bool = False):
    compiler = clang_for_lang(tools, is_cpp)
    extra = ["-std=c++17"] if (is_cpp and platform.system() != "Windows") else []
    run_cmd([compiler, f"-{opt}", *extra, str(ll), "-o", str(exe)], verbose=v)


def run_obfuscation(
    tools: Tools, base: Path, out: Path, seed: int,
    extra: list[str] | None = None, v: bool = False,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        str(tools.opt), "-passes=obfuscation",
        f"-obf-seed={seed}", "-obf-verify",
        "-S", str(base), "-o", str(out),
    ]
    if extra:
        cmd.extend(extra)
    return run_cmd(cmd, verbose=v, capture=True)



def run_dump_config(tools: Tools, base: Path, seed: int,
                    extra: list[str] | None = None, v: bool = False) -> subprocess.CompletedProcess[str]:
    cmd = [str(tools.opt), "-disable-output", "-passes=obf-dump-config",
           f"-obf-seed={seed}", str(base)]
    if extra:
        cmd.extend(extra)
    return run_cmd(cmd, verbose=v, capture=True)

def parse_dump_config_for_fn(dump_stdout: str, fn_name: str) -> tuple[list[str], list[str], Dict[str, Dict[str, str]]]:
    enabled: list[str] = []
    ordered: list[str] = []
    params: Dict[str, Dict[str, str]] = {}
    in_fn = False
    for raw in dump_stdout.splitlines():
        line = raw.rstrip("\n")
        if line.startswith("OBF-CONFIG-FN "):
            cur = line.split(maxsplit=1)[1].strip()
            in_fn = (cur == fn_name)
            continue
        if not in_fn:
            continue
        if line.startswith("  enabled:"):
            enabled = line.split(":", 1)[1].strip().split()
            continue
        if line.startswith("  ordered:"):
            ordered = line.split(":", 1)[1].strip().split()
            continue
        m = re.match(r"\s*pass\.([^:]+):\s*(.*)$", line)
        if not m:
            continue
        pid = m.group(1).strip()
        rest = m.group(2).strip()
        if rest == "(none)" or not rest:
            params[pid] = {}
            continue
        kv = {}
        for tok in rest.split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                kv[k] = v
        params[pid] = kv
    return enabled, ordered, params


def run_o2(tools: Tools, src: Path, out: Path, v: bool = False):
    run_cmd([str(tools.opt), "-passes=default<O2>", "-S", str(src), "-o", str(out)], verbose=v)

def run_metrics(tools: Tools, ll: Path, func: str) -> dict:
    cp = run_cmd([
        str(tools.opt), "-disable-output", "-passes=obf-metrics",
        f"-obf-metrics-function={func}", str(ll),
    ], capture=True)
    lines = [l.strip() for l in cp.stdout.splitlines() if l.strip()]
    if not lines:
        return {}
    try:
        return json.loads(lines[-1])
    except Exception:
        return {"_raw": lines[-1]}


def exec_prog(exe: Path, x: int, y: int) -> tuple[int, str, str]:
    try:
        cp = subprocess.run(
            [str(exe), str(x), str(y)],
            text=True, capture_output=True, timeout=30,
        )
        return cp.returncode, cp.stdout, cp.stderr
    except subprocess.TimeoutExpired:
        return -999, "", "TIMEOUT"

def compare(base: tuple, obf: tuple) -> Optional[str]:
    if base[0] != obf[0]:
        return f"exit: base={base[0]} obf={obf[0]}"
    if base[1] != obf[1]:
        bl, ol = base[1][:60], obf[1][:60]
        return f"stdout: base={bl!r} obf={ol!r}"
    if base[2] != obf[2]:
        return "stderr mismatch"
    return None


def build_inputs(n: int) -> list[tuple[int, int]]:
    rnd = random.Random(0xC0FFEE)
    fixed = [
        (0, 0), (1, 2), (2, 1), (7, 42), (42, 7),
        (123, 456), (456, 123),
        (0xFFFFFFFF, 0), (0x80000000, 0x7FFFFFFF), (0xDEADBEEF, 0xBADF00D),
        (1, 0xFFFFFFFF), (0x55555555, 0xAAAAAAAA),
    ]
    while len(fixed) < n:
        fixed.append((rnd.getrandbits(32), rnd.getrandbits(32)))
    return fixed[:n]


def _exe_name(stem: str) -> str:
    return stem + (".exe" if platform.system() == "Windows" else "")


# ═════════════════════════════════════════════════════════════════════════════
#  Feature Gates (IR pattern verification)
# ═════════════════════════════════════════════════════════════════════════════

def gate_mba_advanced(ir: str) -> Optional[str]:
    mul  = len(re.findall(r"\bmul i32\b", ir))
    urem = len(re.findall(r"\burem i32\b", ir))
    ops  = sum(len(re.findall(rf"\b{op} i32\b", ir))
               for op in ("add","sub","xor","and","or","shl","lshr"))
    if ops < 60:
        return f"too few i32 ops ({ops}, need ≥60)"
    if mul < 8:
        return f"need ≥8 mul i32, got {mul}"
    if urem == 0 and mul < 20:
        return "no urem and insufficient mul for nonlinear MBA"
    return None


def gate_opaque_families(ir: str) -> Optional[str]:
    if any(t in ir for t in ("obf.mba.", "obf.mod.", "obf.hash.", "obf.ptr.")):
        return None
    icmp = len(re.findall(r"\bicmp (eq|ne|ugt|ult|slt|sgt)\b", ir))
    vload = len(re.findall(r"load volatile i32", ir))
    if icmp < 20:
        return f"too few icmp ({icmp}, need ≥20)"
    if vload < 4:
        return f"too few volatile loads ({vload}, need ≥4)"
    return None


def gate_adec_patterns(ir: str) -> Optional[str]:
    """Verify anti-decompiler IR artifacts (at least 2 of 6 techniques)."""
    checks = {
        "asm":      ("asm sideeffect" in ir and
                     (".byte" in ir or ".4byte" in ir or "b 1f" in ir)),
        "ibr":      "indirectbr" in ir or "adec.ibr" in ir,
        "dead":     "adec.dead" in ir or "adec.dk" in ir,
        "stack":    "adec.stk" in ir,
        "call":     "adec.fp" in ir,
        "alias":    "adec.al" in ir,
    }
    found = [k for k, v in checks.items() if v]
    if len(found) < 2:
        return f"only {len(found)}/6 adec techniques: {found or 'none'}"
    return None


def gate_adec_type_confusion(ir: str) -> Optional[str]:
    has_i2f = "sitofp" in ir or "uitofp" in ir
    has_f2i = "fptoui" in ir or "fptosi" in ir
    if not (has_i2f and has_f2i):
        return "missing int↔float cross-casts in dead-code decoys"
    return None


def gate_adec_indirectbr(ir: str) -> Optional[str]:
    if "indirectbr" not in ir:
        return "no indirectbr found"
    if "blockaddress" not in ir:
        return "no blockaddress found"
    return None


def gate_budget_clamped(ir: str, base_ir: str, multiplier: int) -> Optional[str]:
    base_n = count_fn_instructions(base_ir, "obf_target")
    obf_n  = count_fn_instructions(ir, "obf_target")
    if base_n == 0:
        return "couldn't count base instructions"
    limit = base_n * multiplier
    if obf_n > limit * 1.3:
        return (f"budget overflow: {obf_n} > {limit} "
                f"(base={base_n}×{multiplier}, +30% tolerance)")
    return None


def gate_budget_verbose(stderr: str) -> Optional[str]:
    if "[budget]" not in stderr:
        return "no [budget] lines in verbose output"
    if not re.search(r"\[budget\].*->", stderr):
        return "no per-pass delta lines"
    return None


def gate_budget_exhaustion(stderr: str) -> Optional[str]:
    """Verify that at least one pass was skipped due to budget exhaustion."""
    if "EXHAUSTED" not in stderr and "skipping" not in stderr.lower():
        return "expected budget exhaustion (pass skipping) but none found"
    return None


def gate_budget_hardcap(ir: str, cap: int) -> Optional[str]:
    n = count_fn_instructions(ir, "obf_target")
    if n > cap * 1.3:
        return f"hard cap exceeded: {n} > {cap} (+30% tolerance)"
    return None


def gate_seed_determinism(ir_a: str, ir_b: str) -> Optional[str]:
    """Same seed must produce identical IR."""
    if ir_a != ir_b:
        for i, (la, lb) in enumerate(
                zip(ir_a.splitlines(), ir_b.splitlines()), 1):
            if la != lb:
                return f"IR diverges at line {i}: {la[:80]!r} vs {lb[:80]!r}"
        return "IR lengths differ"
    return None


def gate_seed_divergence(ir_a: str, ir_b: str) -> Optional[str]:
    """Different seeds should produce different IR."""
    if ir_a == ir_b:
        return "different seeds produced identical IR"
    return None


# ═════════════════════════════════════════════════════════════════════════════
#  Test Case Definitions
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class TestCase:
    name:         str
    passes:       list[str]
    ann_override: str | None  = None
    extra_opts:   list[str]   = field(default_factory=list)
    gates:        list[str]   = field(default_factory=list)
    # Expectations validated via `opt -passes=obf-dump-config`.
    expect_enabled: list[str]                 = field(default_factory=list)
    expect_order:   list[str]                 = field(default_factory=list)
    expect_config:  Dict[str, Dict[str, str]] = field(default_factory=dict)
    correctness:  bool        = True
    ir_only:      bool        = False
    category:     str         = "pass"


def make_tests() -> list[TestCase]:
    T = TestCase
    out: list[T] = []

    # ── Individual Pass Correctness ───────────────────────────────────
    for p in PASSES:
        out.append(T(name=f"rt_{p}", passes=[p], category="pass"))


    # ── Option Sweep Tests ────────────────────────────────────────────
    # Each supported option gets at least one explicit test.
    OPTION_SWEEPS: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {
        "bcf": [
            ("prob0", {"prob": 0}),
            ("prob100", {"prob": 100}),
            ("loop1", {"loop": 1}),
            ("loop10", {"loop": 10}),
            ("maxBlocks0", {"maxBlocks": 0}),
            ("maxBlocks100", {"maxBlocks": 100}),
        ],
        "split": [
            ("num2", {"num": 2}),
            ("num5", {"num": 5}),
            ("num10", {"num": 10}),
        ],
        "substitution": [
            ("loop1", {"loop": 1}),
            ("loop10", {"loop": 10}),
            ("maxSites0", {"maxSites": 0}),
            ("maxSites1", {"maxSites": 1}),
            ("maxSites100000", {"maxSites": 100000}),
        ],
        "mba": [
            ("prob0", {"prob": 0, "depth": 2, "maxSites": 200}),
            ("depth1", {"prob": 100, "depth": 1, "maxSites": 200}),
            ("depth10", {"prob": 100, "depth": 10, "maxSites": 200}),
            ("maxSites1", {"prob": 100, "depth": 2, "maxSites": 1}),
            ("maxSites5000", {"prob": 100, "depth": 2, "maxSites": 5000}),
            ("termsMin1", {"prob": 100, "depth": 2, "maxSites": 200, "termsMin": 1, "termsMax": 1}),
            ("termsMax96", {"prob": 100, "depth": 2, "maxSites": 200, "termsMin": 64, "termsMax": 96}),
            ("nonlinearOff", {"prob": 100, "depth": 2, "maxSites": 200, "enableNonLinear": 0}),
            ("nonlinearW100", {"prob": 100, "depth": 2, "maxSites": 200, "nonLinearWeight": 100}),
            ("layeredOff", {"prob": 100, "depth": 2, "maxSites": 200, "enableLayered": 0}),
            ("layeredWin256", {"prob": 100, "depth": 2, "maxSites": 200, "layeredWindow": 256}),
            ("layeredBudget32", {"prob": 100, "depth": 2, "maxSites": 200, "layeredBudget": 32}),
        ],
        "sdiff": [
            ("prob1", {"prob": 1, "slots": 2, "maxSites": 40}),
            ("prob100", {"prob": 100, "slots": 2, "maxSites": 40}),
            ("slots1", {"prob": 100, "slots": 1, "maxSites": 40}),
            ("slots8", {"prob": 100, "slots": 8, "maxSites": 40}),
            ("maxSites1", {"prob": 100, "slots": 2, "maxSites": 1}),
            ("maxSites2000", {"prob": 100, "slots": 2, "maxSites": 2000}),
        ],
        "vcall": [
            ("prob0", {"prob": 0}),
            ("prob100", {"prob": 100}),
            ("opaque0", {"prob": 100, "opaqueVTableNames": 0}),
            ("opaque1", {"prob": 100, "opaqueVTableNames": 1}),
            ("decoysOn", {"prob": 100, "addDecoyEntries": 1, "decoyMin": 1, "decoyMax": 4}),
            ("decoysOff", {"prob": 100, "addDecoyEntries": 0}),
            ("varyIndex3", {"prob": 100, "varyIndex": 1, "indexStrength": 3}),
            ("mergeOn", {"prob": 100, "merge": 1}),
            ("mergeOff", {"prob": 100, "merge": 0}),
        ],
        "strenc": [
            ("min1", {"minlen": 1}),
            ("min4", {"minlen": 4}),
            ("min100", {"minlen": 100}),
        ],
        "shield": [
            ("max1", {"maxSites": 1}),
            ("max10000", {"maxSites": 10000}),
            ("volatile0", {"volatile": 0}),
            ("identity0", {"identity": 0}),
            ("dse0", {"dse": 0}),
            ("cfg0", {"cfg": 0}),
            ("allOff", {"volatile": 0, "identity": 0, "dse": 0, "cfg": 0}),
        ],
        "flattening": [
            ("allowIndirect1", {"minBlocks": 2, "maxBlocks": 500, "allowIndirect": 1}),
            ("hybrid1", {"minBlocks": 2, "maxBlocks": 500, "hybrid": 1}),
            ("opaque0", {"minBlocks": 2, "maxBlocks": 500, "opaqueState": 0}),
            ("fake64", {"minBlocks": 2, "maxBlocks": 500, "fakeTransitions": 1, "fakeCases": 64}),
            ("domain0", {"minBlocks": 2, "maxBlocks": 500, "domain": 0}),
            ("ptr0", {"minBlocks": 2, "maxBlocks": 500, "ptr": 0}),
            ("alias0", {"minBlocks": 2, "maxBlocks": 500, "alias": 0}),
        ],
        "adec": [
            ("prob1", {"prob": 1, "strength": 1, "maxSites": 20}),
            ("prob100", {"prob": 100, "strength": 3, "maxSites": 200}),
            ("asm0", {"prob": 100, "strength": 2, "maxSites": 80, "asm": 0}),
            ("asm1", {"prob": 100, "strength": 2, "maxSites": 80, "asm": 1}),
            ("ibr0", {"prob": 100, "strength": 2, "maxSites": 80, "ibr": 0}),
            ("ibr1", {"prob": 100, "strength": 2, "maxSites": 80, "ibr": 1}),
            ("decoy0", {"prob": 100, "strength": 2, "maxSites": 80, "decoy": 0}),
            ("alias0", {"prob": 100, "strength": 2, "maxSites": 80, "alias": 0}),
        ],
    }

    for pid, cases in OPTION_SWEEPS.items():
        for suffix, params in cases:
            ann = ann_specs([pass_spec(pid, params)])
            exp = {pid: {k: str(v) for k, v in params.items()}}
            out.append(T(
                name=f"opt_{pid}_{suffix}",
                passes=[pid],
                ann_override=ann,
                expect_config=exp,
                category="options",
            ))

    # ── Alias + Ordering Tests ────────────────────────────────────────
    out.append(T(
        name="opt_alias_fla",
        passes=["flattening"],
        ann_override=ann_specs([pass_spec("fla", {"minBlocks": 2, "maxBlocks": 200})]),
        expect_enabled=["flattening"],
        category="options",
    ))
    out.append(T(
        name="opt_alias_sub",
        passes=["substitution"],
        ann_override=ann_specs([pass_spec("sub", {"loop": 2})]),
        expect_enabled=["substitution"],
        category="options",
    ))
    out.append(T(
        name="opt_alias_antidecompiler",
        passes=["adec"],
        ann_override=ann_specs([pass_spec("anti-decompiler", {"prob": 100, "strength": 2, "maxSites": 50})]),
        expect_enabled=["adec"],
        category="options",
    ))
    out.append(T(
        name="opt_alias_antiopt",
        passes=["shield"],
        ann_override=ann_specs([pass_spec("antiopt", {"maxSites": 50})]),
        expect_enabled=["shield"],
        category="options",
    ))

    out.append(T(
        name="meta_order_full_pipeline",
        passes=["flattening", "bcf", "sdiff", "split", "vcall", "substitution", "mba", "shield", "adec"],
        ann_override=ann_specs([
            "flattening(minBlocks=2,maxBlocks=500)",
            "bcf(prob=100,loop=2,maxBlocks=200)",
            "sdiff(prob=80,slots=3,maxSites=50)",
            "split(num=5)",
            "vcall(prob=80,merge=1,addDecoyEntries=1)",
            "substitution(loop=2,maxSites=2000)",
            "mba(prob=100,depth=4,maxSites=400,termsMin=12,termsMax=20)",
            "shield(maxSites=200,volatile=1,identity=1,dse=1,cfg=1)",
            "adec(prob=90,strength=2,maxSites=80)",
        ]),
        expect_order=["mba","substitution","vcall","split","sdiff","bcf","flattening","shield","adec"],
        category="meta",
    ))

    # ── Pairwise Combination Matrix (stress configs) ───────────────────
    STRESS: Dict[str, str] = {
        "mba": "mba(prob=100,depth=4,maxSites=400,termsMin=12,termsMax=20,enableNonLinear=1,nonLinearProb=70,enableLayered=1,layeredBudget=4,layeredWindow=72)",
        "substitution": "substitution(loop=2,maxSites=2000)",
        "vcall": "vcall(prob=90,maxSites=300,opaqueVTableNames=1,addDecoyEntries=1,decoyMin=1,decoyMax=4,varyIndex=1,indexStrength=2,merge=1)",
        "split": "split(num=5)",
        "sdiff": "sdiff(prob=80,slots=3,maxSites=80)",
        "bcf": "bcf(prob=90,loop=2,maxBlocks=500)",
        "flattening": "flattening(minBlocks=2,maxBlocks=500,allowIndirect=1,hybrid=1,opaqueState=1,fakeTransitions=1,fakeCases=4,domain=1,ptr=1,alias=1)",
        "shield": "shield(maxSites=200,volatile=1,identity=1,dse=1,cfg=1)",
        "strenc": "strenc(minlen=4)",
        "adec": "adec(prob=90,strength=2,maxSites=80,asm=1,ibr=1,stackPollution=1,decoy=1,callObfuscation=1,alias=1)",
    }

    all_for_matrix = PASSES + ["adec"]
    for a_i in range(len(all_for_matrix)):
        for b_i in range(a_i + 1, len(all_for_matrix)):
            a = all_for_matrix[a_i]
            b = all_for_matrix[b_i]
            out.append(T(
                name=f"mx_{a}__{b}",
                passes=[a, b],
                ann_override=ann_specs([STRESS[a], STRESS[b]]),
                category="matrix",
            ))



    # ── Combos ────────────────────────────────────────────────────────
    out.append(T(name="rt_combo_all", passes=PASSES[:], category="pass"))
    out.append(T(
        name="rt_kitchen_sink",
        passes=ALL_PASSES_WITH_ADEC[:],
        ann_override=ann_extra("kitchen_sink"),
        category="pass",
    ))

    # ── Feature Tests ─────────────────────────────────────────────────
    out.append(T(
        name="rt_mba_advanced", passes=["mba"],
        ann_override=ann_extra("mba_advanced"),
        gates=["mba_advanced"], category="feature",
    ))
    out.append(T(
        name="rt_opaque_families", passes=["flattening", "bcf"],
        ann_override=ann_extra("opaque_families"),
        gates=["opaque_families"], category="feature",
    ))

    # ── Anti-Decompiler ───────────────────────────────────────────────
    out.append(T(
        name="rt_adec", passes=["adec"],
        gates=["adec_patterns"],
        category="adec",
    ))
    out.append(T(
        name="rt_adec_full", passes=["adec"],
        ann_override=ann_extra("adec_full"),
        gates=["adec_patterns", "adec_type_confusion"],
        category="adec",
    ))
    out.append(T(
        name="rt_adec_combo", passes=["mba", "bcf", "adec"],
        ann_override=ann_extra("adec_combo"),
        gates=["adec_patterns"],
        category="adec",
    ))
    out.append(T(
        name="rt_adec_selective", passes=["adec"],
        ann_override=ann_extra("adec_selective"),
        gates=["adec_patterns"],
        category="adec",
    ))
    out.append(T(
        name="rt_adec_flat", passes=["flattening", "adec"],
        ann_override=ann_extra("adec_with_flat"),
        gates=["adec_patterns"],
        category="adec",
    ))

    # ── IR Budget System ──────────────────────────────────────────────
    out.append(T(
        name="rt_budget_low", passes=["mba", "bcf", "substitution"],
        ann_override=ann_extra("budget_low"),
        extra_opts=["--obf-ir-budget-multiplier=8"],
        gates=["budget_clamped_8"],
        category="budget",
    ))
    out.append(T(
        name="rt_budget_verbose", passes=["mba", "bcf", "substitution"],
        ann_override=ann_extra("budget_low"),
        extra_opts=["--obf-ir-budget-multiplier=20", "--obf-verbose"],
        gates=["budget_verbose"],
        category="budget",
    ))
    out.append(T(
        name="rt_budget_exhaust", passes=["mba", "bcf", "substitution"],
        ann_override=ann_extra("budget_low"),
        extra_opts=["--obf-ir-budget-multiplier=3", "--obf-verbose"],
        gates=["budget_exhaustion"],
        category="budget",
    ))
    out.append(T(
        name="rt_budget_unlimited", passes=["mba", "bcf"],
        extra_opts=["--obf-ir-budget-multiplier=0"],
        category="budget",
    ))
    out.append(T(
        name="rt_budget_hardcap", passes=["mba", "bcf", "substitution"],
        ann_override=ann_extra("budget_low"),
        extra_opts=["--obf-ir-budget-multiplier=100", "--obf-ir-budget-max=2000"],
        gates=["budget_hardcap_2000"],
        category="budget",
    ))

    # ── Meta ──────────────────────────────────────────────────────────
    out.append(T(
        name="rt_seed_determinism", passes=["mba", "bcf"],
        gates=["seed_determinism"],
        category="meta",
    ))
    out.append(T(
        name="rt_seed_divergence", passes=["mba", "bcf"],
        gates=["seed_divergence"],
        category="meta",
    ))
    
    
    # ── C++ & Exception Handling ─────────────────────────────────────
    out.append(T(
        name="rt_cpp_eh_basic", 
        passes=["flattening", "mba"], 
        category="cpp",
    ))
    out.append(T(
        name="rt_cpp_eh_full", 
        passes=ALL_PASSES_WITH_ADEC[:], 
        ann_override=ann_extra("kitchen_sink"),
        category="cpp",
    ))

    # ── Big Functions / Complex Logic ────────────────────────────────
    out.append(T(
        name="rt_complex_logic_flat", 
        passes=["flattening"], 
        category="pass",
    ))
    out.append(T(
        name="rt_complex_logic_heavy", 
        passes=["flattening", "bcf", "mba", "split"], 
        category="pass",
    ))

    return out


# ═════════════════════════════════════════════════════════════════════════════
#  Test Result
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class TestResult:
    name:       str
    category:   str   = "pass"
    status:     str   = "PASS"
    elapsed:    float = 0.0
    reason:     str   = ""
    base_insts: int   = 0
    obf_insts:  int   = 0
    seeds_run:  int   = 0
    inputs_run: int   = 0
    report_json: Dict[str, str] = field(default_factory=dict)
    report_html: Dict[str, str] = field(default_factory=dict)

# ═════════════════════════════════════════════════════════════════════════════
#  Gate Dispatcher
# ═════════════════════════════════════════════════════════════════════════════

def run_gate(
    key: str, *,
    obf_ir: str = "", base_ir: str = "",
    stderr_text: str = "",
    ir_a: str = "", ir_b: str = "",
) -> Optional[str]:
    if key == "mba_advanced":       return gate_mba_advanced(obf_ir)
    if key == "opaque_families":    return gate_opaque_families(obf_ir)
    if key == "adec_patterns":      return gate_adec_patterns(obf_ir)
    if key == "adec_type_confusion":return gate_adec_type_confusion(obf_ir)
    if key == "adec_indirectbr":    return gate_adec_indirectbr(obf_ir)
    if key == "budget_verbose":     return gate_budget_verbose(stderr_text)
    if key == "budget_exhaustion":  return gate_budget_exhaustion(stderr_text)
    if key == "seed_determinism":   return gate_seed_determinism(ir_a, ir_b)
    if key == "seed_divergence":    return gate_seed_divergence(ir_a, ir_b)
    m = re.match(r"budget_clamped_(\d+)", key)
    if m: return gate_budget_clamped(obf_ir, base_ir, int(m.group(1)))
    m = re.match(r"budget_hardcap_(\d+)", key)
    if m: return gate_budget_hardcap(obf_ir, int(m.group(1)))
    return f"unknown gate: {key}"


# ═════════════════════════════════════════════════════════════════════════════
#  Test Runner
# ═════════════════════════════════════════════════════════════════════════════

def run_test(
    tc: TestCase, tools: Tools, work: Path,
    seeds: list[int], inputs: list[tuple[int, int]],
    o2_gate: bool, no_metrics: bool, no_gates: bool, verbose: bool,
    report_enabled: bool, report_root: Path, report_html: bool, report_tool: Optional[Path],
) -> TestResult:
    t0 = time.monotonic()
    res = TestResult(name=tc.name, category=tc.category)
    tdir = work / tc.name
    tdir.mkdir(parents=True, exist_ok=True)

    # Per-test report root (separate from work so reports can persist even when work is cleaned).
    test_report_root: Optional[Path] = None
    if report_enabled:
        test_report_root = report_root / tc.name
        test_report_root.mkdir(parents=True, exist_ok=True)

    def _report_opts(label: str) -> tuple[list[str], Optional[Path]]:
        # Return (extra_opts, report_dir) for this obfuscation run label.
        if not report_enabled or test_report_root is None:
            return (list(tc.extra_opts or []), None)
        rdir = test_report_root / label
        rdir.mkdir(parents=True, exist_ok=True)
        opts = list(tc.extra_opts or [])
        opts.append(f"--obf-report-dir={rdir}")
        return (opts, rdir)

    ann = tc.ann_override or ann_for(tc.passes)
    # ... lines 534-535: tdir.mkdir... and ann = ...
    
    # --- INSERT START ---
    is_cpp = "cpp" in tc.category or "eh" in tc.name
    ext = ".cpp" if is_cpp else ".c"
    
    # Template Selection
    if "eh" in tc.name:
        c_src = render_cpp_eh_program(ann)
    elif "complex" in tc.name:
        c_src = render_complex_logic_program(ann)
    else:
        c_src = render_program(ann, want_strenc=("strenc" in tc.passes))

    c_file = tdir / f"test{ext}"
    write_text(c_file, c_src)

    # Use clang++ for C++ files
    compiler = str(tools.clang)
    if is_cpp and not platform.system() == "Windows": # on Linux/macOS
        compiler = compiler.replace("clang", "clang++")
    # --- INSERT END ---

    # Compile C → IR
    base_ll = tdir / "base.ll" # Line 539 in original
    try:
        # UPDATE THIS CALL to pass 'compiler'
        run_cmd([
            compiler, "-O0", "-Xclang", "-disable-O0-optnone",
            "-fno-discard-value-names", "-S", "-emit-llvm",
            str(c_file), "-o", str(base_ll),
        ], verbose=verbose)
    except Exception as e:
        res.status = "FAIL"; res.reason = f"clang→ll: {e}"
        res.elapsed = time.monotonic() - t0; return res

    base_ir = read_text(base_ll)
    res.base_insts = count_fn_instructions(base_ir, "obf_target") or count_all_instructions(base_ir)

    # Compile baseline exe
    base_exe = tdir / _exe_name("base")
    try:
        compile_ll_to_exe(tools, base_ll, base_exe, "O0", verbose)
    except Exception as e:
        res.status = "FAIL"; res.reason = f"base compile: {e}"
        res.elapsed = time.monotonic() - t0; return res

    # Special: seed determinism / divergence
    is_det = "seed_determinism" in tc.gates
    is_div = "seed_divergence" in tc.gates
    if (is_det or is_div) and not no_gates:
        s1, s2 = (42, 42) if is_det else (42, 99)
        ll_a, ll_b = tdir / "det_a.ll", tdir / "det_b.ll"
        try:
            extra_a, rdir_a = _report_opts(f"det_a_s{s1}")
            extra_b, rdir_b = _report_opts(f"det_b_s{s2}")
            run_obfuscation(tools, base_ll, ll_a, s1, extra_a or None, verbose)
            run_obfuscation(tools, base_ll, ll_b, s2, extra_b or None, verbose)

            # Optional HTML generation
            if report_enabled and report_html and report_tool:
                for label, rdir in ((f"det_a_s{s1}", rdir_a), (f"det_b_s{s2}", rdir_b)):
                    if not rdir:
                        continue
                    j = rdir / "obf_report.json"
                    h = rdir / "obf_report.html"
                    if j.exists():
                        why = _gen_obf_report_html(report_tool, j, h, rdir, verbose=verbose)
                        # Record paths even if HTML fails (JSON still useful).
                        try:
                            res.report_json[label] = str(j.relative_to(report_root))
                        except Exception:
                            res.report_json[label] = str(j)
                        if h.exists():
                            try:
                                res.report_html[label] = str(h.relative_to(report_root))
                            except Exception:
                                res.report_html[label] = str(h)
                        elif why and verbose:
                            print(warn(f"report html failed for {tc.name}:{label}: {why}"))

        except Exception as e:
            res.status = "FAIL"; res.reason = f"obf: {e}"
            res.elapsed = time.monotonic() - t0; return res
        ir_a, ir_b = read_text(ll_a), read_text(ll_b)
        key = "seed_determinism" if is_det else "seed_divergence"
        why = run_gate(key, ir_a=ir_a, ir_b=ir_b)
        if why:
            res.status = "FAIL"; res.reason = f"gate [{key}]: {why}"
        res.obf_insts = count_fn_instructions(ir_a, "obf_target")
        res.seeds_run = 2
        res.elapsed = time.monotonic() - t0
        return res

    # Per-seed loop
    for seed in seeds:
        obf_ll  = tdir / f"obf_s{seed}.ll"
        obf_exe = tdir / _exe_name(f"obf_s{seed}")

        try:
            extra_opts, rdir = _report_opts(f"seed_{seed}")
            cp = run_obfuscation(tools, base_ll, obf_ll, seed,
                                  extra_opts or None, verbose)
        except Exception as e:
            res.status = "FAIL"; res.reason = f"seed {seed}: opt: {e}"; break

        obf_ir = read_text(obf_ll)

        # Optional report HTML generation (best-effort; never fails the test).
        if report_enabled and rdir is not None:
            j = rdir / "obf_report.json"
            h = rdir / "obf_report.html"
            if j.exists():
                # Record JSON path
                try:
                    res.report_json[f"seed_{seed}"] = str(j.relative_to(report_root))
                except Exception:
                    res.report_json[f"seed_{seed}"] = str(j)

                if report_html and report_tool:
                    why = _gen_obf_report_html(report_tool, j, h, rdir, verbose=verbose)
                    if h.exists():
                        try:
                            res.report_html[f"seed_{seed}"] = str(h.relative_to(report_root))
                        except Exception:
                            res.report_html[f"seed_{seed}"] = str(h)
                    elif why and verbose:
                        print(warn(f"report html failed for {tc.name}:seed_{seed}: {why}"))
        n = count_fn_instructions(obf_ir, "obf_target")
        res.obf_insts = max(res.obf_insts, n or count_all_instructions(obf_ir))
        res.seeds_run += 1

        # Feature gates
        if not no_gates and tc.gates:
            stderr_text = cp.stderr or ""
            for gk in tc.gates:
                why = run_gate(gk, obf_ir=obf_ir, base_ir=base_ir,
                               stderr_text=stderr_text)
                if why:
                    res.status = "FAIL"
                    res.reason = f"seed {seed}: gate [{gk}]: {why}"
                    break
            if res.status == "FAIL":
                break

        if tc.ir_only:
            continue

        # Compile obfuscated IR
        try:
            compile_ll_to_exe(tools, obf_ll, obf_exe, "O0", verbose)
        except Exception as e:
            res.status = "FAIL"; res.reason = f"seed {seed}: compile: {e}"; break

        # Differential correctness
        if tc.correctness:
            fail = False
            for x, y in inputs:
                b = exec_prog(base_exe, x, y)
                o = exec_prog(obf_exe, x, y)
                why = compare(b, o)
                if why:
                    res.status = "FAIL"
                    res.reason = f"seed {seed}: {why} (x={x:#x} y={y:#x})"
                    fail = True; break
                res.inputs_run += 1
            if fail:
                break

        # O2 survival
        if o2_gate:
            b_o2_ll  = tdir / "base_O2.ll"
            o_o2_ll  = tdir / f"obf_s{seed}_O2.ll"
            b_o2_exe = tdir / _exe_name("base_O2")
            o_o2_exe = tdir / _exe_name(f"obf_s{seed}_O2")
            try:
                run_o2(tools, base_ll, b_o2_ll, verbose)
                run_o2(tools, obf_ll, o_o2_ll, verbose)
                compile_ll_to_exe(tools, b_o2_ll, b_o2_exe, "O0", verbose)
                compile_ll_to_exe(tools, o_o2_ll, o_o2_exe, "O0", verbose)
            except Exception as e:
                res.status = "FAIL"; res.reason = f"seed {seed}: O2: {e}"; break

            fail = False
            for x, y in inputs:
                b = exec_prog(b_o2_exe, x, y)
                o = exec_prog(o_o2_exe, x, y)
                why = compare(b, o)
                if why:
                    res.status = "FAIL"
                    res.reason = f"seed {seed}: O2: {why} (x={x:#x} y={y:#x})"
                    fail = True; break
            if fail:
                break

        # Metrics (best-effort)
        if not no_metrics:
            try:
                bm = run_metrics(tools, base_ll, "obf_target")
                om = run_metrics(tools, obf_ll, "obf_target")
                mf = tdir / "metrics.jsonl"
                with open(mf, "a", encoding="utf-8") as f:
                    f.write(json.dumps({
                        "test": tc.name, "seed": seed,
                        "passes": tc.passes, "base": bm, "obf": om,
                    }) + "\n")
            except Exception:
                pass

    res.elapsed = time.monotonic() - t0
    return res


# ═════════════════════════════════════════════════════════════════════════════
#  Summary Table
# ═════════════════════════════════════════════════════════════════════════════

def _cat_label(cat: str) -> str:
    m = {"pass": CYAN, "feature": MAGENTA, "budget": YELLOW,
         "adec": BLUE, "meta": GRAY}
    c = m.get(cat, DIM)
    return f"{c()}{cat[:4]}{RST()}"


def print_table(results: list[TestResult]) -> None:
    print()
    print(head("═" * 86))
    print(head("  Test Results"))
    print(head("═" * 86))
    print()

    nw = max((len(r.name) for r in results), default=10)
    nw = max(nw, 10)

    header = (f"  {'Test':<{nw}}  {'Cat':>4}  {'Status':>6}  {'Time':>7}  "
              f"{'Base':>6}  {'Obf':>6}  {'Grow':>6}  {'Seed':>4}  {'Inp':>5}")
    print(bold(header))
    rule = "─" * (nw + 58)
    print(f"  {rule}")

    for r in results:
        cat_s = _cat_label(r.category)
        st = (f"{GREEN()}PASS{RST()}" if r.status == "PASS" else
              f"{RED()}FAIL{RST()}" if r.status == "FAIL" else
              f"{YELLOW()}SKIP{RST()}")
        tm = fmt_time(r.elapsed)
        base_s = str(r.base_insts) if r.base_insts else "—"
        obf_s = str(r.obf_insts) if r.obf_insts else "—"
        ratio = (r.obf_insts / r.base_insts
                 if r.base_insts > 0 and r.obf_insts > 0 else 0)
        gr = fmt_growth(ratio)

        def _pad(s: str, w: int) -> str:
            return " " * max(0, w - _stripped_len(s)) + s

        print(f"  {r.name:<{nw}}  {_pad(cat_s,4)}  {_pad(st,6)}  {_pad(tm,7)}  "
              f"{base_s:>6}  {obf_s:>6}  {_pad(gr,6)}  {r.seeds_run:>4}  {r.inputs_run:>5}")

        if r.status == "FAIL" and r.reason:
            reason = r.reason[:110] + "..." if len(r.reason) > 113 else r.reason
            print(f"  {' ' * nw}  {DIM()}{RED()}↳ {reason}{RST()}")

    print(f"  {rule}")

    total   = len(results)
    passed  = sum(1 for r in results if r.status == "PASS")
    failed  = sum(1 for r in results if r.status == "FAIL")
    skipped = sum(1 for r in results if r.status == "SKIP")
    t_total = sum(r.elapsed for r in results)

    parts = []
    if passed:  parts.append(f"{GREEN()}{passed} passed{RST()}")
    if failed:  parts.append(f"{RED()}{failed} failed{RST()}")
    if skipped: parts.append(f"{YELLOW()}{skipped} skipped{RST()}")

    print()
    print(f"  {bold('Total:')} {total} tests — {', '.join(parts)}"
          f"  ({fmt_time(t_total)})")
    print()


# ═════════════════════════════════════════════════════════════════════════════
#  JSON Report
# ═════════════════════════════════════════════════════════════════════════════

def write_json_report(results: list[TestResult], path: Path) -> None:
    data = {
        "summary": {
            "total":   len(results),
            "passed":  sum(1 for r in results if r.status == "PASS"),
            "failed":  sum(1 for r in results if r.status == "FAIL"),
            "skipped": sum(1 for r in results if r.status == "SKIP"),
            "elapsed": round(sum(r.elapsed for r in results), 3),
        },
        "tests": [
            {
                "name":       r.name,
                "category":   r.category,
                "status":     r.status,
                "elapsed":    round(r.elapsed, 3),
                "reason":     r.reason,
                "base_insts": r.base_insts,
                "obf_insts":  r.obf_insts,
                "growth":     round(r.obf_insts / r.base_insts, 2)
                              if r.base_insts > 0 and r.obf_insts > 0 else 0,
                "seeds":      r.seeds_run,
                "inputs":     r.inputs_run,
                "report_json": r.report_json,
                "report_html": r.report_html,
            }
            for r in results
        ],
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ═════════════════════════════════════════════════════════════════════════════
#  Main
# ═════════════════════════════════════════════════════════════════════════════

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Runtime correctness + feature-gate test suite for the LLVM obfuscator.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            categories:
              pass     Individual & combo pass correctness
              feature  MBA-advanced, opaque-predicate families
              adec     Anti-decompiler patterns
              budget   IR instruction budget system
              meta     Seed determinism & divergence
        """),
    )
    ap.add_argument("--build-dir", default="", help="LLVM build directory (required unless --list)")
    ap.add_argument("--config", default="Debug", help="MSVC multi-config (Debug/Release)")
    ap.add_argument("--work", default="", help="Work directory for temp artifacts")
    ap.add_argument("--seeds", default="1", help="Comma-separated seeds (e.g. 1,2,3)")
    ap.add_argument("--inputs", default=24, type=int, help="Input pairs per test")
    ap.add_argument("--o2-gate", action="store_true", help="Test obf→O2 survival")
    ap.add_argument("--no-metrics", action="store_true", help="Skip obf-metrics collection")
    ap.add_argument("--no-gates", action="store_true", help="Skip IR feature-gate checks")
    ap.add_argument("--keep", action="store_true", help="Preserve work dir on success")
    ap.add_argument("--verbose", "-v", action="store_true", help="Print all commands")
    ap.add_argument("--filter", default="", help="Run only tests matching substring")
    ap.add_argument("--category", default="",
                    help="Run only tests in category (pass/feature/budget/adec/meta)")
    ap.add_argument("--list", action="store_true", help="List all tests and exit")
    ap.add_argument("--quick", action="store_true", help="Fewer inputs (8) for fast iteration")
    ap.add_argument("--no-color", action="store_true", help="Disable colored output")
    ap.add_argument("--json-report", default="", help="Write JSON report to path")
    ap.add_argument("--obf-report", action="store_true",
                    help="Enable obfuscation map + CFG artifact report generation for every obfuscation run")
    ap.add_argument("--obf-report-out", default="",
                    help="Output directory for reports (default: ./obf_reports)")
    ap.add_argument("--obf-report-no-html", action="store_true",
                    help="Disable HTML generation (still emits JSON + DOT via -obf-report-dir)")
    ap.add_argument("--obf-report-tool", default="",
                    help="Path to obf_report_html.py (auto-detect if empty)")
    args = ap.parse_args()

    if args.no_color:
        _cs.enabled = False

    all_tests = make_tests()

    # --list
    if args.list:
        cur_cat = ""
        for tc in all_tests:
            if tc.category != cur_cat:
                cur_cat = tc.category
                print(f"\n  {bold(f'── {cur_cat.upper()} ──')}")
            gates = f" {dim(f'gates: {chr(44).join(tc.gates)}')}" if tc.gates else ""
            passes = dim(f"({', '.join(tc.passes)})")
            print(f"    {CYAN()}•{RST()} {tc.name} {passes}{gates}")
        print()
        return 0

    # Filter
    if not args.build_dir:
        die("--build-dir is required (use --list to see tests without it)")
    if args.filter:
        all_tests = [t for t in all_tests if args.filter in t.name]
    if args.category:
        all_tests = [t for t in all_tests if t.category == args.category]
    if not all_tests:
        die("no tests match the filter/category")

    build_dir = Path(args.build_dir)
    tools = detect_tools(build_dir, args.config)
    work = Path(args.work) if args.work else (Path.cwd() / "obf_rt_work")
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    # Report configuration
    report_enabled = bool(args.obf_report)
    report_root = Path(args.obf_report_out) if args.obf_report_out else (Path.cwd() / "obf_reports")
    report_html = bool(report_enabled and not args.obf_report_no_html)
    report_tool: Optional[Path] = None

    if report_enabled:
        if report_root.exists():
            shutil.rmtree(report_root, ignore_errors=True)
        report_root.mkdir(parents=True, exist_ok=True)

        if report_html:
            if args.obf_report_tool:
                report_tool = Path(args.obf_report_tool)
            else:
                report_tool = find_obf_report_html_tool(build_dir)
            if not report_tool or not report_tool.exists():
                report_tool = None
                report_html = False

    work.mkdir(parents=True, exist_ok=True)

    seeds  = [int(s.strip()) for s in args.seeds.split(",") if s.strip()]
    n_inp  = 8 if args.quick else args.inputs
    inputs = build_inputs(n_inp)

    # Banner
    print()
    print(head("╔═══════════════════════════════════════════════════════════╗"))
    print(head("║    LLVM Obfuscator — Runtime Correctness Test Suite      ║"))
    print(head("╚═══════════════════════════════════════════════════════════╝"))
    print()
    print(info(f"clang:    {tools.clang}"))
    print(info(f"opt:      {tools.opt}"))
    print(info(f"work:     {work}"))
    print(info(f"seeds:    {seeds}"))
    print(info(f"inputs:   {n_inp} pairs"))
    print(info(f"O2 gate:  {'enabled' if args.o2_gate else 'disabled'}"))
    print(info(f"gates:    {'disabled' if args.no_gates else 'enabled'}"))
    if report_enabled:
        print(info("reports:  enabled"))
        print(info(f"report out: {report_root}"))
        if report_html and report_tool:
            print(info(f"report html: enabled ({report_tool})"))
        else:
            print(info("report html: disabled"))
    print(info(f"tests:    {len(all_tests)}"))
    print()

    # Run
    results: list[TestResult] = []
    t_start = time.monotonic()
    cur_cat = ""

    for i, tc in enumerate(all_tests, 1):
        if tc.category != cur_cat:
            cur_cat = tc.category
            label = cur_cat.upper()
            print(f"  {bold(f'── {label} ')}{dim('─' * (60 - len(label)))}")

        tag    = f"[{i}/{len(all_tests)}]"
        passes = dim(f"({', '.join(tc.passes)})")
        sys.stdout.write(f"  {bold(tag)} {tc.name} {passes} ")
        sys.stdout.flush()

        r = run_test(
            tc, tools, work, seeds, inputs,
            o2_gate=args.o2_gate, no_metrics=args.no_metrics,
            no_gates=args.no_gates, verbose=args.verbose,
            report_enabled=report_enabled, report_root=report_root,
            report_html=report_html, report_tool=report_tool,
        )
        results.append(r)

        if r.status == "PASS":
            print(f"{badge_pass()} {fmt_time(r.elapsed)}")
        elif r.status == "FAIL":
            print(f"{badge_fail()} {fmt_time(r.elapsed)}")
            reason = r.reason[:130] + "..." if len(r.reason) > 133 else r.reason
            print(f"         {DIM()}{RED()}↳ {reason}{RST()}")
        else:
            print(f"{badge_skip()} {fmt_time(r.elapsed)}")

    # Summary
    if report_enabled:
        idx = write_obf_reports_index(report_root, results)
        print(info(f"Obfuscation reports index → {idx}"))

    print_table(results)

    if args.json_report:
        rp = Path(args.json_report)
        write_json_report(results, rp)
        print(info(f"JSON report → {rp}"))

    # Exit
    failed = [r for r in results if r.status == "FAIL"]
    if failed:
        print()
        print(head("  Failed:"))
        for r in failed:
            print(f"    {RED()}✗{RST()} {r.name}: {r.reason}")
        print()
        print(f"  {BG_RED()}{BOLD()}{WHITE()} {len(failed)} FAILURE(S) {RST()}")
        print()
        return 1

    t_total = time.monotonic() - t_start
    print(f"  {BG_GREEN()}{BOLD()}{WHITE()} ALL {len(results)} TESTS PASSED {RST()}"
          f"  {fmt_time(t_total)}")
    print()

    if not args.keep:
        if report_enabled and _is_subpath(report_root, work):
            print(warn("report out dir is inside work; preserving work dir to keep reports"))
        else:
            shutil.rmtree(work, ignore_errors=True)
    else:
        print(info(f"work dir preserved: {work}"))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())