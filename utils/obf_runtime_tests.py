#!/usr/bin/env python3
# fix-rev: 4 -- VM src_override programs self-contained; add VM i64/div/select/switch coverage
"""
obf_runtime_test.py — Runtime differential correctness suite for the LLVM obfuscator.

Verifies:
  • Every obfuscation pass preserves program semantics (differential testing)
  • Option parsing and alias normalization via `opt -passes=obf-dump-config`
  • IR budget system limits instruction growth correctly
  • Anti-decompiler pass emits expected IR patterns
  • Seed determinism: same seed → bitwise-identical IR
  • Seed divergence: different seeds → different IR
  • O2 survival: obfuscated IR survives -O2 without breaking semantics

Cross-platform (Windows / Linux / macOS).

Examples:
  python obf_runtime_test.py --build-dir ./build
  python obf_runtime_test.py --build-dir ./build --extended
  python obf_runtime_test.py --build-dir ./build --extended --exhaustive-combos --combo-max-size 3
  python obf_runtime_test.py --build-dir ./build --seeds 1,2,3 --o2-gate
  python obf_runtime_test.py --build-dir ./build --filter adec -v
  python obf_runtime_test.py --build-dir ./build --quick --json-report report.json
  python obf_runtime_test.py --build-dir ./build --list
  python obf_runtime_test.py --build-dir ./build --category budget
"""

from __future__ import annotations

import argparse
import html
import itertools
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
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Any, Dict, List, Tuple

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
    "vm",
    "shield",
    "strenc",  # module-only
]

ALL_PASSES_WITH_ADEC = PASSES + ["adec"]

PASS_ANN: Dict[str, str] = {
    "flattening":   "flattening(minBlocks=3,maxBlocks=200,opaqueState=1,"
                    "fakeTransitions=1,fakeCases=2,domain=1,ptr=1,alias=1)",
    "bcf":          "bcf(prob=100,loop=1)",
    "split":        "split(num=3)",
    "substitution": "substitution(loop=1)",
    "mba":          "mba(prob=100,depth=2,maxSites=200)",
    "sdiff":        "sdiff(prob=100,slots=2,maxSites=40)",
    "shield":       "shield(maxSites=200,volatile=1,identity=1,dse=1,cfg=1)",
    "vcall":        "vcall(prob=100)",
    "vm":           "vm(minBlocks=1,obfRegIdx=1,encBytecode=1)",
    "strenc":       "strenc(minlen=4,aes=1,keysplit=1)",
    "adec":         "adec(prob=80,strength=2,maxSites=30)",
}

EXTRA_ANN: Dict[str, str] = {
    "mba_advanced": (
        "mba(prob=100,depth=4,maxSites=400,"
        "termsMin=12,termsMax=20,"
        "enableNonLinear=1,nonLinearWeight=70,"
        "enableLayered=1,layeredBudget=4,layeredWindow=72)"
    ),
    "opaque_families": (
        "flattening(prob=100,minBlocks=3,maxBlocks=250,opaqueState=1,"
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
        "mba(prob=80,depth=2,maxSites=200), "
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
        "vcall(prob=50), "
        "split(num=2), "
        "bcf(prob=60,loop=1), "
        "sdiff(prob=80,slots=2,maxSites=30), "
        "flattening(prob=100,minBlocks=3,maxBlocks=120), "
        "shield(maxSites=200,volatile=1,identity=1,dse=1,cfg=1), "
        "strenc(minlen=4,aes=1,keysplit=1), "
        "adec(prob=50,strength=1,maxSites=20)"
    ),
    # ── VM pass v7 annotation bundles ─────────────────────────────────────
    # Full hardening (both layers on — the only recommended config)
    "vm_v7":            "vm(minBlocks=1,obfRegIdx=1,encBytecode=1)",
    # Minimal: no hardening layers
    "vm_v7_bare":       "vm(minBlocks=1,obfRegIdx=0,encBytecode=0)",
    # Index obfuscation only
    "vm_v7_obfidx":     "vm(minBlocks=1,obfRegIdx=1,encBytecode=0)",
    # Bytecode encryption only
    "vm_v7_enc":        "vm(minBlocks=1,obfRegIdx=0,encBytecode=1)",
    "vm_v7_hardened":   "vm(minBlocks=1,obfRegIdx=1,encBytecode=1,hardened=1)",
    "vm_v7_regenc":     "vm(minBlocks=1,obfRegIdx=1,encBytecode=1,regEncrypt=1)",
    "vm_v7_regenc_hardened": "vm(minBlocks=1,obfRegIdx=1,encBytecode=1,hardened=1)",
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
            if cp.stderr:
                tail += cp.stderr[-600:]
            elif cp.stdout:
                tail += cp.stdout[-600:]
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


def _gen_obf_report_html(
    tool: Path, report_json: Path, out_html: Path, report_dir: Path, *,
    verbose: bool,
) -> Optional[str]:
    # Return error string on failure, else None.
    try:
        run_cmd(
            [
                sys.executable,
                str(tool),
                "--json", str(report_json),
                "--out", str(out_html),
                "--report-dir", str(report_dir),
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

    doc = """<!doctype html>
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
  <div class="meta small">Generated by obf_runtime_test.py</div>
  <table>
    <thead>
      <tr>
        <th>Test</th><th>Category</th><th>Status</th><th>Time</th><th>Reports</th>
      </tr>
    </thead>
    <tbody>
""" + "\n".join(rows) + """
    </tbody>
  </table>
</body>
</html>
"""

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


def ann_specs(specs: list[str]) -> str:
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
#  Test Program Templates
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
        }} catch (const std::runtime_error&) {{
            status += 100;
        }} catch (int ecode) {{
            status += (uint32_t)ecode;
        }} catch (...) {{
            status += 1;
        }}
        return status;
    }}

    int main(int argc, char** argv) {{
        uint32_t x = (argc > 1) ? (uint32_t)strtoul(argv[1], 0, 0) : 10u;
        uint32_t y = (argc > 2) ? (uint32_t)strtoul(argv[2], 0, 0) : 5u;
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
            switch ((res + (uint32_t)i) % 4u) {{
                case 0:
                    for (uint32_t j = 0; j < (x % 5u); j++) res ^= (y + j);
                    break;
                case 1:
                    if (res > y) res -= y; else res += x;
                    break;
                case 2:
                    res = (res << 3) | (res >> 29);
                    break;
                case 3:
                    res *= 31u;
                    break;
            }}
            if (res & 0x80000000u) res >>= 1;
        }}
        return res;
    }}

    int main(int argc, char** argv) {{
        uint32_t x = (argc > 1) ? (uint32_t)strtoul(argv[1], 0, 0) : 123u;
        uint32_t y = (argc > 2) ? (uint32_t)strtoul(argv[2], 0, 0) : 456u;
        printf("R=%u\\n", obf_target(x, y));
        return 0;
    }}
    """)




# ─────────────────────────────────────────────────────────────────────────────
#  VM-specific render functions
#
#  These generate self-contained C programs (with main) that still name the
#  annotated function "obf_target", so:
#    • dump-config validation finds "OBF-CONFIG-FN obf_target" as usual
#    • count_fn_instructions("obf_target") works normally
#    • runtime differential checks work with the standard (x, y) argv interface
# ─────────────────────────────────────────────────────────────────────────────

def render_vm_v7_memory_program(annotation: str) -> str:
    """VM: exercise loads/stores through pointers and array indexing."""
    return textwrap.dedent(f"""\
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>

    __attribute__((noinline, annotate("{annotation}")))
    uint32_t obf_target(uint32_t x, uint32_t y) {{
        uint32_t arr[8];
        for (uint32_t i = 0; i < 8u; ++i) {{
            arr[i] = (x + i) ^ (y + (i * 3u));
        }}
        uint32_t idx = (x ^ (y << 1)) & 7u;
        uint32_t *p = &arr[idx];
        uint32_t v = *p;                 /* load */
        *p = v + (y & 0xFFu);            /* store */
        uint32_t w = arr[(idx + 5u) & 7u];
        return (v ^ w) + arr[idx];
    }}

    int main(int argc, char** argv) {{
        uint32_t x = (argc > 1) ? (uint32_t)strtoul(argv[1], 0, 0) : 123u;
        uint32_t y = (argc > 2) ? (uint32_t)strtoul(argv[2], 0, 0) : 456u;
        uint32_t r = obf_target(x, y);
        printf("R=%u\\n", r);
        return (int)(r & 0xFFu);
    }}
    """)


def render_vm_v7_gep_chain_program(annotation: str) -> str:
    """VM: exercise GEP chains (pointer arithmetic) and array traffic."""
    return textwrap.dedent(f"""\
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>

    __attribute__((noinline, annotate("{annotation}")))
    uint32_t obf_target(uint32_t x, uint32_t y) {{
        uint32_t a[16];
        uint32_t b[16];
        for (uint32_t i = 0; i < 16u; ++i) {{
            a[i] = x + (i * 7u);
            b[i] = y ^ (i * 13u);
        }}

        uint32_t idx = (x + y) & 15u;
        uint32_t *pa = &a[0];
        uint32_t *pb = &b[0];
        uint32_t *p  = pa + idx;
        uint32_t *q  = pb + ((idx ^ 7u) & 15u);

        uint32_t vx = *p;
        uint32_t vy = *q;
        uint32_t r  = (vx + vy) ^ (x * 3u);

        *(pa + ((idx + 5u) & 15u)) = r ^ y; /* store via GEP chain */
        return r ^ a[(idx + 5u) & 15u];
    }}

    int main(int argc, char** argv) {{
        uint32_t x = (argc > 1) ? (uint32_t)strtoul(argv[1], 0, 0) : 123u;
        uint32_t y = (argc > 2) ? (uint32_t)strtoul(argv[2], 0, 0) : 456u;
        uint32_t r = obf_target(x, y);
        printf("R=%u\\n", r);
        return (int)(r & 0xFFu);
    }}
    """)


def render_vm_v7_call_program(annotation: str) -> str:
    """VM: force direct calls so the VM pass must model callees."""
    return textwrap.dedent(f"""\
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>

    static __attribute__((noinline)) int helper(int a, int b) {{
        int x = (a * 3) + (b * 5);
        return (x ^ (a - b)) + 17;
    }}

    __attribute__((noinline, annotate("{annotation}")))
    uint32_t obf_target(uint32_t x, uint32_t y) {{
        int a = (int)x;
        int b = (int)y;
        int r;
        if (a > b) r = helper(a, b);
        else       r = helper(b, a) ^ a;
        return (uint32_t)r;
    }}

    int main(int argc, char** argv) {{
        uint32_t x = (argc > 1) ? (uint32_t)strtoul(argv[1], 0, 0) : 123u;
        uint32_t y = (argc > 2) ? (uint32_t)strtoul(argv[2], 0, 0) : 456u;
        uint32_t r = obf_target(x, y);
        printf("R=%u\\n", r);
        return (int)(r & 0xFFu);
    }}
    """)


def render_vm_v7_casts_program(annotation: str) -> str:
    """VM: exercise casts (zext/sext/trunc) from narrow integer types."""
    return textwrap.dedent(f"""\
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>

    __attribute__((noinline, annotate("{annotation}")))
    uint32_t obf_target(uint32_t x, uint32_t y) {{
        short s = (short)(x & 0xFFFFu);
        char  c = (char)(y & 0xFFu);

        int a = (int)s + (int)x;
        int b = (int)(unsigned char)c;
        short t = (short)(a & 0x7FFF);

        /* force both signed and unsigned extensions */
        int32_t t32 = (int32_t)(a ^ b);
        int64_t sext = (int64_t)t32;
        uint32_t u32 = (uint32_t)(a + (uint32_t)b);
        uint64_t zext = (uint64_t)u32;

        uint64_t mix = (uint64_t)sext + zext + (uint64_t)(uint16_t)t;
        return (uint32_t)(mix ^ (mix >> 32));
    }}

    int main(int argc, char** argv) {{
        uint32_t x = (argc > 1) ? (uint32_t)strtoul(argv[1], 0, 0) : 123u;
        uint32_t y = (argc > 2) ? (uint32_t)strtoul(argv[2], 0, 0) : 456u;
        uint32_t r = obf_target(x, y);
        printf("R=%u\\n", r);
        return (int)(r & 0xFFu);
    }}
    """)


def render_vm_v7_icmp_program(annotation: str) -> str:
    """VM: comparisons and multi-way control flow based on ICMP results."""
    return textwrap.dedent(f"""\
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>

    __attribute__((noinline, annotate("{annotation}")))
    uint32_t obf_target(uint32_t x, uint32_t y) {{
        int a = (int)x;
        int b = (int)y;
        int c = (int)(x ^ y);
        int r = 0;
        if (a < b) r = a + c;
        else if (a > c) r = b ^ c;
        else r = a & b & c;
        return (uint32_t)r;
    }}

    int main(int argc, char** argv) {{
        uint32_t x = (argc > 1) ? (uint32_t)strtoul(argv[1], 0, 0) : 123u;
        uint32_t y = (argc > 2) ? (uint32_t)strtoul(argv[2], 0, 0) : 456u;
        uint32_t r = obf_target(x, y);
        printf("R=%u\\n", r);
        return (int)(r & 0xFFu);
    }}
    """)


def render_vm_v7_multiblock_program(annotation: str) -> str:
    """VM: deep multi-block CFG with nested branches and a small loop."""
    return textwrap.dedent(f"""\
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>

    __attribute__((noinline, annotate("{annotation}")))
    uint32_t obf_target(uint32_t x, uint32_t y) {{
        int a = (int)x;
        int b = (int)y;
        int c = (int)(x + y);
        int d = (int)(x ^ y);

        int x1 = a + b;
        int y1 = c ^ d;
        int z;
        if (x1 > y1) {{
            z = x1 * (c & 0xFF);
            if (z > 1000) z = z - 1000;
        }} else {{
            z = y1 | (a & b);
        }}

        for (int i = 0; i < 3; ++i) {{
            if ((z + i) & 1) z ^= (a + i);
            else z += (b - i);
        }}

        return (uint32_t)(z ^ (x1 + y1));
    }}

    int main(int argc, char** argv) {{
        uint32_t x = (argc > 1) ? (uint32_t)strtoul(argv[1], 0, 0) : 123u;
        uint32_t y = (argc > 2) ? (uint32_t)strtoul(argv[2], 0, 0) : 456u;
        uint32_t r = obf_target(x, y);
        printf("R=%u\\n", r);
        return (int)(r & 0xFFu);
    }}
    """)


def render_vm_v7_i64_ops_program(annotation: str) -> str:
    """VM: cover select, div/rem, i64 ops, ptrtoint64, cast64 and switch."""
    return textwrap.dedent(f"""\
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <inttypes.h>

    __attribute__((noinline, annotate("{annotation}")))
    uint32_t obf_target(uint32_t x, uint32_t y) {{
        /* widen into i64 domain */
        uint64_t ux = (((uint64_t)x) << 32) | (uint64_t)y;
        uint64_t uy = (((uint64_t)y) << 32) | (uint64_t)x;
        uy |= 1ULL; /* avoid division by zero */

        /* 64-bit load/store + ptrtoint64 (deterministic) */
        uint64_t buf[4];
        buf[0] = ux + 0x123456789ABCDEF0ULL;
        buf[1] = uy ^ 0x0F0F0F0F0F0F0F0FULL;
        buf[2] = buf[0] + buf[1];
        buf[3] = buf[0] ^ buf[1];
        uint64_t *p = &buf[(x ^ y) & 3u];
        uint64_t v  = *p;              /* OP_LOAD64 */
        *p = v + 1ULL;                 /* OP_STORE64 */

        /* ptrtoint64 but stable across runs: offset into buf */
        uintptr_t pi = (uintptr_t)((uint8_t*)p - (uint8_t*)buf);

        /* signed + unsigned div/rem (OP_BINOP includes SDiv/UDiv/SRem/URem) */
        int64_t sx = (int64_t)((int32_t)x) - 123;
        int64_t sy = (int64_t)((int32_t)y) + 7;
        if (sy == 0) sy = 1;
        int64_t sdiv = sx / sy;
        int64_t srem = sx % sy;
        uint64_t udiv = ux / uy;
        uint64_t urem = ux % uy;

        /* select */
        uint64_t sel = (x & 1u) ? (uint64_t)sdiv : udiv;

        /* cast64 paths */
        int32_t  t32  = (int32_t)(sel ^ (uint64_t)pi);
        int64_t  sext = (int64_t)t32;           /* OP_CAST64 (sext) */
        uint32_t u32  = (uint32_t)(sel + v);
        uint64_t zext = (uint64_t)u32;          /* OP_CAST64 (zext) */
        uint64_t mix  = (uint64_t)sext + zext + (uint64_t)(uint32_t)srem;

        /* switch */
        uint64_t out;
        switch ((unsigned)(mix & 7u)) {{
            case 0: out = sel + (uint64_t)srem; break;
            case 1: out = sel ^ urem; break;
            case 2: out = (sel << 5) | (sel >> 3); break;
            case 3: out = sel - (uint64_t)pi; break;
            case 4: out = sel + v; break;
            default: out = sel ^ mix; break;
        }}

        return (uint32_t)(out ^ (out >> 32));
    }}

    int main(int argc, char** argv) {{
        uint32_t x = (argc > 1) ? (uint32_t)strtoul(argv[1], 0, 0) : 123u;
        uint32_t y = (argc > 2) ? (uint32_t)strtoul(argv[2], 0, 0) : 456u;
        uint32_t r = obf_target(x, y);
        printf("R=%u\\n", r);
        return (int)(r & 0xFFu);
    }}
    """)
# ─────────────────────────────────────────────────────────────────────────────
#  strenc-specific render functions
#
#  Key design: all functions are named "obf_target" so that:
#    • dump-config validation finds "OBF-CONFIG-FN obf_target" as usual
#    • count_fn_instructions("obf_target") works normally
#    • the per-seed seed_determinism/divergence IR comparison is correct
#
#  Correctness oracle: exit code 0 (strcmp == 0 ↔ decryption correct).
#  No x/y argument pairs are needed — strings are compile-time constants.
# ─────────────────────────────────────────────────────────────────────────────

# Secrets: long enough for minlen=4, no '%' (pass skips format strings)
_STRENC_SECRET_A = "OBF_RUNTIME_SECRET_2026"
_STRENC_SECRET_B = "STRENC_ALPHA_BRAVO_2026"
_STRENC_SECRET_C = "CIPHER_VERIFICATION_KEY"
_STRENC_SHORT    = "hi"   # 2 bytes — must stay plaintext under minlen=4


def render_strenc_basic(annotation: str) -> str:
    """Single encrypted string; exit 0 iff strcmp succeeds after decryption."""
    s = _STRENC_SECRET_A
    return textwrap.dedent(f"""\
    #include <string.h>
    #include <stdio.h>
    #include <stdlib.h>

    __attribute__((noinline, annotate("{annotation}")))
    int obf_target(int unused_x, int unused_y) {{
        const char *msg = "{s}";
        return strcmp(msg, "{s}");
    }}

    int main(int argc, char **argv) {{
        int r = obf_target(0, 0);
        if (r != 0) printf("FAIL strenc basic\\n");
        return r;
    }}
    """)


def render_strenc_multi(annotation: str) -> str:
    """Multiple encrypted strings in one annotated function."""
    a, b, c = _STRENC_SECRET_A, _STRENC_SECRET_B, _STRENC_SECRET_C
    return textwrap.dedent(f"""\
    #include <string.h>
    #include <stdio.h>
    #include <stdlib.h>

    __attribute__((noinline, annotate("{annotation}")))
    int obf_target(int unused_x, int unused_y) {{
        int r = 0;
        r |= strcmp("{a}", "{a}");
        r |= strcmp("{b}", "{b}");
        r |= strcmp("{c}", "{c}");
        return r;
    }}

    int main(int argc, char **argv) {{
        int r = obf_target(0, 0);
        if (r != 0) printf("FAIL strenc multi\\n");
        return r;
    }}
    """)


def render_strenc_minlen(annotation: str) -> str:
    """Short string (below minlen=4) must stay plaintext; long string encrypted."""
    short = _STRENC_SHORT    # "hi" — 2 chars, below minlen=4
    long_ = _STRENC_SECRET_A
    return textwrap.dedent(f"""\
    #include <string.h>
    #include <stdio.h>
    #include <stdlib.h>

    __attribute__((noinline, annotate("{annotation}")))
    int obf_target(int unused_x, int unused_y) {{
        int r = 0;
        r |= strcmp("{short}", "{short}");   /* too short: stays plaintext */
        r |= strcmp("{long_}", "{long_}");   /* encrypted + decrypted      */
        return r;
    }}

    int main(int argc, char **argv) {{
        int r = obf_target(0, 0);
        if (r != 0) printf("FAIL strenc minlen\\n");
        return r;
    }}
    """)


def render_strenc_xor_fallback(annotation: str) -> str:
    """Legacy XOR path (aes=0); must still decrypt correctly."""
    s = "XOR_FALLBACK_SECRET_2026"
    return textwrap.dedent(f"""\
    #include <string.h>
    #include <stdio.h>
    #include <stdlib.h>

    __attribute__((noinline, annotate("{annotation}")))
    int obf_target(int unused_x, int unused_y) {{
        return strcmp("{s}", "{s}");
    }}

    int main(int argc, char **argv) {{
        int r = obf_target(0, 0);
        if (r != 0) printf("FAIL strenc xor\\n");
        return r;
    }}
    """)


def render_aes_stub_obfuscated(annotation: str) -> str:
    """strenc + MBA + BCF: AES stub gets obfuscated, runtime must still work."""
    s = "STUB_OBFUSCATION_VERIFY_2026"
    return textwrap.dedent(f"""\
    #include <string.h>
    #include <stdio.h>
    #include <stdlib.h>

    __attribute__((noinline, annotate("{annotation}")))
    int obf_target(int unused_x, int unused_y) {{
        return strcmp("{s}", "{s}");
    }}

    int main(int argc, char **argv) {{
        int r = obf_target(0, 0);
        if (r != 0) printf("FAIL strenc stub_obf\\n");
        return r;
    }}
    """)


def render_aes_stub_passes(annotation: str) -> str:
    """aes_stub(...): stub functions obfuscated via dedicated sub-annotation."""
    s = "STUB_PASSES_VERIFY_2026"
    return textwrap.dedent(f"""\
    #include <string.h>
    #include <stdio.h>
    #include <stdlib.h>

    __attribute__((noinline, annotate("{annotation}")))
    int obf_target(int unused_x, int unused_y) {{
        return strcmp("{s}", "{s}");
    }}

    int main(int argc, char **argv) {{
        int r = obf_target(0, 0);
        if (r != 0) printf("FAIL strenc stub_passes\\n");
        return r;
    }}
    """)


# ─────────────────────────────────────────────────────────────────────────────
#  strenc IR gate functions
# ─────────────────────────────────────────────────────────────────────────────

def gate_strenc_no_plaintext(obf_ir: str) -> Optional[str]:
    """Secret strings must NOT appear as plaintext in the obfuscated IR."""
    for s in (_STRENC_SECRET_A, _STRENC_SECRET_B, _STRENC_SECRET_C):
        if s in obf_ir:
            return (f"plaintext secret found in obfuscated IR: {s!r} "
                    f"— encryption may have been skipped")
    return None


def gate_strenc_decrypt_present(obf_ir: str) -> Optional[str]:
    """AES decrypt stub must be linked into the module."""
    if "__aes_decrypt" not in obf_ir:
        return "__aes_decrypt not found in obfuscated IR — stub not linked"
    return None


def gate_strenc_key_providers(obf_ir: str) -> Optional[str]:
    """Both key-provider functions must be present (key-split active)."""
    missing = [fn for fn in ("__aes_key_a", "__aes_key_b")
               if fn not in obf_ir]
    if missing:
        return f"key-provider(s) missing from IR: {', '.join(missing)}"
    return None


def gate_strenc_keysplit_sections(obf_ir: str) -> Optional[str]:
    """Key-split section markers must appear in the IR."""
    missing = [sec for sec in (".strenc.kd", ".strenc.kt")
               if sec not in obf_ir]
    if missing:
        return f"key-split section(s) missing from IR: {', '.join(missing)}"
    return None


def gate_strenc_short_plaintext(obf_ir: str) -> Optional[str]:
    """Short string below minlen must survive as plaintext in the IR."""
    s = _STRENC_SHORT  # "hi"
    # LLVM IR spells string literals as: c"hi\00"  or  c"hi"
    if f'c"{s}\\00"' in obf_ir or f'c"{s}"' in obf_ir or s in obf_ir:
        return None
    return (f"short string {s!r} not found as plaintext in IR "
            f"— may have been incorrectly encrypted")


def gate_aes_stub_grew(obf_ir: str) -> Optional[str]:
    """__strenc_decrypt must have more than the bare-minimum block count,
    indicating that at least one obfuscation pass (e.g. BCF/flattening) ran
    on the stub and added basic blocks to it."""
    # Count define lines for __strenc_decrypt — then count its basic-block
    # labels by scanning the IR text between 'define' and the next top-level
    # closing brace.  A naive but reliable approach: count label lines
    # (lines ending with ':') inside the function body.
    fn_body = _extract_fn_body(obf_ir, "__aes_decrypt")
    if fn_body is None:
        return "__aes_decrypt not found — cannot check stub growth"
    bb_count = sum(1 for line in fn_body.splitlines()
                   if re.match(r"^\s*\w[\w.]*\s*:", line))
    if bb_count <= 1:
        return (f"__aes_decrypt has only {bb_count} basic block(s) — "
                f"stub obfuscation passes appear not to have run")
    return None


def gate_aes_stub_no_plaintext_key(obf_ir: str) -> Optional[str]:
    """After stub obfuscation, key-provider immediates should still appear
    (stores in __strenc_key_b) but the decrypt logic should have grown/changed.
    This is a light structural check: verify __strenc_key_b is defined (not
    just declared) and has at least one store instruction."""
    fn_body = _extract_fn_body(obf_ir, "__aes_key_b")
    if fn_body is None:
        return "__aes_key_b body not found in IR — function not defined"
    if "store" not in fn_body:
        return "__strenc_key_b has no store instructions — key bytes missing"
    return None


# ─────────────────────────────────────────────────────────────────────────────
#  VM Pass v7 gate functions
# ─────────────────────────────────────────────────────────────────────────────

def gate_vm_dispatch_present(ir: str) -> Optional[str]:
    """vm.dispatch block must exist."""
    if not re.search(r"vm\.dispatch\b", ir):
        return "vm.dispatch block not found — virtualisation did not run"
    return None

def gate_vm_entry_present(ir: str) -> Optional[str]:
    """vm.entry block must exist (interpreter entry point)."""
    if not re.search(r"vm\.entry\b", ir):
        return "vm.entry block not found"
    return None

def gate_vm_bytecode_global(ir: str) -> Optional[str]:
    """@fn.vm.bytecode global must be emitted."""
    if not re.search(r"vm\.bytecode\b", ir):
        return "no vm.bytecode global found — BytecodeEmitter did not run"
    return None

def gate_vm_ophandlers_global(ir: str) -> Optional[str]:
    """@fn.vm.ophandlers global (18-entry dispatch table) must exist."""
    if not re.search(r"vm\.ophandlers\b", ir):
        return "no vm.ophandlers global found"
    return None

def gate_vm_indirectbr(ir: str) -> Optional[str]:
    """The interpreter must use indirectbr for opcode dispatch."""
    if "indirectbr" not in ir:
        return "no indirectbr found — opcode dispatch is not indirect"
    return None

def gate_vm_regs_alloca(ir: str) -> Optional[str]:
    """vm.regs alloca must be present (integer virtual register file)."""
    if not re.search(r"vm\.regs\b", ir):
        return "vm.regs alloca not found"
    return None

def gate_vm_no_original_blocks(ir: str) -> Optional[str]:
    """No original user-named basic blocks should survive; only vm.* names."""
    # Look for label lines that are not vm.*, not entry, not alloca
    labels = re.findall(r"^(\w[\w.]*):$", ir, re.MULTILINE)
    bad = [l for l in labels if not l.startswith("vm.") and l not in ("entry",)]
    if bad:
        return f"original blocks still present: {bad[:4]}"
    return None

def gate_vm_opc_blocks(ir: str) -> Optional[str]:
    """All base ISA opcode handler blocks must be present (Step 01/02 extended)."""
    expected = ["loadi","movr","binop","icmp","cast","ptrtoint","inttoptr",
                "load32","store32","gep","jmp","jmpc",
                "ret_void","ret_int","ret_ptr",
                "call_void","call_int","call_ptr",
                # Step 01.1/01.3: float register file handlers
                 "loadi_f","movr_f","binop_f","fcmp",
                "fcast_ff","fcast_fv","fcast_fv64","fcast_vf","fcast_v64f",
                "load_f","store_f","ret_f","select_f","fneg",
                "load_f32","store_f32",
                # Step 02: extended call ABI
                "call_int64","call_f",
                ]
    missing = [n for n in expected if not re.search(r"vm\.opc\." + n + r"\b", ir)]
    if missing:
        return f"missing opcode handler blocks: {missing}"
    return None

def gate_vm_bytecode_nonempty(ir: str) -> Optional[str]:
    """@fn.vm.bytecode must have at least one element."""
    m = re.search(r"vm\.bytecode[^[]*\[(\d+)\s*x\s*i8\]", ir)
    if not m:
        return "vm.bytecode global not found or malformed"
    size = int(m.group(1))
    if size == 0:
        return "vm.bytecode has 0 bytes — bytecode emitter produced nothing"
    return None

def gate_vm_pregs_alloca(ir: str) -> Optional[str]:
    """vm.pregs alloca must be present (pointer virtual register file)."""
    if not re.search(r"vm\.pregs\b", ir):
        return "vm.pregs alloca not found — ptr register file not allocated"
    return None

def gate_vm_salt_volatile(ir: str) -> Optional[str]:
    """vm.salt loads must be volatile (prevents optimizer from seeing through)."""
    if not re.search(r"load volatile.*vm\.salt|volatile.*load.*vm\.salt", ir):
        if "vm.salt" not in ir:
            return "vm.salt alloca not found"
        return "vm.salt load is not volatile"
    return None

def gate_vm_enc_ctor(ir: str) -> Optional[str]:
    """encBytecode=1 must emit a .init_array constructor."""
    # AES path: vm.ctor.aes block; LCG path: ctor.loop block
    if not (re.search(r"vm\.ctor\.aes\b", ir) or re.search(r"ctor\.loop\b", ir)):
        return "encryption constructor not found (neither AES nor LCG path)"
    return None



def gate_vm_aes_ctor(ir: str) -> Optional[str]:
    """useAES=1 (default) must emit the AES-CTR constructor path."""
    if not re.search(r"vm\.ctor\.aes\b", ir):
        return "vm.ctor.aes block not found — AES ctor not built"
    return None


def gate_vm_aes_no_lcg_constants(ir: str) -> Optional[str]:
    """When useAES=1, the LCG constants must NOT appear in VM output."""
    # LCG_A = 6364136223846793005  LCG_C = 1442695040888963407
    for c in ("6364136223846793005", "1442695040888963407"):
        if c in ir:
            return f"LCG constant {c} found in IR — useAES should have replaced LCG"
    return None


def gate_vm_aes_globals(ir: str) -> Optional[str]:
    """useAES=1 must emit per-function AES globals."""
    if not re.search(r"vm\.aes\.rk\b", ir):
        return "vm.aes.rk global not found — AES expanded key not emitted"
    if not re.search(r"vm\.aes\.nonce\b", ir):
        return "vm.aes.nonce global not found — AES nonce not emitted"
    return None


def gate_vm_obf_aes_ctr_present(ir: str) -> Optional[str]:
    """__obf_aes_ctr_decrypt must be linked into the module."""
    if "__obf_aes_ctr_decrypt" not in ir:
        return "__obf_aes_ctr_decrypt not found — AES stub not linked"
    return None



def gate_vm_no_enc_ctor(ir: str) -> Optional[str]:
    """encBytecode=0 must NOT emit a ctor (ctor.loop should be absent)."""
    if re.search(r"ctor\.loop\b", ir) or re.search(r"vm\.ctor\.aes\b", ir):
        return "encryption ctor found but encBytecode=0"
    return None

def gate_vm_callees_global(ir: str) -> Optional[str]:
    """When calls are present, @fn.vm.callees must be emitted."""
    if not re.search(r"vm\.callees\b", ir):
        return "vm.callees global not found (required for call virtualisation)"
    return None


def gate_vm_fregs_alloca(ir: str) -> Optional[str]:
    """vm.fregs alloca must be present (float virtual register file)."""
    if not re.search(r"vm\.fregs\b", ir):
        return "vm.fregs alloca not found — float register file not allocated"
    return None


# ── Step 04: Hardened handler verification gates ─────────────────────

def gate_vm_hardened_mba(ir: str) -> Optional[str]:
    """hardened=1 must produce MBA patterns in __vm_engine handler blocks."""
    engine = _extract_fn_body(ir, "__vm_engine")
    if engine is None:
        return "__vm_engine not found"
    # MBA substitutions produce characteristic patterns: mba.or, mba.and, mba.xor etc
    mba_names = len(re.findall(r"mba\.", engine))
    if mba_names < 10:
        return f"too few MBA-named values in __vm_engine ({mba_names}, need >=10)"
    return None


def gate_vm_hardened_dead_blocks(ir: str) -> Optional[str]:
    """hardened=1 must produce dead code blocks in __vm_engine."""
    engine = _extract_fn_body(ir, "__vm_engine")
    if engine is None:
        return "__vm_engine not found"
    dead = len(re.findall(r"vm\.dead\.\d+:", engine))
    if dead < 3:
        return f"too few dead code blocks ({dead}, need >=3)"
    return None


def gate_vm_hardened_dispatch_guard(ir: str) -> Optional[str]:
    """hardened=1 must have a pre-dispatch opaque predicate block."""
    engine = _extract_fn_body(ir, "__vm_engine")
    if engine is None:
        return "__vm_engine not found"
    if "vm.predisp:" not in engine:
        return "vm.predisp block not found — dispatch not guarded"
    return None


def gate_vm_hardened_handler_guards(ir: str) -> Optional[str]:
    """hardened=1 must have at least 1 handler entry guard."""
    engine = _extract_fn_body(ir, "__vm_engine")
    if engine is None:
        return "__vm_engine not found"
    guards = len(re.findall(r"vm\.opc\.[\w.]+\.guard:", engine))
    if guards < 1:
        return f"no handler entry guards found (need >=1)"
    return None


# —— Step 05: Register Value Encryption at Rest gates ————————————

def gate_vm_regenc_key_alloca(ir: str) -> Optional[str]:
    """regEnc=1 must allocate per-function key arrays in the wrapper."""
    # Key allocas are in the wrapper (not __vm_engine) — search full IR
    if not re.search(r"vm\.regkeys\b", ir):
        return "vm.regkeys alloca not found — i32 register key array missing"
    if not re.search(r"vm\.reg64keys\b", ir):
        return "vm.reg64keys alloca not found — i64 register key array missing"
    return None


def gate_vm_regenc_key_loads(ir: str) -> Optional[str]:
    """regEnc=1 must load per-slot XOR keys in __vm_engine handlers."""
    engine = _extract_fn_body(ir, "__vm_engine")
    if engine is None:
        return "__vm_engine not found"
     # Key load names survive MBA rewriting (MBA only rewrites arithmetic, not loads)
    rk32 = len(re.findall(r"vm\.rk\.v", engine))
    rk64 = len(re.findall(r"vm\.rk64\.v", engine))
    total = rk32 + rk64
    if total < 4:
        return f"too few register key loads in __vm_engine ({total}, need >=4)"
    return None


def gate_vm_regenc_key_geps(ir: str) -> Optional[str]:
    """regEnc=1 must GEP into key arrays in __vm_engine handlers."""
    engine = _extract_fn_body(ir, "__vm_engine")
    if engine is None:
        return "__vm_engine not found"
    rk_gep = len(re.findall(r"vm\.rk\.p", engine))
    rk64_gep = len(re.findall(r"vm\.rk64\.p", engine))
    total = rk_gep + rk64_gep
    if total < 4:
        return f"too few register key GEPs in __vm_engine ({total}, need >=4)"
    return None


def gate_vm_regenc_pregs_exempt(ir: str) -> Optional[str]:
    """regEnc=1 must NOT XOR-encrypt pointer registers (vm.pg.dec / vm.pg.enc must be absent)."""
    engine = _extract_fn_body(ir, "__vm_engine")
    if engine is None:
        return "__vm_engine not found"
    pr_dec = len(re.findall(r"vm\.pg\.dec\b", engine))
    pr_enc = len(re.findall(r"vm\.pg\.enc\b", engine))
    if pr_dec > 0 or pr_enc > 0:
        return f"pointer registers must NOT be encrypted (found pr.dec={pr_dec}, pr.enc={pr_enc})"
    return None


def gate_vm_regenc_freg_key(ir: str) -> Optional[str]:
    """regEnc=1 must allocate a float register key array in the wrapper."""
    if not re.search(r"vm\.fregkeys\b", ir):
        return "vm.fregkeys alloca not found — float register key array missing"
    return None


# ── Step 06: Shared vm_engine gates ──────────────────────────────────

def gate_vm_engine_exists(ir: str) -> Optional[str]:
    """@__vm_engine function must exist in module (Step 06)."""
    if "define internal void @__vm_engine(" not in ir:
        return "@__vm_engine function not found — shared engine not created"
    return None


def gate_vm_engine_singleton(ir: str) -> Optional[str]:
    """Only ONE @__vm_engine must exist (not duplicated per function)."""
    count = ir.count("define internal void @__vm_engine(")
    if count == 0:
        return "@__vm_engine not found"
    if count != 1:
        return f"expected 1 __vm_engine definition, found {count}"
    return None


def gate_vm_wrapper_calls_engine(ir: str) -> Optional[str]:
    """Virtualised function must call __vm_engine (directly or indirectly).

    Step 06b.1 replaces the direct call with an indirect call through a
    decoded handler-table pointer.  We accept both patterns:
      - 'call void @__vm_engine('          (direct -- legacy / should not appear)
      - 'call void %vm.eng.ptr(' or similar (indirect, via XOR-decoded ptr)
    """
    fn = _extract_fn_body(ir, "obf_target")
    if fn is None:
        return "obf_target function not found"
    has_direct   = "call void @__vm_engine(" in fn
    # Indirect call pattern: 'call void %<ssa_name>(' where name is an SSA reg
    has_indirect = bool(re.search(r"call void %[\w.]+\(", fn))
    if not has_direct and not has_indirect:
        return "obf_target does not call __vm_engine (direct or indirect) -- wrapper not generated"
    return None


def gate_vm_wrapper_is_thin(ir: str) -> Optional[str]:
    """Wrapper should NOT contain handler blocks (they belong in __vm_engine)."""
    fn = _extract_fn_body(ir, "obf_target")
    if fn is None:
        return "obf_target function not found"
    handler_labels = re.findall(r"^vm\.opc\.\w+:", fn, re.MULTILINE)
    if handler_labels:
        return f"obf_target contains handler blocks: {handler_labels[:4]}"
    if "indirectbr" in fn:
        return "obf_target contains indirectbr — should only be in __vm_engine"
    return None


def gate_vm_engine_has_handlers(ir: str) -> Optional[str]:
    """__vm_engine must contain the core opcode handler blocks."""
    engine = _extract_fn_body(ir, "__vm_engine")
    if engine is None:
        return "__vm_engine function body not found"
    expected = ["loadi", "movr", "binop", "icmp", "cast", "ptrtoint", "inttoptr",
                "load32", "store32", "gep", "jmp", "jmpc",
                "ret_void", "ret_int", "ret_ptr",
                "call_void", "call_int", "call_ptr"]
    missing = [n for n in expected if not re.search(r"vm\.opc\." + n + r"\b", engine)]
    if missing:
        return f"__vm_engine missing handler blocks: {missing}"
    return None


def gate_vm_engine_indirectbr(ir: str) -> Optional[str]:
    """__vm_engine must use indirectbr for opcode dispatch."""
    engine = _extract_fn_body(ir, "__vm_engine")
    if engine is None:
        return "__vm_engine function body not found"
    if "indirectbr" not in engine:
        return "__vm_engine has no indirectbr — dispatch not indirect"
    return None


def gate_vm_engine_dispatch(ir: str) -> Optional[str]:
    """__vm_engine must contain vm.dispatch block."""
    engine = _extract_fn_body(ir, "__vm_engine")
    if engine is None:
        return "__vm_engine function body not found"
    if not re.search(r"vm\.dispatch\b", engine):
        return "vm.dispatch not found in __vm_engine"
    return None


def gate_vm_multi_fn_shared(ir: str) -> Optional[str]:
    """Multiple virtualised functions must share the same __vm_engine."""
    handler_globals = re.findall(r"@\w+\.vm\.ophandlers\b", ir)
    engine_refs = ir.count("blockaddress(@__vm_engine,")
    if len(handler_globals) < 2:
        return f"expected 2+ per-function handler tables, found {len(handler_globals)}"
    if engine_refs < 2:
        return f"expected blockaddress(@__vm_engine) in multiple tables, found {engine_refs} refs"
    defcount = ir.count("define internal void @__vm_engine(")
    if defcount != 1:
        return f"expected 1 __vm_engine definition, found {defcount}"
    return None


def gate_vm_handlers_permuted(ir: str) -> Optional[str]:
    """Two per-function handler tables must have different opcode permutations."""
     # The global has TWO bracketed parts: [51 x ptr] (type) and [...] (initializer).
    # We need the second bracket — skip the type with [^[]*\[[^\]]*\]\s*
    tables = re.findall(
        r"@(\w+)\.vm\.ophandlers\s*=[^[]*\[[^\]]*\]\s*\[([^\]]+)\]",
        ir,
    )
    if len(tables) < 2:
        return None  # not a multi-function test
    entries_a = [x.strip() for x in tables[0][1].split(",")]
    entries_b = [x.strip() for x in tables[1][1].split(",")]
    if entries_a == entries_b:
        return f"handler tables for {tables[0][0]} and {tables[1][0]} identical"
    return None




def _extract_fn_body(ir: str, fn_name: str) -> Optional[str]:
    """Return the text between 'define ... @fn_name' and its closing '}',
    or None if not found.  Handles the function not being defined (declare)."""
    # Match 'define' lines that contain @fn_name (not 'declare')
    pattern = re.compile(
        r"^define\b[^\n]*@" + re.escape(fn_name) + r"\b[^\n]*\{",
        re.MULTILINE,
    )
    m = pattern.search(ir)
    if not m:
        return None
    start = m.end()
    depth = 1
    i = start
    while i < len(ir) and depth:
        if ir[i] == '{':
            depth += 1
        elif ir[i] == '}':
            depth -= 1
        i += 1
    return ir[start:i - 1]


# ═════════════════════════════════════════════════════════════════════════════
#  Compile / Run Helpers
# ═════════════════════════════════════════════════════════════════════════════

def clang_for_lang(tools: Tools, is_cpp: bool) -> Path:
    """Select clang/clang++ for compilation and linking.

    Notes:
      • On Windows, clang.exe/clang-cl.exe can compile C++ as well, so we keep it.
      • On Unix, prefer clang++ if available (same bin dir as clang).
    """
    if not is_cpp:
        return tools.clang

    if platform.system() == "Windows":
        return tools.clang

    clang = tools.clang
    name = clang.name
    if name.startswith("clang-cl"):
        return clang

    cands: list[Path] = []
    if name.startswith("clang-"):
        cands.append(clang.with_name(name.replace("clang-", "clang++-", 1)))
    cands.append(clang.with_name(name.replace("clang", "clang++", 1)))

    for c in cands:
        if c.exists():
            return c
    return clang  # fallback


def compile_src_to_ll(tools: Tools, src: Path, out: Path, *, is_cpp: bool, v: bool = False) -> None:
    compiler = clang_for_lang(tools, is_cpp)
    extra = ["-std=c++17"] if is_cpp else []
    run_cmd([
        str(compiler),
        "-O0",
        "-Xclang", "-disable-O0-optnone",
        "-fno-discard-value-names",
        "-ffp-contract=off",
        "-S", "-emit-llvm",
        *extra,
        str(src),
        "-o", str(out),
    ], verbose=v)


def compile_ll_to_exe(tools: Tools, ll: Path, exe: Path, opt: str, *, is_cpp: bool, v: bool = False) -> None:
    compiler = clang_for_lang(tools, is_cpp)
    extra = ["-std=c++17"] if is_cpp else []
    run_cmd([str(compiler), f"-{opt}", *extra, str(ll), "-o", str(exe)], verbose=v)


def run_obfuscation(
    tools: Tools, base: Path, out: Path, seed: int,
    extra: list[str] | None = None, v: bool = False,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        str(tools.opt),
        "-passes=obfuscation",
        f"-obf-seed={seed}",
        "-obf-verify",
        "-S", str(base),
        "-o", str(out),
    ]
    if extra:
        cmd.extend(extra)
    return run_cmd(cmd, verbose=v, capture=True)


def run_dump_config(
    tools: Tools, base: Path, seed: int,
    extra: list[str] | None = None, v: bool = False,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        str(tools.opt),
        "-disable-output",
        "-passes=obf-dump-config",
        f"-obf-seed={seed}",
        str(base),
    ]
    if extra:
        cmd.extend(extra)
    return run_cmd(cmd, verbose=v, capture=True)


def parse_dump_config_for_fn(
    dump_stdout: str, fn_name: str
) -> tuple[list[str], list[str], Dict[str, Dict[str, str]]]:
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
        kv: Dict[str, str] = {}
        for tok in rest.split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                kv[k] = v
        params[pid] = kv

    return enabled, ordered, params


def run_o2(tools: Tools, src: Path, out: Path, v: bool = False) -> None:
    run_cmd([str(tools.opt), "-passes=default<O2>", "-S", str(src), "-o", str(out)], verbose=v)


def run_metrics(tools: Tools, ll: Path, func: str) -> dict:
    cp = run_cmd([
        str(tools.opt),
        "-disable-output",
        "-passes=obf-metrics",
        f"-obf-metrics-function={func}",
        str(ll),
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
               for op in ("add", "sub", "xor", "and", "or", "shl", "lshr"))
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
        "asm":      ("asm sideeffect" in ir and (".byte" in ir or ".4byte" in ir or "b 1f" in ir)),
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
        for i, (la, lb) in enumerate(zip(ir_a.splitlines(), ir_b.splitlines()), 1):
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
    # Set to True for tests where the annotated function is ineligible for
    # obfuscation (e.g. EH/invoke), so obf-dump-config will not emit an
    # OBF-CONFIG-FN block — the missing-block check should be suppressed.
    no_config_check: bool     = False
    src_override: Optional[str] = None


def make_tests(*, extended: bool, exhaustive_combos: bool, combo_max_size: int) -> list[TestCase]:
    T = TestCase
    out: list[T] = []

    # ── Individual Pass Correctness ───────────────────────────────────
    for p in PASSES:
        out.append(T(name=f"rt_{p}", passes=[p], category="pass"))

    # ── Combos ────────────────────────────────────────────────────────
    out.append(T(name="rt_combo_all", passes=PASSES[:], category="pass"))
    out.append(T(
        name="rt_kitchen_sink",
        passes=ALL_PASSES_WITH_ADEC[:],
        ann_override=ann_extra("kitchen_sink"),
        # expect_enabled must match the kitchen_sink annotation exactly.
        # The annotation omits vm (vm conflicts with flattening) and uses an
        # explicit vcall entry, so pin the list here rather than deriving it
        # from tc.passes (which includes all of ALL_PASSES_WITH_ADEC).
        expect_enabled=["mba", "substitution", "vcall", "split", "bcf",
                        "sdiff", "flattening", "shield", "strenc", "adec"],
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

    # ── C++ & Exception Handling ──────────────────────────────────────
    # EH functions have invoke/landingpad instructions that make them
    # ineligible for most obfuscation passes.  obf-dump-config will not
    # emit an OBF-CONFIG-FN block for them, so skip the config check.
    out.append(T(
        name="rt_cpp_eh_basic",
        passes=["flattening", "mba"],
        no_config_check=True,
        category="cpp",
    ))
    out.append(T(
        name="rt_cpp_eh_full",
        passes=ALL_PASSES_WITH_ADEC[:],
        ann_override=ann_extra("kitchen_sink"),
        no_config_check=True,
        category="cpp",
    ))

    # ── Big Functions / Complex Logic ─────────────────────────────────
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

    # ── VM Pass v7 ───────────────────────────────────────────────────────
    VM_CORE_GATES = [
        "vm_dispatch_present", "vm_entry_present", "vm_bytecode_global",
        "vm_ophandlers_global", "vm_indirectbr", "vm_regs_alloca",
        "vm_pregs_alloca", "vm_no_original_blocks", "vm_opc_blocks",
        "vm_bytecode_nonempty",
    ]

    # Step 06: gates that verify the shared vm_engine architecture
    VM_ENGINE_GATES = [
        "vm_engine_exists", "vm_engine_singleton",
        "vm_wrapper_calls_engine", "vm_wrapper_is_thin",
        "vm_engine_has_handlers", "vm_engine_indirectbr",
        "vm_engine_dispatch",
    ]

    # Combined: all VM tests should check both wrapper + engine structure
    VM_SHARED_GATES = VM_CORE_GATES + VM_ENGINE_GATES

    # AES-specific gates (useAES=1 is default when encBytecode=1)
    VM_AES_GATES = [
        "vm_aes_ctor", "vm_aes_globals",
        "vm_obf_aes_ctr_present", "vm_aes_no_lcg_constants",
    ]



        # Step 01.3: float register file gate (added to tests that exercise fregs)
    VM_FLOAT_GATES = VM_CORE_GATES + ["vm_fregs_alloca", "vm_enc_ctor"]

    # Step 05: register value encryption gates
    VM_REGENC_GATES = [
        "vm_regenc_key_alloca", "vm_regenc_key_loads",
        "vm_regenc_key_geps", "vm_regenc_pregs_exempt",
    ]

    def render_vm_v7_float_basic_program(annotation: str) -> str:
        """VM Step 01: basic float/double arithmetic — FAdd/FSub/FMul/FDiv/FRem."""
        return textwrap.dedent(f"""\
        #include <stdint.h>
        #include <stdio.h>
        #include <stdlib.h>
        #include <math.h>

        __attribute__((noinline, annotate("{annotation}")))
        uint32_t obf_target(uint32_t x, uint32_t y) {{
            float  fx = (float)x * 0.001f;
            float  fy = (float)y * 0.001f + 1.0f;   /* avoid div-by-zero */
            double dx = (double)x * 0.000001;
            double dy = (double)y * 0.000001 + 1.0;

            /* OP_BINOP_F: FAdd/FSub/FMul/FDiv/FRem */
            float  a = fx + fy;
            float  b = fx - fy;
            float  c = fx * fy;
            float  d = fx / fy;
            float  e = fmodf(fx + 1.0f, fy);

            double da = dx + dy;
            double db = dx * dy;
            double dc = dx / dy;
            double dd = fmod(dx + 1.0, dy);

            /* Mix results deterministically */
            double r = (double)(a + b + c + d + e) + da + db + dc + dd;
            /* Collapse to u32 via bitwise fingerprint */
            uint32_t bits;
            __builtin_memcpy(&bits, &r, 4);
            return bits ^ x ^ y;
        }}

        int main(int argc, char** argv) {{
            uint32_t x = (argc > 1) ? (uint32_t)strtoul(argv[1], 0, 0) : 1234u;
            uint32_t y = (argc > 2) ? (uint32_t)strtoul(argv[2], 0, 0) : 5678u;
            uint32_t r = obf_target(x, y);
            printf("R=%u\\n", r);
            return (int)(r & 0xFF);
        }}
        """)


    def render_vm_v7_float_cast_program(annotation: str) -> str:
        """VM Step 01: float/double cast opcodes — FPExt, FPTrunc, FPToSI/UI, SIToFP/UIToFP."""
        return textwrap.dedent(f"""\
        #include <stdint.h>
        #include <stdio.h>
        #include <stdlib.h>

        __attribute__((noinline, annotate("{annotation}")))
        uint32_t obf_target(uint32_t x, uint32_t y) {{
            /* SIToFP / UIToFP  (OP_FCAST: FK_SITOFP, FK_UITOFP, FK_SI64TOFP, FK_UI64TOFP) */
            int32_t  si = (int32_t)x - 50000;
            uint32_t ui = y;
            int64_t  si64 = (int64_t)si * 1000LL;
            uint64_t ui64 = (uint64_t)ui * 2ULL;

            double fa = (double)si;
            double fb = (double)ui;
            double fc = (double)si64;
            double fd = (double)ui64;

            /* FPExt / FPTrunc  (OP_FCAST: FK_FPEXT, FK_FPTRUNC) */
            float   flt = (float)fa;           /* fptrunc */
            double  ext = (double)flt;         /* fpext   */

            /* FPToSI / FPToUI  (OP_FCAST: FK_FPTOSI, FK_FPTOUI, FK_FPTOSI64, FK_FPTOUI64) */
            int32_t  back_si   = (int32_t)(fa + 0.5);
            uint32_t back_ui   = (uint32_t)(fb + 0.5);
            int64_t  back_si64 = (int64_t)(fc * 0.001 + 0.5);
            uint64_t back_ui64 = (uint64_t)(fd * 0.5  + 0.5);

            uint64_t mix = (uint64_t)((uint32_t)back_si ^ back_ui)
                        ^ (uint64_t)(back_si64 ^ (int64_t)back_ui64);
            mix ^= *(uint64_t*)&ext;           /* use ext to keep fpext alive */
            mix ^= (uint64_t)fa + (uint64_t)fb;
            return (uint32_t)(mix ^ (mix >> 32));
        }}

        int main(int argc, char** argv) {{
            uint32_t x = (argc > 1) ? (uint32_t)strtoul(argv[1], 0, 0) : 77777u;
            uint32_t y = (argc > 2) ? (uint32_t)strtoul(argv[2], 0, 0) : 33333u;
            uint32_t r = obf_target(x, y);
            printf("R=%u\\n", r);
            return (int)(r & 0xFF);
        }}
        """)


    def render_vm_v7_float_fcmp_program(annotation: str) -> str:
        """VM Step 01: float comparisons — FCmp ordered and unordered predicates."""
        return textwrap.dedent(f"""\
        #include <stdint.h>
        #include <stdio.h>
        #include <stdlib.h>
        #include <math.h>

        __attribute__((noinline, annotate("{annotation}")))
        uint32_t obf_target(uint32_t x, uint32_t y) {{
            double a = (double)(int32_t)x;
            double b = (double)(int32_t)y;

            /* FCmp ordered predicates (OP_FCMP) */
            uint32_t r = 0;
            if (a == b)  r |= 1u;
            if (a != b)  r |= 2u;
            if (a <  b)  r |= 4u;
            if (a <= b)  r |= 8u;
            if (a >  b)  r |= 16u;
            if (a >= b)  r |= 32u;

            /* Unordered: use NaN to exercise UNO/ORD paths at runtime */
            double nan_val = (x == 0 && y == 0) ? (0.0/0.0) : a;
            if (!isnan(nan_val) && nan_val < b)  r |= 64u;
            if ( isnan(nan_val) || nan_val > b)  r |= 128u;

            /* OP_SELECT_F: conditional select between two doubles */
            double sel = (x > y) ? a * 2.0 : b + 1.0;
            uint32_t sel_bits;
            __builtin_memcpy(&sel_bits, &sel, 4);

            return r ^ x ^ y ^ sel_bits;
        }}

        int main(int argc, char** argv) {{
            uint32_t x = (argc > 1) ? (uint32_t)strtoul(argv[1], 0, 0) : 100u;
            uint32_t y = (argc > 2) ? (uint32_t)strtoul(argv[2], 0, 0) : 200u;
            uint32_t r = obf_target(x, y);
            printf("R=%u\\n", r);
            return (int)(r & 0xFF);
        }}
        """)


    def render_vm_v7_float_mem_program(annotation: str) -> str:
        return textwrap.dedent(f"""\
        #include <stdint.h>
        #include <stdio.h>
        #include <stdlib.h>

        __attribute__((noinline, annotate("{annotation}")))
        uint32_t obf_target(uint32_t x, uint32_t y) {{
            double buf[4];
            buf[0] = (double)x;
            buf[1] = (double)y;
            buf[2] = buf[0] * 1.5 + 0.5;
            buf[3] = buf[1] * 2.0 - 1.0;

            double sum     = buf[0] + buf[1] + buf[2] + buf[3];
            double idx_val = buf[(x ^ y) & 3u];

            /* Union reinterpret avoids llvm.memcpy intrinsic */
            union {{ double d; uint64_t u; }} cs = {{sum}}, ci = {{idx_val}};
            uint64_t r64 = cs.u ^ ci.u ^ (uint64_t)x ^ ((uint64_t)y << 32);
            return (uint32_t)(r64 ^ (r64 >> 32));
        }}

        int main(int argc, char** argv) {{
            uint32_t x = (argc > 1) ? (uint32_t)strtoul(argv[1], 0, 0) : 42u;
            uint32_t y = (argc > 2) ? (uint32_t)strtoul(argv[2], 0, 0) : 99u;
            uint32_t r = obf_target(x, y);
            printf("R=%u\\n", r);
            return (int)(r & 0xFF);
        }}
        """)


    def render_vm_v7_float_ret_program(annotation: str) -> str:
        """VM Step 01: functions returning float/double — OP_RET_F."""
        return textwrap.dedent(f"""\
        #include <stdint.h>
        #include <stdio.h>
        #include <stdlib.h>

        /* Returns double; forces OP_RET_F in the VM bytecode */
        __attribute__((noinline, annotate("{annotation}")))
        double obf_target(uint32_t x, uint32_t y) {{
            double a = (double)x * 3.14159265358979;
            double b = (double)y * 2.71828182845904;
            double c = a + b;
            if (x & 1u) c = a * b;
            if (y & 1u) c -= a;
            return c;
        }}

        int main(int argc, char** argv) {{
            uint32_t x = (argc > 1) ? (uint32_t)strtoul(argv[1], 0, 0) : 7u;
            uint32_t y = (argc > 2) ? (uint32_t)strtoul(argv[2], 0, 0) : 13u;
            double r = obf_target(x, y);
            /* Deterministic integer fingerprint of the double */
            uint64_t bits;
            __builtin_memcpy(&bits, &r, 8);
            printf("R=%llu\\n", (unsigned long long)bits);
            return (int)(bits & 0xFF);
        }}
        """)


    def render_vm_v7_call_i64_args_program(annotation: str) -> str:
        """VM Step 02: call ABI v2 — i64 arguments passed via vreg64."""
        return textwrap.dedent(f"""\
        #include <stdint.h>
        #include <stdio.h>
        #include <stdlib.h>

        static __attribute__((noinline))
        uint64_t helper64(uint64_t a, uint64_t b, uint32_t c) {{
            return (a ^ b) + (uint64_t)c * 0xDEADBEEFULL;
        }}

        __attribute__((noinline, annotate("{annotation}")))
        uint32_t obf_target(uint32_t x, uint32_t y) {{
            uint64_t a = ((uint64_t)x << 32) | (uint64_t)y;
            uint64_t b = ((uint64_t)y << 32) | (uint64_t)x;
            /* OP_CALL_INT (but args include i64) — exercises CAT_VREG64 in ArgTypes */
            uint64_t r = helper64(a, b, x ^ y);
            return (uint32_t)(r ^ (r >> 32));
        }}

        int main(int argc, char** argv) {{
            uint32_t x = (argc > 1) ? (uint32_t)strtoul(argv[1], 0, 0) : 0xCAFEu;
            uint32_t y = (argc > 2) ? (uint32_t)strtoul(argv[2], 0, 0) : 0xBABEu;
            uint32_t r = obf_target(x, y);
            printf("R=%u\\n", r);
            return (int)(r & 0xFF);
        }}
        """)


    def render_vm_v7_call_vararg_program(annotation: str) -> str:
        """VM Step 02: vararg call — isVarArg=1 in call ABI encoding (CF_VARARG)."""
        return textwrap.dedent(f"""\
        #include <stdint.h>
        #include <stdio.h>
        #include <stdlib.h>
        #include <stdarg.h>

        /* A simple vararg helper to force OP_CALL_VOID with CF_VARARG */
        static __attribute__((noinline))
        uint32_t vadd(int n, ...) {{
            va_list ap;
            va_start(ap, n);
            uint32_t sum = 0;
            for (int i = 0; i < n; i++) sum += (uint32_t)va_arg(ap, int);
            va_end(ap);
            return sum;
        }}

        __attribute__((noinline, annotate("{annotation}")))
        uint32_t obf_target(uint32_t x, uint32_t y) {{
            /* Forces vararg call emission in bytecode */
            uint32_t a = vadd(3, (int)x, (int)y, (int)(x ^ y));
            uint32_t b = vadd(2, (int)(x + y), (int)(x * y & 0xFFFF));
            return a ^ b ^ (x << 1) ^ (y >> 1);
        }}

        int main(int argc, char** argv) {{
            uint32_t x = (argc > 1) ? (uint32_t)strtoul(argv[1], 0, 0) : 111u;
            uint32_t y = (argc > 2) ? (uint32_t)strtoul(argv[2], 0, 0) : 222u;
            uint32_t r = obf_target(x, y);
            printf("R=%u\\n", r);
            return (int)(r & 0xFF);
        }}
        """)


    def render_vm_v7_call_i64_ret_program(annotation: str) -> str:
        """VM Step 02: call returning i64 — OP_CALL_INT64."""
        return textwrap.dedent(f"""\
        #include <stdint.h>
        #include <stdio.h>
        #include <stdlib.h>

        static __attribute__((noinline))
        uint64_t compute64(uint32_t x, uint32_t y) {{
            return ((uint64_t)x * 0x100000001ULL) ^ ((uint64_t)y << 17) ^ 0xFEDCBA9876543210ULL;
        }}

        __attribute__((noinline, annotate("{annotation}")))
        uint32_t obf_target(uint32_t x, uint32_t y) {{
            /* OP_CALL_INT64: callee returns i64, stored into vreg64 */
            uint64_t r = compute64(x, y);
            uint64_t s = compute64(y, x);
            uint64_t t = r ^ s ^ ((uint64_t)x << 32 | y);
            return (uint32_t)(t ^ (t >> 32));
        }}

        int main(int argc, char** argv) {{
            uint32_t x = (argc > 1) ? (uint32_t)strtoul(argv[1], 0, 0) : 0xABCDu;
            uint32_t y = (argc > 2) ? (uint32_t)strtoul(argv[2], 0, 0) : 0x1234u;
            uint32_t r = obf_target(x, y);
            printf("R=%u\\n", r);
            return (int)(r & 0xFF);
        }}
        """)


    def render_vm_v7_float_comprehensive_program(annotation: str) -> str:
        """VM Step 01+02: comprehensive float test combining arithmetic, casts, fcmp,
        memory, select, i64 interaction, and float-returning function."""
        return textwrap.dedent(f"""\
        #include <stdint.h>
        #include <stdio.h>
        #include <stdlib.h>
        #include <math.h>

        static __attribute__((noinline))
        double scalar_op(double a, double b, int mode) {{
            switch (mode & 3) {{
            case 0: return a + b;
            case 1: return a - b;
            case 2: return a * b;
            default: return (b != 0.0) ? a / b : a;
            }}
        }}

        __attribute__((noinline, annotate("{annotation}")))
        uint32_t obf_target(uint32_t x, uint32_t y) {{
            /* OP_FCAST: int->float conversions */
            double dx = (double)(int32_t)x;
            double dy = (double)(int32_t)y;
            float  fx = (float)dx;   /* FPTrunc */
            double ex = (double)fx;  /* FPExt */

            /* OP_BINOP_F */
            double s  = dx + dy;
            double p  = dx * dy;
            double d  = (dy != 0.0) ? dx / dy : dx;
            double rm = fmod(dx + 1.0, dy + 1.0);

            /* OP_FCMP + OP_SELECT_F */
            double big = (dx > dy) ? s : p;
            double sml = (dx < dy) ? d : rm;

            /* OP_LOAD_F / OP_STORE_F via stack buffer */
            double buf[4] = {{ s, p, d, rm }};
            buf[(x & 3u)] = big + sml;
            double loaded = buf[(y & 3u)];

            /* OP_FCAST: float->int */
            int32_t  si  = (int32_t)(loaded + 0.5);
            double abs_loaded = loaded >= 0.0 ? loaded : -loaded;
            uint32_t ui = (uint32_t)(abs_loaded + 0.5);
            int64_t  si64 = (int64_t)(s * 1000.0 + 0.5);

            /* Call returning double (exercises OP_CALL_F in Step 02 context) */
            double cr = scalar_op(dx, dy, (int)(x ^ y));

            /* OP_FCAST: double->int64 */
            int64_t cr64 = (int64_t)(cr * 100.0 + 0.5);

            /* Fold everything to u32 */
            uint64_t acc = (uint64_t)(uint32_t)si ^ (uint64_t)ui
                        ^ (uint64_t)(uint32_t)si64 ^ (uint64_t)(uint32_t)cr64;
            union {{ float f; uint32_t u; }} ce = {{(float)ex}};
            uint32_t ex_bits = ce.u;
            return (uint32_t)(acc ^ (acc >> 32)) ^ x ^ y ^ ex_bits;
        }}

        int main(int argc, char** argv) {{
            uint32_t x = (argc > 1) ? (uint32_t)strtoul(argv[1], 0, 0) : 31416u;
            uint32_t y = (argc > 2) ? (uint32_t)strtoul(argv[2], 0, 0) : 27182u;
            uint32_t r = obf_target(x, y);
            printf("R=%u\\n", r);
            return (int)(r & 0xFF);
        }}
        """)

    out.append(T(
        name="rt_vm_v7_basic",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        gates=VM_CORE_GATES + ["vm_enc_ctor"],
        extra_opts=["--obf-debug", "--obf-verbose"],
        category="vm",
    ))
    out.append(T(
        name="rt_vm_v7_bare",
        passes=["vm"],
        ann_override=ann_extra("vm_v7_bare"),
        gates=VM_CORE_GATES + ["vm_no_enc_ctor"],
        extra_opts=["--obf-debug", "--obf-verbose"],
        category="vm",
    ))
    out.append(T(
        name="rt_vm_v7_obfidx",
        passes=["vm"],
        ann_override=ann_extra("vm_v7_obfidx"),
        gates=VM_CORE_GATES + ["vm_no_enc_ctor"],
        extra_opts=["--obf-debug", "--obf-verbose"],
        category="vm",
    ))
    out.append(T(
        name="rt_vm_v7_enc",
        passes=["vm"],
        ann_override=ann_extra("vm_v7_enc"),
        gates=VM_CORE_GATES + ["vm_enc_ctor"],
        extra_opts=["--obf-debug", "--obf-verbose"],
        category="vm",
    ))
    out.append(T(
        name="rt_vm_v7_determinism",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        extra_opts=["--obf-debug", "--obf-verbose"],
        gates=["seed_determinism"],
        category="vm",
    ))
    
    out.append(T(
        name="rt_vm_v7_divergence",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        extra_opts=["--obf-debug", "--obf-verbose"],
        gates=["seed_divergence"],
        category="vm",
    ))
    
    out.append(T(
        name="rt_vm_v7_memory",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        gates=VM_CORE_GATES + ["vm_enc_ctor"],
        extra_opts=["--obf-debug", "--obf-verbose"],
        category="vm",
        src_override=render_vm_v7_memory_program(ann_extra("vm_v7")),
    ))
    out.append(T(
        name="rt_vm_v7_gep_chain",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        gates=VM_CORE_GATES + ["vm_enc_ctor"],
        extra_opts=["--obf-debug", "--obf-verbose"],
        category="vm",
        src_override=render_vm_v7_gep_chain_program(ann_extra("vm_v7")),
    ))
    out.append(T(
        name="rt_vm_v7_call",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        gates=VM_CORE_GATES + ["vm_enc_ctor", "vm_callees_global"],
        extra_opts=["--obf-debug", "--obf-verbose"],
        category="vm",
        src_override=render_vm_v7_call_program(ann_extra("vm_v7")),
    ))
    out.append(T(
        name="rt_vm_v7_casts",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        gates=VM_CORE_GATES + ["vm_enc_ctor"],
        extra_opts=["--obf-debug", "--obf-verbose"],
        category="vm",
        src_override=render_vm_v7_casts_program(ann_extra("vm_v7")),
    ))
    out.append(T(
        name="rt_vm_v7_icmp",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        gates=VM_CORE_GATES + ["vm_enc_ctor"],
        extra_opts=["--obf-debug", "--obf-verbose"],
        category="vm",
        src_override=render_vm_v7_icmp_program(ann_extra("vm_v7")),
    ))
    out.append(T(
        name="rt_vm_v7_multiblock",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        gates=VM_CORE_GATES + ["vm_enc_ctor"],
        extra_opts=["--obf-debug", "--obf-verbose"],
        category="vm",
        src_override=render_vm_v7_multiblock_program(ann_extra("vm_v7")),
    ))

    out.append(T(
        name="rt_vm_v7_i64_ops",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        extra_opts=["--obf-debug", "--obf-verbose"],
        gates=VM_CORE_GATES + ["vm_enc_ctor"],
        category="vm",
        src_override=render_vm_v7_i64_ops_program(ann_extra("vm_v7")),
    ))

    # ── strenc: AES-128-CTR string encryption ─────────────────────────
    # These tests use render_strenc_* functions, which all name the annotated
    # function "obf_target" — so dump-config, IR instruction counting, and
    # seed determinism/divergence all work identically to other categories.
    # Correctness oracle: exit code 0 (strcmp == 0 ↔ decryption succeeded).

    _aes_ann  = "obf: strenc(minlen=4,aes=1,keysplit=1)"
    _xor_ann  = "obf: strenc(minlen=4,aes=0)"
    _stub_ann = ("obf: strenc(minlen=4,aes=1,keysplit=1), "
                 "mba(prob=80,depth=2,maxSites=150), "
                 "bcf(prob=60,loop=1)")

    # aes_stub sub-annotation variants — each exercises a different
    # combination of passes applied to the linked AES stub functions.
    # The stub secret is distinct from other strenc secrets so the
    # gate_strenc_no_plaintext check correctly scopes to this test.
    _stub_passes_mba_bcf = (
        "obf: strenc(minlen=4,aes=1,keysplit=1), "
        "aes_stub(mba(prob=80,depth=2,maxSites=150),bcf(prob=60,loop=1))"
    )
    _stub_passes_fla = (
        "obf: strenc(minlen=4,aes=1,keysplit=1), "
        "aes_stub(flattening(minBlocks=2,maxBlocks=100))"
    )
    _stub_passes_sub = (
        "obf: strenc(minlen=4,aes=1,keysplit=1), "
        "aes_stub(substitution(loop=1))"
    )
    _stub_passes_full = (
        "obf: strenc(minlen=4,aes=1,keysplit=1), "
        "aes_stub(mba(prob=80,depth=2,maxSites=100),"
        "bcf(prob=60,loop=1),"
        "substitution(loop=1))"
    )


    # ── Step 01.3: float register file tests ──────────────────────────────────
    out.append(T(
        name="rt_vm_v7_float_basic",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        gates=VM_FLOAT_GATES,
        category="vm",
        src_override=render_vm_v7_float_basic_program(ann_extra("vm_v7")),
    ))

    out.append(T(
        name="rt_vm_v7_float_cast",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        gates=VM_FLOAT_GATES,
        category="vm",
        src_override=render_vm_v7_float_cast_program(ann_extra("vm_v7")),
    ))

    out.append(T(
        name="rt_vm_v7_float_fcmp_select",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        gates=VM_FLOAT_GATES,
        category="vm",
        src_override=render_vm_v7_float_fcmp_program(ann_extra("vm_v7")),
    ))

    out.append(T(
        name="rt_vm_v7_float_mem",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        gates=VM_FLOAT_GATES,
        category="vm",
        src_override=render_vm_v7_float_mem_program(ann_extra("vm_v7")),
    ))

    out.append(T(
        name="rt_vm_v7_float_ret",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        gates=VM_FLOAT_GATES,
        category="vm",
        src_override=render_vm_v7_float_ret_program(ann_extra("vm_v7")),
    ))

    out.append(T(
        name="rt_vm_v7_float_comprehensive",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        gates=VM_FLOAT_GATES + ["vm_callees_global"],
        category="vm",
        src_override=render_vm_v7_float_comprehensive_program(ann_extra("vm_v7")),
    ))

    # ── Step 02: extended call ABI tests ─────────────────────────────────────
    out.append(T(
        name="rt_vm_v7_call_i64_args",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        gates=VM_CORE_GATES + ["vm_enc_ctor", "vm_callees_global"],
        category="vm",
        src_override=render_vm_v7_call_i64_args_program(ann_extra("vm_v7")),
    ))

    out.append(T(
        name="rt_vm_v7_call_vararg",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        gates=VM_CORE_GATES + ["vm_enc_ctor", "vm_callees_global"],
        category="vm",
        src_override=render_vm_v7_call_vararg_program(ann_extra("vm_v7")),
    ))

    out.append(T(
        name="rt_vm_v7_call_i64_ret",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        gates=VM_CORE_GATES + ["vm_enc_ctor", "vm_callees_global"],
        category="vm",
        src_override=render_vm_v7_call_i64_ret_program(ann_extra("vm_v7")),
    ))


    # ── Step 06: Shared vm_engine architecture tests ────────────────────

    def render_vm_v7_multi_function_program(annotation: str) -> str:
        """Step 06: Multiple VM-annotated functions sharing one __vm_engine."""
        return textwrap.dedent(f"""\
        #include <stdint.h>
        #include <stdio.h>
        #include <stdlib.h>

        __attribute__((noinline, annotate("{annotation}")))
        uint32_t obf_fn1(uint32_t x, uint32_t y) {{
            uint32_t r = x;
            for (uint32_t i = 0; i < (y & 0xF); i++)
                r = r * 31u + i;
            return r ^ y;
        }}

        __attribute__((noinline, annotate("{annotation}")))
        uint32_t obf_fn2(uint32_t a, uint32_t b) {{
            uint32_t s = a + b;
            if (s > 1000u) s = s - 500u;
            else           s = s * 3u;
            return s ^ (a << 2) ^ (b >> 1);
        }}

        /* obf_target calls both — exercises inter-function callee table */
        __attribute__((noinline, annotate("{annotation}")))
        uint32_t obf_target(uint32_t x, uint32_t y) {{
            return obf_fn1(x, y) + obf_fn2(y, x);
        }}

        int main(int argc, char** argv) {{
            uint32_t x = (argc > 1) ? (uint32_t)atoi(argv[1]) : 42;
            uint32_t y = (argc > 2) ? (uint32_t)atoi(argv[2]) : 17;
            printf("%u\\n", obf_target(x, y));
            return 0;
        }}
        """)

    out.append(T(
        name="rt_vm_v7_multi_function",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        gates=VM_SHARED_GATES + ["vm_enc_ctor", "vm_callees_global",
               "vm_multi_fn_shared", "vm_handlers_permuted"],
        category="vm",
        src_override=render_vm_v7_multi_function_program(ann_extra("vm_v7")),
    ))

    # ── Step 06: Shared engine structure verification (single function) ──

    out.append(T(
        name="rt_vm_v7_shared_engine_basic",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        gates=VM_SHARED_GATES + ["vm_enc_ctor"],
        category="vm",
    ))

    # ── Step 03+06: AES-128-CTR encryption with shared engine ────────

    out.append(T(
        name="rt_vm_v7_aes_ctr",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        gates=VM_SHARED_GATES + VM_AES_GATES + ["vm_enc_ctor"],
        category="vm",
    ))

    # Verify AES is NOT used when encBytecode=0
    out.append(T(
        name="rt_vm_v7_no_enc_no_aes",
        passes=["vm"],
        ann_override=ann_extra("vm_v7_bare"),
        gates=VM_ENGINE_GATES + [
            "vm_entry_present", "vm_bytecode_global",
            "vm_ophandlers_global", "vm_bytecode_nonempty",
            "vm_no_enc_ctor",
        ],
        category="vm",
    ))

    # ── Step 06: Multi-function with AES (stress test) ───────────────

    def render_vm_v7_multi_fn_aes_program(annotation: str) -> str:
        """Step 06 + Step 03: multiple VM functions with AES encryption."""
        return textwrap.dedent(f"""\
        #include <stdint.h>
        #include <stdio.h>
        #include <stdlib.h>

        __attribute__((noinline, annotate("{annotation}")))
        uint32_t obf_a(uint32_t x) {{
            return (x ^ 0xDEADBEEFu) * 7u + 3u;
        }}

        __attribute__((noinline, annotate("{annotation}")))
        uint32_t obf_b(uint32_t x) {{
            return (x ^ 0xCAFEBABEu) * 11u - 5u;
        }}

        __attribute__((noinline, annotate("{annotation}")))
        uint32_t obf_target(uint32_t x, uint32_t y) {{
            return obf_a(x) ^ obf_b(y);
        }}

        int main(int argc, char** argv) {{
            uint32_t x = (argc > 1) ? (uint32_t)atoi(argv[1]) : 99;
            uint32_t y = (argc > 2) ? (uint32_t)atoi(argv[2]) : 77;
            printf("%u\\n", obf_target(x, y));
            return 0;
        }}
        """)

    out.append(T(
        name="rt_vm_v7_multi_fn_aes",
        passes=["vm"],
        ann_override=ann_extra("vm_v7"),
        gates=VM_SHARED_GATES + VM_AES_GATES + [
            "vm_enc_ctor", "vm_callees_global",
            "vm_multi_fn_shared", "vm_engine_singleton",
        ],
        category="vm",
        src_override=render_vm_v7_multi_fn_aes_program(ann_extra("vm_v7")),
    ))


    # ── Step 04: Hardened gate test ──────────────────────────────────
    out.append(T(
        name="rt_vm_v7_hardened",
        passes=["vm"],
        ann_override=ann_extra("vm_v7_hardened"),
                gates=VM_CORE_GATES + ["vm_enc_ctor",
               "vm_hardened_mba", "vm_hardened_dead_blocks",
               "vm_hardened_dispatch_guard", "vm_hardened_handler_guards"],
        extra_opts=["--obf-debug", "--obf-verbose"],
        category="vm",
    ))

    # —— Step 05: Register Value Encryption at Rest ————————————————

    out.append(T(
        name="rt_vm_v7_regenc",
        passes=["vm"],
        ann_override=ann_extra("vm_v7_regenc"),
        gates=VM_CORE_GATES + VM_REGENC_GATES + ["vm_enc_ctor"],
        extra_opts=["--obf-debug", "--obf-verbose"],
        category="vm",
    ))

    out.append(T(
        name="rt_vm_v7_regenc_float",
        passes=["vm"],
        ann_override=ann_extra("vm_v7_regenc"),
        gates=VM_FLOAT_GATES + VM_REGENC_GATES + ["vm_regenc_freg_key"],
        category="vm",
        src_override=render_vm_v7_float_basic_program(ann_extra("vm_v7_regenc")),
    ))

    out.append(T(
        name="rt_vm_v7_regenc_i64",
        passes=["vm"],
        ann_override=ann_extra("vm_v7_regenc"),
        gates=VM_CORE_GATES + VM_REGENC_GATES + ["vm_enc_ctor", "vm_callees_global"],
        category="vm",
        src_override=render_vm_v7_call_i64_args_program(ann_extra("vm_v7_regenc")),
    ))

    out.append(T(
        name="rt_vm_v7_regenc_multi_fn",
        passes=["vm"],
        ann_override=ann_extra("vm_v7_regenc"),
        gates=VM_SHARED_GATES + VM_REGENC_GATES + [
            "vm_enc_ctor", "vm_callees_global",
            "vm_multi_fn_shared",
        ],
        category="vm",
        src_override=render_vm_v7_multi_function_program(ann_extra("vm_v7_regenc")),
    ))

    out.append(T(
        name="rt_vm_v7_regenc_hardened",
        passes=["vm"],
        ann_override=ann_extra("vm_v7_regenc_hardened"),
        gates=VM_CORE_GATES + VM_REGENC_GATES + [
            "vm_enc_ctor",
            "vm_hardened_mba", "vm_hardened_dead_blocks",
            "vm_hardened_dispatch_guard", "vm_hardened_handler_guards",
        ],
        extra_opts=["--obf-debug", "--obf-verbose"],
        category="vm",
    ))

    out.append(T(
        name="rt_vm_v7_regenc_seed_determinism",
        passes=["vm"],
        ann_override=ann_extra("vm_v7_regenc"),
        gates=["seed_determinism"],
        category="vm",
    ))

    out.append(T(
        name="rt_vm_v7_regenc_seed_divergence",
        passes=["vm"],
        ann_override=ann_extra("vm_v7_regenc"),
        gates=["seed_divergence"],
        category="vm",
    ))


    out.append(T(
        name="strenc_aes_basic",
        passes=["strenc"],
        ann_override=_aes_ann,
        gates=["strenc_no_plaintext", "strenc_decrypt_present",
               "strenc_key_providers", "strenc_keysplit_sections"],
        category="strenc",
    ))
    out.append(T(
        name="strenc_aes_multi",
        passes=["strenc"],
        ann_override=_aes_ann,
        gates=["strenc_no_plaintext", "strenc_decrypt_present"],
        category="strenc",
    ))
    out.append(T(
        name="strenc_aes_minlen",
        passes=["strenc"],
        ann_override=_aes_ann,
        gates=["strenc_decrypt_present", "strenc_short_plaintext"],
        category="strenc",
    ))
    out.append(T(
        name="strenc_aes_keysplit",
        passes=["strenc"],
        ann_override=_aes_ann,
        gates=["strenc_no_plaintext", "strenc_decrypt_present",
               "strenc_key_providers", "strenc_keysplit_sections"],
        category="strenc",
    ))
    out.append(T(
        name="strenc_aes_keysplit_off",
        passes=["strenc"],
        ann_override="obf: strenc(minlen=4,aes=1,keysplit=0)",
        gates=["strenc_no_plaintext", "strenc_decrypt_present"],
        category="strenc",
    ))
    out.append(T(
        name="strenc_xor_fallback",
        passes=["strenc"],
        ann_override=_xor_ann,
        gates=[],   # XOR path has no __strenc_decrypt
        category="strenc",
    ))
    out.append(T(
        name="aes_stub_obfuscated",
        passes=["strenc", "mba", "bcf"],
        ann_override=_stub_ann,
        gates=["strenc_no_plaintext", "strenc_decrypt_present"],
        category="strenc",
    ))
    out.append(T(
        name="strenc_seed_determinism",
        passes=["strenc"],
        ann_override=_aes_ann,
        gates=["seed_determinism"],
        category="strenc",
    ))
    out.append(T(
        name="strenc_seed_divergence",
        passes=["strenc"],
        ann_override=_aes_ann,
        gates=["seed_divergence"],
        category="strenc",
    ))

    # ── aes_stub: dedicated stub obfuscation via aes_stub(...) ──────
    # These tests verify that the aes_stub(passes...) sub-annotation
    # correctly routes obfuscation passes onto __strenc_decrypt and the
    # key-provider functions after they are linked into the module.
    #
    # Gates checked on top of the standard AES gates:
    #   aes_stub_grew            — __strenc_decrypt has >1 basic block
    #   aes_stub_no_plaintext_key — __strenc_key_b has store instructions
    #
    # Correctness oracle: exit code 0 (strcmp succeeds after decrypt).
    out.append(T(
        name="aes_stub_passes_mba_bcf",
        passes=["strenc"],
        ann_override=_stub_passes_mba_bcf,
        expect_enabled=["strenc", "aes_stub"],
        gates=["strenc_no_plaintext", "strenc_decrypt_present",
               "strenc_key_providers", "strenc_keysplit_sections",
               "aes_stub_grew", "aes_stub_no_plaintext_key"],
        category="strenc",
    ))
    out.append(T(
        name="aes_stub_passes_fla",
        passes=["strenc"],
        ann_override=_stub_passes_fla,
        expect_enabled=["strenc", "aes_stub"],
        gates=["strenc_no_plaintext", "strenc_decrypt_present",
               "aes_stub_grew"],
        category="strenc",
    ))
    out.append(T(
        name="aes_stub_passes_sub",
        passes=["strenc"],
        ann_override=_stub_passes_sub,
        expect_enabled=["strenc", "aes_stub"],
        gates=["strenc_no_plaintext", "strenc_decrypt_present",
               "strenc_key_providers", "strenc_keysplit_sections"],
        category="strenc",
    ))
    out.append(T(
        name="aes_stub_passes_full",
        passes=["strenc"],
        ann_override=_stub_passes_full,
        expect_enabled=["strenc", "aes_stub"],
        gates=["strenc_no_plaintext", "strenc_decrypt_present",
               "strenc_key_providers", "strenc_keysplit_sections",
               "aes_stub_grew", "aes_stub_no_plaintext_key"],
        category="strenc",
    ))

    # ── Extended suite: option sweeps, alias tests, matrices ──────────
    if extended:
        # Each supported option gets at least one explicit config test.
        OPTION_SWEEPS: Dict[str, list[tuple[str, Dict[str, Any]]]] = {
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
                ("min1",         {"minlen": 1}),
                ("min4",         {"minlen": 4}),
                ("min100",       {"minlen": 100}),
                ("aes_on",       {"minlen": 4, "aes": 1}),
                ("aes_off",      {"minlen": 4, "aes": 0}),
                ("keysplit_on",  {"minlen": 4, "aes": 1, "keysplit": 1}),
                ("keysplit_off", {"minlen": 4, "aes": 1, "keysplit": 0}),
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
                ("min2max200", {"minBlocks": 2, "maxBlocks": 200}),
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

        # Aliases (must normalize)
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
        # NOTE: hyphenated pass IDs are not accepted by the current annotation parser (\\w+),
        # so use the supported alias.
        out.append(T(
            name="opt_alias_antidecompiler",
            passes=["adec"],
            ann_override=ann_specs([pass_spec("antidecompiler", {"prob": 100, "strength": 2, "maxSites": 50})]),
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

        # Pipeline recommended order
        out.append(T(
            name="meta_order_full_pipeline",
            passes=["flattening", "bcf", "sdiff", "split", "vcall", "substitution", "mba", "shield", "adec", "strenc"],
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
                "strenc(minlen=4,aes=1,keysplit=1)",
            ]),
            # recommended order per ObfuscationPipeline::getRecommendedOrder
            expect_order=["mba", "substitution", "vcall", "split", "sdiff", "bcf", "flattening", "shield", "strenc", "adec"],
            category="meta",
        ))

        # Pairwise Combination Matrix (stress configs)
        STRESS: Dict[str, str] = {
            "mba": "mba(prob=100,depth=4,maxSites=400,termsMin=12,termsMax=20,enableNonLinear=1,nonLinearWeight=70,enableLayered=1,layeredBudget=4,layeredWindow=72)",
            "substitution": "substitution(loop=2,maxSites=2000)",
            "vcall": "vcall(prob=90,maxSites=300,opaqueVTableNames=1,addDecoyEntries=1,decoyMin=1,decoyMax=4,varyIndex=1,indexStrength=2,merge=1)",
            "split": "split(num=5)",
            "sdiff": "sdiff(prob=80,slots=3,maxSites=80)",
            "bcf": "bcf(prob=90,loop=2,maxBlocks=500)",
            "flattening": "flattening(minBlocks=2,maxBlocks=500,allowIndirect=1,hybrid=1,opaqueState=1,fakeTransitions=1,fakeCases=4,domain=1,ptr=1,alias=1)",
            "shield": "shield(maxSites=200,volatile=1,identity=1,dse=1,cfg=1)",
            "strenc": "strenc(minlen=4,aes=1,keysplit=1)",
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

    # ── Exhaustive combinations of enabled passes (bounded) ────────────
    if exhaustive_combos:
        all_passes = PASSES + ["adec"]
        max_k = max(1, combo_max_size)

        # Skip k=1 because those are already covered by rt_<pass>.
        for k in range(2, max_k + 1):
            for subset in itertools.combinations(all_passes, k):
                subset_list = list(subset)
                name = "exh_" + "_".join(subset_list)
                out.append(T(
                    name=name,
                    passes=subset_list,
                    category="exhaustive",
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
    if key == "mba_advanced":             return gate_mba_advanced(obf_ir)
    if key == "opaque_families":          return gate_opaque_families(obf_ir)
    if key == "adec_patterns":            return gate_adec_patterns(obf_ir)
    if key == "adec_type_confusion":      return gate_adec_type_confusion(obf_ir)
    if key == "adec_indirectbr":          return gate_adec_indirectbr(obf_ir)
    if key == "budget_verbose":           return gate_budget_verbose(stderr_text)
    if key == "budget_exhaustion":        return gate_budget_exhaustion(stderr_text)
    if key == "seed_determinism":         return gate_seed_determinism(ir_a, ir_b)
    if key == "seed_divergence":          return gate_seed_divergence(ir_a, ir_b)

    # VM pass v7 gates
    if key == "vm_dispatch_present":      return gate_vm_dispatch_present(obf_ir)
    if key == "vm_entry_present":         return gate_vm_entry_present(obf_ir)
    if key == "vm_bytecode_global":       return gate_vm_bytecode_global(obf_ir)
    if key == "vm_ophandlers_global":     return gate_vm_ophandlers_global(obf_ir)
    if key == "vm_indirectbr":            return gate_vm_indirectbr(obf_ir)
    if key == "vm_regs_alloca":           return gate_vm_regs_alloca(obf_ir)
    if key == "vm_no_original_blocks":    return gate_vm_no_original_blocks(obf_ir)
    if key == "vm_opc_blocks":            return gate_vm_opc_blocks(obf_ir)
    if key == "vm_bytecode_nonempty":     return gate_vm_bytecode_nonempty(obf_ir)
    if key == "vm_pregs_alloca":          return gate_vm_pregs_alloca(obf_ir)
    if key == "vm_salt_volatile":         return gate_vm_salt_volatile(obf_ir)
    if key == "vm_enc_ctor":              return gate_vm_enc_ctor(obf_ir)
    if key == "vm_no_enc_ctor":           return gate_vm_no_enc_ctor(obf_ir)
    if key == "vm_callees_global":        return gate_vm_callees_global(obf_ir)
    if key == "vm_fregs_alloca":          return gate_vm_fregs_alloca(obf_ir)     # Step 01.3


    if key == "vm_hardened_mba":            return gate_vm_hardened_mba(obf_ir)
    if key == "vm_hardened_dead_blocks":    return gate_vm_hardened_dead_blocks(obf_ir)
    if key == "vm_hardened_dispatch_guard": return gate_vm_hardened_dispatch_guard(obf_ir)
    if key == "vm_hardened_handler_guards": return gate_vm_hardened_handler_guards(obf_ir)

    # Step 05: Register encryption gates
    if key == "vm_regenc_key_alloca":      return gate_vm_regenc_key_alloca(obf_ir)
    if key == "vm_regenc_key_loads":       return gate_vm_regenc_key_loads(obf_ir)
    if key == "vm_regenc_key_geps":        return gate_vm_regenc_key_geps(obf_ir)
    if key == "vm_regenc_pregs_exempt":    return gate_vm_regenc_pregs_exempt(obf_ir)
    if key == "vm_regenc_freg_key":        return gate_vm_regenc_freg_key(obf_ir)

    # Step 06: Shared vm_engine gates
    if key == "vm_engine_exists":          return gate_vm_engine_exists(obf_ir)
    if key == "vm_engine_singleton":       return gate_vm_engine_singleton(obf_ir)
    if key == "vm_wrapper_calls_engine":   return gate_vm_wrapper_calls_engine(obf_ir)
    if key == "vm_wrapper_is_thin":        return gate_vm_wrapper_is_thin(obf_ir)
    if key == "vm_engine_has_handlers":    return gate_vm_engine_has_handlers(obf_ir)
    if key == "vm_engine_indirectbr":      return gate_vm_engine_indirectbr(obf_ir)
    if key == "vm_engine_dispatch":        return gate_vm_engine_dispatch(obf_ir)
    if key == "vm_multi_fn_shared":        return gate_vm_multi_fn_shared(obf_ir)
    if key == "vm_handlers_permuted":      return gate_vm_handlers_permuted(obf_ir)

    # VM AES-CTR gates (Step 03)
    if key == "vm_aes_ctor":               return gate_vm_aes_ctor(obf_ir)
    if key == "vm_aes_no_lcg_constants":   return gate_vm_aes_no_lcg_constants(obf_ir)
    if key == "vm_aes_globals":            return gate_vm_aes_globals(obf_ir)
    if key == "vm_obf_aes_ctr_present":    return gate_vm_obf_aes_ctr_present(obf_ir)

    # strenc AES-CTR gates
    if key == "strenc_no_plaintext":      return gate_strenc_no_plaintext(obf_ir)
    if key == "strenc_decrypt_present":   return gate_strenc_decrypt_present(obf_ir)
    if key == "strenc_key_providers":     return gate_strenc_key_providers(obf_ir)
    if key == "strenc_keysplit_sections": return gate_strenc_keysplit_sections(obf_ir)
    if key == "strenc_short_plaintext":        return gate_strenc_short_plaintext(obf_ir)
    if key == "aes_stub_grew":              return gate_aes_stub_grew(obf_ir)
    if key == "aes_stub_no_plaintext_key":  return gate_aes_stub_no_plaintext_key(obf_ir)
    m = re.match(r"budget_clamped_(\d+)", key)
    if m:
        return gate_budget_clamped(obf_ir, base_ir, int(m.group(1)))
    m = re.match(r"budget_hardcap_(\d+)", key)
    if m:
        return gate_budget_hardcap(obf_ir, int(m.group(1)))
    return f"unknown gate: {key}"


# ═════════════════════════════════════════════════════════════════════════════
#  Dump-config Expectation Checks
# ═════════════════════════════════════════════════════════════════════════════

def _check_dump_expectations(
    tc: TestCase,
    enabled: list[str],
    ordered: list[str],
    params: Dict[str, Dict[str, str]],
) -> Optional[str]:
    exp_enabled = tc.expect_enabled or tc.passes
    if enabled != exp_enabled:
        return f"enabled mismatch: got={enabled} expected={exp_enabled}"

    if tc.expect_order and ordered != tc.expect_order:
        return f"order mismatch: got={ordered} expected={tc.expect_order}"

    if tc.expect_config:
        for pid, exp_kv in tc.expect_config.items():
            if pid not in params:
                return f"missing pass config: {pid}"
            got_kv = params.get(pid, {})
            for k, v in exp_kv.items():
                if k not in got_kv:
                    return f"pass {pid} missing key {k} (expected {k}={v})"
                if got_kv[k] != v:
                    return f"pass {pid} key {k} mismatch: got={got_kv[k]} expected={v}"
    return None


# ═════════════════════════════════════════════════════════════════════════════
#  Test Runner
# ═════════════════════════════════════════════════════════════════════════════

def run_test(
    tc: TestCase, tools: Tools, work: Path,
    seeds: list[int], inputs: list[tuple[int, int]],
    o2_gate: bool, no_metrics: bool, no_gates: bool, verbose: bool,
    report_enabled: bool, report_root: Path, report_html: bool, report_tool: Optional[Path],
    config_check: bool,
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

    # Decide program kind.
    is_cpp = (tc.category == "cpp") or ("_cpp" in tc.name) or ("_eh" in tc.name)
    ext = ".cpp" if is_cpp else ".c"

    # strenc tests use self-contained render functions.  All of them name the
    # annotated function "obf_target" so dump-config, count_fn_instructions,
    # and seed determinism/divergence all work exactly as for other tests.
    if tc.src_override:
        src_text = tc.src_override
    elif "eh" in tc.name:
        src_text = render_cpp_eh_program(ann)
    elif "complex" in tc.name:
        src_text = render_complex_logic_program(ann)
    elif tc.category == "strenc":
        if "multi" in tc.name:
            src_text = render_strenc_multi(ann)
        elif "minlen" in tc.name:
            src_text = render_strenc_minlen(ann)
        elif "xor" in tc.name:
            src_text = render_strenc_xor_fallback(ann)
        elif "stub_obf" in tc.name:
            src_text = render_aes_stub_obfuscated(ann)
        elif "stub_passes" in tc.name:
            src_text = render_aes_stub_passes(ann)
        else:
            src_text = render_strenc_basic(ann)
    else:
        src_text = render_program(ann, want_strenc=("strenc" in tc.passes))

    src_file = tdir / f"test{ext}"
    write_text(src_file, src_text)

    # Compile source → IR
    base_ll = tdir / "base.ll"
    try:
        compile_src_to_ll(tools, src_file, base_ll, is_cpp=is_cpp, v=verbose)
    except Exception as e:
        res.status = "FAIL"
        res.reason = f"clang→ll: {e}"
        res.elapsed = time.monotonic() - t0
        return res

    base_ir = read_text(base_ll)
    res.base_insts = count_fn_instructions(base_ir, "obf_target") or count_all_instructions(base_ir)

    # Validate dump-config expectations (always checks enabled list; optional key/value checks).
    if config_check and not tc.no_config_check:
        try:
            seed_cfg = seeds[0] if seeds else 1
            cp = run_dump_config(tools, base_ll, seed_cfg, tc.extra_opts or None, v=verbose)
            enabled, ordered, params = parse_dump_config_for_fn(cp.stdout, "obf_target")
            if not enabled and "OBF-CONFIG-FN obf_target" not in cp.stdout:
                res.status = "FAIL"
                res.reason = "dump-config: missing OBF-CONFIG-FN obf_target block"
                res.elapsed = time.monotonic() - t0
                return res

            why = _check_dump_expectations(tc, enabled, ordered, params)
            if why:
                res.status = "FAIL"
                res.reason = f"dump-config: {why}"
                res.elapsed = time.monotonic() - t0
                return res
        except Exception as e:
            res.status = "FAIL"
            res.reason = f"dump-config: {e}"
            res.elapsed = time.monotonic() - t0
            return res

    # Compile baseline exe
    base_exe = tdir / _exe_name("base")
    try:
        compile_ll_to_exe(tools, base_ll, base_exe, "O0", is_cpp=is_cpp, v=verbose)
    except Exception as e:
        res.status = "FAIL"
        res.reason = f"base compile: {e}"
        res.elapsed = time.monotonic() - t0
        return res

    # Special: seed determinism / divergence
    is_det = "seed_determinism" in tc.gates
    is_div = "seed_divergence" in tc.gates
    if (is_det or is_div) and not no_gates:
        s1, s2 = (42, 42) if is_det else (42, 99)
        ll_a, ll_b = tdir / "det_a.ll", tdir / "det_b.ll"
        try:
            extra_a, rdir_a = _report_opts(f"det_a_s{s1}")
            extra_b, rdir_b = _report_opts(f"det_b_s{s2}")
            run_obfuscation(tools, base_ll, ll_a, s1, extra_a or None, v=verbose)
            run_obfuscation(tools, base_ll, ll_b, s2, extra_b or None, v=verbose)

            # Optional HTML generation
            if report_enabled and report_html and report_tool:
                for label, rdir in ((f"det_a_s{s1}", rdir_a), (f"det_b_s{s2}", rdir_b)):
                    if not rdir:
                        continue
                    j = rdir / "obf_report.json"
                    h = rdir / "obf_report.html"
                    if j.exists():
                        why2 = _gen_obf_report_html(report_tool, j, h, rdir, verbose=verbose)
                        try:
                            res.report_json[label] = str(j.relative_to(report_root))
                        except Exception:
                            res.report_json[label] = str(j)
                        if h.exists():
                            try:
                                res.report_html[label] = str(h.relative_to(report_root))
                            except Exception:
                                res.report_html[label] = str(h)
                        elif why2 and verbose:
                            print(warn(f"report html failed for {tc.name}:{label}: {why2}"))

        except Exception as e:
            res.status = "FAIL"
            res.reason = f"obf: {e}"
            res.elapsed = time.monotonic() - t0
            return res

        ir_a, ir_b = read_text(ll_a), read_text(ll_b)
        key = "seed_determinism" if is_det else "seed_divergence"
        why = run_gate(key, ir_a=ir_a, ir_b=ir_b)
        if why:
            res.status = "FAIL"
            res.reason = f"gate [{key}]: {why}"
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
            cp = run_obfuscation(tools, base_ll, obf_ll, seed, extra_opts or None, v=verbose)
        except Exception as e:
            res.status = "FAIL"
            res.reason = f"seed {seed}: opt: {e}"
            break

        obf_ir = read_text(obf_ll)

        # Optional report HTML generation (best-effort; never fails the test).
        if report_enabled and rdir is not None:
            j = rdir / "obf_report.json"
            h = rdir / "obf_report.html"
            if j.exists():
                try:
                    res.report_json[f"seed_{seed}"] = str(j.relative_to(report_root))
                except Exception:
                    res.report_json[f"seed_{seed}"] = str(j)

                if report_html and report_tool:
                    why2 = _gen_obf_report_html(report_tool, j, h, rdir, verbose=verbose)
                    if h.exists():
                        try:
                            res.report_html[f"seed_{seed}"] = str(h.relative_to(report_root))
                        except Exception:
                            res.report_html[f"seed_{seed}"] = str(h)
                    elif why2 and verbose:
                        print(warn(f"report html failed for {tc.name}:seed_{seed}: {why2}"))

        n = count_fn_instructions(obf_ir, "obf_target")
        res.obf_insts = max(res.obf_insts, n or count_all_instructions(obf_ir))
        res.seeds_run += 1

        # Feature gates
        if not no_gates and tc.gates:
            stderr_text = cp.stderr or ""
            for gk in tc.gates:
                why = run_gate(gk, obf_ir=obf_ir, base_ir=base_ir, stderr_text=stderr_text)
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
            compile_ll_to_exe(tools, obf_ll, obf_exe, "O0", is_cpp=is_cpp, v=verbose)
        except Exception as e:
            res.status = "FAIL"
            res.reason = f"seed {seed}: compile: {e}"
            break

        # Differential correctness
        if tc.correctness:
            fail = False
            if tc.category == "strenc":
                # strenc programs are self-contained: exit 0 = decryption OK.
                # Run once with no arguments — no x/y input pairs needed.
                rc, stdout, _stderr = exec_prog(obf_exe, 0, 0)
                if rc != 0:
                    res.status = "FAIL"
                    res.reason = (f"seed {seed}: strenc binary exited {rc} "
                                  f"(stdout={stdout.strip()!r})")
                    fail = True
                else:
                    res.inputs_run += 1
            else:
                for x, y in inputs:
                    b = exec_prog(base_exe, x, y)
                    o = exec_prog(obf_exe, x, y)
                    why = compare(b, o)
                    if why:
                        res.status = "FAIL"
                        res.reason = f"seed {seed}: {why} (x={x:#x} y={y:#x})"
                        fail = True
                        break
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
                run_o2(tools, base_ll, b_o2_ll, v=verbose)
                run_o2(tools, obf_ll, o_o2_ll, v=verbose)
                compile_ll_to_exe(tools, b_o2_ll, b_o2_exe, "O0", is_cpp=is_cpp, v=verbose)
                compile_ll_to_exe(tools, o_o2_ll, o_o2_exe, "O0", is_cpp=is_cpp, v=verbose)
            except Exception as e:
                res.status = "FAIL"
                res.reason = f"seed {seed}: O2: {e}"
                break

            fail = False
            for x, y in inputs:
                b = exec_prog(b_o2_exe, x, y)
                o = exec_prog(o_o2_exe, x, y)
                why = compare(b, o)
                if why:
                    res.status = "FAIL"
                    res.reason = f"seed {seed}: O2: {why} (x={x:#x} y={y:#x})"
                    fail = True
                    break
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
                        "test": tc.name,
                        "seed": seed,
                        "passes": tc.passes,
                        "base": bm,
                        "obf": om,
                    }) + "\n")
            except Exception:
                pass

    res.elapsed = time.monotonic() - t0
    return res


# ═════════════════════════════════════════════════════════════════════════════
#  Summary Table
# ═════════════════════════════════════════════════════════════════════════════

def _cat_label(cat: str) -> str:
    m = {
        "pass": CYAN,
        "feature": MAGENTA,
        "budget": YELLOW,
        "adec": BLUE,
        "meta": GRAY,
        "cpp": BCYAN,
        "options": MAGENTA,
        "matrix": BLUE,
        "exhaustive": GRAY,
        "strenc": BGREEN,
        "vm": BRED,
    }
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
    if passed:
        parts.append(f"{GREEN()}{passed} passed{RST()}")
    if failed:
        parts.append(f"{RED()}{failed} failed{RST()}")
    if skipped:
        parts.append(f"{YELLOW()}{skipped} skipped{RST()}")

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
              pass       Individual & combo pass correctness
              feature    MBA-advanced, opaque-predicate families
              options    Option parsing sweeps + alias tests (requires --extended)
              matrix     Pairwise pass interaction matrix (requires --extended)
              exhaustive Exhaustive pass-set combinations (requires --exhaustive-combos)
              adec       Anti-decompiler patterns
              budget     IR instruction budget system
              meta       Seed determinism & divergence
              cpp        C++ / EH programs
              strenc     AES-128-CTR string encryption (correctness + IR gates)
              vm         Code virtualisation pass v7 (structural + hardening gates)
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
    ap.add_argument("--no-config-check", action="store_true",
                    help="Skip opt -passes=obf-dump-config validation (enabled list + option KV checks)")
    ap.add_argument("--keep", action="store_true", help="Preserve work dir on success")
    ap.add_argument("--verbose", "-v", action="store_true", help="Print all commands")
    ap.add_argument("--filter", default="", help="Run only tests matching substring")
    ap.add_argument("--category", default="",
                    help="Run only tests in category (pass/feature/options/matrix/exhaustive/adec/budget/meta/cpp)")
    ap.add_argument("--list", action="store_true", help="List all tests and exit")
    ap.add_argument("--quick", action="store_true", help="Fewer inputs (8) for fast iteration")
    ap.add_argument("--no-color", action="store_true", help="Disable colored output")
    ap.add_argument("--json-report", default="", help="Write JSON report to path")

    # Extended / exhaustive test generation
    ap.add_argument("--extended", action="store_true",
                    help="Enable extended option sweeps + pairwise matrix tests (slower)")
    ap.add_argument("--exhaustive-combos", action="store_true",
                    help="Generate exhaustive pass-set combos up to --combo-max-size (implies --extended)")
    ap.add_argument("--combo-max-size", default=3, type=int,
                    help="Max pass-set size for --exhaustive-combos (default: 3)")

    # Obfuscation report generation
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

    extended = bool(args.extended or args.exhaustive_combos)
    exhaustive = bool(args.exhaustive_combos)

    all_tests = make_tests(
        extended=extended,
        exhaustive_combos=exhaustive,
        combo_max_size=max(1, int(args.combo_max_size)),
    )

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
    print(head("║    LLVM Obfuscator — Runtime Correctness Test Suite       ║"))
    print(head("╚═══════════════════════════════════════════════════════════╝"))
    print()
    print(info(f"clang:    {tools.clang}"))
    print(info(f"opt:      {tools.opt}"))
    print(info(f"work:     {work}"))
    print(info(f"seeds:    {seeds}"))
    print(info(f"inputs:   {n_inp} pairs"))
    print(info(f"O2 gate:  {'enabled' if args.o2_gate else 'disabled'}"))
    print(info(f"gates:    {'disabled' if args.no_gates else 'enabled'}"))
    print(info(f"config:   {'disabled' if args.no_config_check else 'enabled'}"))
    print(info(f"extended: {'enabled' if extended else 'disabled'}"))
    if exhaustive:
        print(info(f"exhaustive: enabled (max size {args.combo_max_size})"))
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
            o2_gate=args.o2_gate,
            no_metrics=args.no_metrics,
            no_gates=args.no_gates,
            verbose=args.verbose,
            report_enabled=report_enabled,
            report_root=report_root,
            report_html=report_html,
            report_tool=report_tool,
            config_check=(not args.no_config_check),
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
