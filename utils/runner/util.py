"""Generic helpers: process spawn, file IO, IR counting, exec/compare."""

from __future__ import annotations

import platform
import random
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

from .fmt import DIM, RST, err


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


def is_subpath(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except Exception:
        return False


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


def exe_name(stem: str) -> str:
    return stem + (".exe" if platform.system() == "Windows" else "")
