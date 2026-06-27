"""Compile / obfuscate / O2 / metrics pipeline wrappers around clang and opt."""

from __future__ import annotations

import json
import platform
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from .config import Tools
from .util import run_cmd


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
    return clang


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
