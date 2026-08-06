"""Thin glue between BenchCase and the existing runner/pipeline.py.

Keeps compile/obfuscate steps in one place so every attack module drives the
same clang/opt invocations the correctness-test runner uses.
"""

from __future__ import annotations

import platform
from pathlib import Path
from typing import Tuple

import programs
from runner import pipeline
from runner.util import exe_name, run_cmd, write_text

from .cases import BenchCase


def _case_work_dir(work: Path, case: BenchCase, seed: int) -> Path:
    d = work / f"{case.name}.s{seed}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _write_source(d: Path, case: BenchCase) -> Tuple[Path, bool]:
    is_cpp = programs.is_cpp(case.program)
    src = d / ("src.cpp" if is_cpp else "src.c")
    write_text(src, case.render())
    return src, is_cpp


def compile_and_obfuscate(tools, case: BenchCase, work: Path, seed: int,
                           *, verbose: bool = False) -> Path:
    """Render + compile to base IR, run the obfuscation pass, return the
    obfuscated .ll path."""
    d = _case_work_dir(work, case, seed)
    src, is_cpp = _write_source(d, case)

    base_ll = d / "base.ll"
    pipeline.compile_src_to_ll(tools, src, base_ll, is_cpp=is_cpp, v=verbose)

    obf_ll = d / "obf.ll"
    pipeline.run_obfuscation(tools, base_ll, obf_ll, seed, v=verbose)
    return obf_ll


def compile_and_obfuscate_exe(tools, case: BenchCase, work: Path, seed: int,
                               *, opt: str = "O0",
                               verbose: bool = False) -> Tuple[Path, Path]:
    """Same as compile_and_obfuscate, but also links baseline + obfuscated
    native executables. Returns (baseline_exe, obf_exe)."""
    d = _case_work_dir(work, case, seed)
    src, is_cpp = _write_source(d, case)

    base_ll = d / "base.ll"
    pipeline.compile_src_to_ll(tools, src, base_ll, is_cpp=is_cpp, v=verbose)

    obf_ll = d / "obf.ll"
    pipeline.run_obfuscation(tools, base_ll, obf_ll, seed, v=verbose)

    base_exe = d / exe_name("base")
    obf_exe = d / exe_name("obf")
    pipeline.compile_ll_to_exe(tools, base_ll, base_exe, opt, is_cpp=is_cpp, v=verbose)
    pipeline.compile_ll_to_exe(tools, obf_ll, obf_exe, opt, is_cpp=is_cpp, v=verbose)
    return base_exe, obf_exe


def compile_and_obfuscate_variant(tools, case: BenchCase, work: Path, seed: int,
                                   *, annotation: str, tag: str,
                                   verbose: bool = False) -> Path:
    """Same as compile_and_obfuscate, but renders the case's program with a
    *different* annotation than the case's own (e.g. the same base pass
    config with a defense pass stripped out, as a reference point) — used
    by attacks that need an A/B comparison against a variant of the same
    source rather than a fixed baseline."""
    d = _case_work_dir(work, case, seed) / tag
    is_cpp = programs.is_cpp(case.program)
    src = d / ("src.cpp" if is_cpp else "src.c")
    write_text(src, programs.render(case.program, annotation=annotation, **case.render_kwargs))

    base_ll = d / "base.ll"
    pipeline.compile_src_to_ll(tools, src, base_ll, is_cpp=is_cpp, v=verbose)

    obf_ll = d / "obf.ll"
    pipeline.run_obfuscation(tools, base_ll, obf_ll, seed, v=verbose)
    return obf_ll


def compile_and_obfuscate_exe_exported(tools, case: BenchCase, work: Path, seed: int,
                                        *, symbol: str = "obf_target", opt: str = "O0",
                                        verbose: bool = False) -> Tuple[Path, Path]:
    """Same as compile_and_obfuscate_exe, but forces `symbol` to keep an
    address-bearing entry in the binary's symbol/export table.

    PE binaries built by clang/lld-link drop local (non-exported) function
    symbols by default, so a plain build leaves angr's loader unable to find
    `obf_target` at all. `/EXPORT:<symbol>` keeps it resolvable without
    changing codegen. Not needed on ELF, where non-stripped local symbols
    stay in .symtab regardless."""
    d = _case_work_dir(work, case, seed)
    src, is_cpp = _write_source(d, case)

    base_ll = d / "base.ll"
    pipeline.compile_src_to_ll(tools, src, base_ll, is_cpp=is_cpp, v=verbose)

    obf_ll = d / "obf.ll"
    pipeline.run_obfuscation(tools, base_ll, obf_ll, seed, v=verbose)

    base_exe = d / exe_name("base")
    obf_exe = d / exe_name("obf")
    extra = ["-Xlinker", f"/EXPORT:{symbol}"] if platform.system() == "Windows" else []
    compiler = pipeline.clang_for_lang(tools, is_cpp)
    for ll, exe in ((base_ll, base_exe), (obf_ll, obf_exe)):
        run_cmd([str(compiler), f"-{opt}", str(ll), "-o", str(exe), *extra], verbose=verbose)
    return base_exe, obf_exe
