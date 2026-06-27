"""Cross-architecture build/exec pipeline.

Per target: llc emits assembly from the obfuscated/base .ll, an optional
attribute-strip pass cleans RISC-V, then the cross-gcc links a static
binary. exec_target runs it via qemu-user and captures stdout for compare.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional

from .config import Tools
from .targets import Target
from .util import run_cmd


def build_for_target(
    tools: Tools, ll: Path, out_exe: Path, target: Target, *,
    verbose: bool = False,
) -> None:
    """ll → .s (llc) → static exe (cross-gcc)."""
    if tools.llc is None:
        raise RuntimeError("llc not detected in build_dir; required for cross-arch")
    asm = out_exe.with_suffix(".s")

    run_cmd([
        str(tools.llc),
        f"-mtriple={target.triple}",
        f"-march={target.llc_arch}",
        *target.llc_flags,
        str(ll),
        "-o", str(asm),
    ], verbose=verbose)

    if target.strip_attribute_directives:
        lines = asm.read_text(encoding="utf-8", errors="replace").splitlines()
        cleaned = [l for l in lines if not l.strip().startswith(".attribute")]
        asm.write_text("\n".join(cleaned), encoding="utf-8", newline="\n")

    run_cmd([target.cross_gcc, "-static", str(asm), "-o", str(out_exe)],
            verbose=verbose)


def exec_target(target: Target, exe: Path, x: int, y: int,
                timeout: int = 30) -> tuple[int, str, str]:
    """Run a target binary under qemu-user; same shape as runner.util.exec_prog."""
    try:
        cp = subprocess.run(
            [target.qemu_bin, str(exe), str(x), str(y)],
            text=True, capture_output=True, timeout=timeout,
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
    return None
