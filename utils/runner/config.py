"""Tool detection: locate clang and opt inside the LLVM build directory."""

from __future__ import annotations

import platform
from dataclasses import dataclass
from pathlib import Path

from .util import die


@dataclass(frozen=True)
class Tools:
    clang: Path
    opt: Path
    llc: Path | None = None  # optional — only required for cross-arch builds


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

    llc_path = bin_dir / f"llc{exe}"
    llc = llc_path if llc_path.exists() else None

    return Tools(clang=clang, opt=bin_dir / f"opt{exe}", llc=llc)
