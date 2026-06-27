"""Cross-compilation target registry.

A Target bundles the LLVM triple, llc backend args, cross-link toolchain,
and qemu-user emulator for a non-host architecture. The host pseudo-target
uses the local clang directly and runs binaries natively.

Currently populated for the WSL-bridge workflow (Windows-built LLVM driving
Linux cross-gcc + qemu-user inside WSL). Extend by adding entries to
TARGETS and ensuring the toolchain/qemu binaries are on PATH.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Target:
    name: str
    triple: str
    llc_arch: str
    cross_gcc: str
    qemu_bin: str
    llc_flags: list[str] = field(default_factory=list)
    # Post-process the .s file before handing it to cross-gcc. Some targets
    # (e.g. RISC-V) emit attribute directives older GNU assemblers reject.
    strip_attribute_directives: bool = False


HOST = Target(
    name="host",
    triple="",
    llc_arch="",
    cross_gcc="",
    qemu_bin="",
)


TARGETS: dict[str, Target] = {
    "host": HOST,
    "aarch64": Target(
        name="aarch64",
        triple="aarch64-linux-gnu",
        llc_arch="aarch64",
        cross_gcc="aarch64-linux-gnu-gcc",
        qemu_bin="qemu-aarch64",
    ),
    "arm32": Target(
        name="arm32",
        triple="arm-linux-gnueabi",
        llc_arch="arm",
        cross_gcc="arm-linux-gnueabi-gcc",
        qemu_bin="qemu-arm",
    ),
    "riscv64": Target(
        name="riscv64",
        triple="riscv64-unknown-linux-gnu",
        llc_arch="riscv64",
        cross_gcc="riscv64-linux-gnu-gcc",
        qemu_bin="qemu-riscv64",
        llc_flags=[
            "-target-abi=lp64d",
            "-mattr=+m,+a,+f,+d,+c,-relax",
            "-relocation-model=static",
            "-code-model=medium",
        ],
        strip_attribute_directives=True,
    ),
}


def resolve(names: list[str]) -> list[Target]:
    out: list[Target] = []
    for n in names:
        if n not in TARGETS:
            raise KeyError(f"unknown target: {n} (known: {', '.join(TARGETS)})")
        out.append(TARGETS[n])
    return out


def is_available(t: Target) -> tuple[bool, str]:
    """True if cross-gcc and qemu-user binaries are on PATH; otherwise
    return (False, reason)."""
    if t.name == "host":
        return True, ""
    if not shutil.which(t.cross_gcc):
        return False, f"missing cross-gcc: {t.cross_gcc}"
    if not shutil.which(t.qemu_bin):
        return False, f"missing qemu-user: {t.qemu_bin}"
    return True, ""
