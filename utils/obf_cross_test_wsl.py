#!/usr/bin/env python3
"""Thin entrypoint preserving the historical --build-dir / --seeds CLI shape
used to drive cross-architecture testing from WSL.

The cross-arch pipeline (llc + cross-gcc + qemu-user) is now part of the
main runner; this shim just forwards to obf_runtime_tests.py with the
default WSL target set when --targets is not overridden.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Default to the three WSL bridge targets unless the user passes --targets.
_DEFAULT_TARGETS = "aarch64,arm32,riscv64"
if not any(a.startswith("--targets") for a in sys.argv[1:]):
    sys.argv.append(f"--targets={_DEFAULT_TARGETS}")

from runner.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
