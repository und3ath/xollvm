"""cases package — test-suite catalog and runner.

Each category lives in its own module (passes, features, adec, budget, seed,
eh, vm, strenc, extended, exhaustive). Modules expose a `register(reg, **opts)`
hook that appends TestCase entries to the shared Registry.

make_tests() invokes the hooks in a stable order; --extended / --exhaustive
modules consult their respective opts to decide whether to emit anything.

The TestResult dataclass and run_test driver live in cases._runner and are
re-exported here for backward compatibility with runner.cli.
"""

from __future__ import annotations

from ._common import Registry, TestCase
from ._runner import TestResult, run_test  # re-export for runner.cli

from . import (
    adec, budget, constenc, edge, eh, exhaustive, extended, features, passes,
    seed, strenc, vm,
)

_MODULES = (passes, features, adec, budget, seed, eh, vm, strenc, constenc,
            edge, extended, exhaustive)


def make_tests(*, extended: bool, exhaustive_combos: bool,
               combo_max_size: int) -> list[TestCase]:
    reg = Registry()
    opts = dict(extended=extended,
                exhaustive_combos=exhaustive_combos,
                combo_max_size=combo_max_size)
    for mod in _MODULES:
        mod.register(reg, **opts)
    return reg.cases


__all__ = ["TestCase", "TestResult", "make_tests", "run_test"]
