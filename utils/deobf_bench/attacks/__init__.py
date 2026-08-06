"""Attack module registry + shared result type.

Each attack module (mba_smt, cfg_recovery, string_extract) exposes a single
`run(case, tools, work, seed, *, verbose=False, progress=None) -> AttackResult`
function and is registered here under the name used by `--attacks`/
BenchCase.attack.

`progress`, when given, is a `Callable[[str], None]` the attack calls at
each major phase boundary (compile, lift, solve, ...) so a caller running in
--nerd mode can print live checkpoints instead of a single result at the end
of a potentially multi-minute angr/Z3 call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, Optional


@dataclass
class AttackResult:
    """Outcome of running one attack against one (case, seed).

    status:
      PASS  — attack engine ran to completion and produced `resilience`.
              A low/zero resilience is a valid, useful result (obfuscation
              was broken) — it is NOT a bench failure.
      SKIP  — required tool unavailable (e.g. z3-solver/angr not importable).
      FAIL  — bench infra error (compile crash, engine exception, timeout).
    resilience: 0.0 (fully broken) .. 1.0 (fully held). None unless PASS.
    tool: the concrete deobfuscation tool driving the attack (e.g. "z3",
      "angr+capstone") — what the user would install/name if reproducing it.
    technique: one-line description of the attack technique used, so the
      report reads as "X was attacked with Y via Z" rather than just a score.
    extra: nerd-mode diagnostics (solver stats, raw block/edge counts, hex
      dumps, ...) — only shown with --nerd, kept out of the default table.
    """
    case: str
    attack: str
    seed: int
    status: str            # "PASS" | "SKIP" | "FAIL"
    resilience: Optional[float]
    detail: str
    tool: str
    technique: str
    elapsed: float = 0.0
    extra: Dict[str, str] = field(default_factory=dict)


AttackFn = Callable[..., AttackResult]

_REGISTRY: Dict[str, AttackFn] = {}


def register(name: str) -> Callable[[AttackFn], AttackFn]:
    def deco(fn: AttackFn) -> AttackFn:
        _REGISTRY[name] = fn
        return fn
    return deco


def get(name: str) -> AttackFn:
    return _REGISTRY[name]


def names() -> list[str]:
    return sorted(_REGISTRY)


def load_all() -> None:
    """Import every attack module so its @register(...) runs.

    Import errors inside an attack module (e.g. `import angr` failing) must
    NOT prevent other attacks from registering — each module guards its own
    optional dependency and reports SKIP at run() time instead.
    """
    from . import mba_smt   # noqa: F401
    from . import cfg_recovery  # noqa: F401
    from . import string_extract  # noqa: F401
    from . import opt_survival  # noqa: F401
    from . import decompile_quality  # noqa: F401
    from . import call_target_recovery  # noqa: F401
    from . import vm_bytecode  # noqa: F401
    from . import opaque_predicate  # noqa: F401
    from . import latopq_opaque  # noqa: F401
    from . import dse_coverage  # noqa: F401
    from . import handler_sig  # noqa: F401
