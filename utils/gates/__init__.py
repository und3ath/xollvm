"""Gate registry and dispatcher.

A "gate" is a predicate that inspects obfuscation output (IR, stderr, or a
pair of IRs from two seeds) and returns None on success or a short error
string on failure.

Each gate module under gates/ declares its predicates with @register(name,
needs=...). Importing this package eagerly imports the submodules so all
gates self-register.
"""

from __future__ import annotations

import re
from typing import Callable, Optional

_NEEDS = ("ir", "ir_pair", "stderr", "ir_and_base")

_REGISTRY: dict[str, tuple[Callable, str]] = {}


def register(name: str, *, needs: str = "ir"):
    """Decorator: register a gate under `name`.

    needs:
      "ir"         — gate(obf_ir) -> Optional[str]
      "ir_pair"    — gate(ir_a, ir_b) -> Optional[str]
      "stderr"     — gate(stderr_text) -> Optional[str]
      "ir_and_base"— gate(obf_ir, base_ir) -> Optional[str]
    """
    if needs not in _NEEDS:
        raise ValueError(f"unknown 'needs' kind: {needs}")

    def deco(fn: Callable) -> Callable:
        if name in _REGISTRY:
            raise RuntimeError(f"duplicate gate registration: {name}")
        _REGISTRY[name] = (fn, needs)
        return fn

    return deco


def run_gate(
    key: str, *,
    obf_ir: str = "", base_ir: str = "",
    stderr_text: str = "",
    ir_a: str = "", ir_b: str = "",
) -> Optional[str]:
    entry = _REGISTRY.get(key)
    if entry is not None:
        fn, needs = entry
        if needs == "ir":           return fn(obf_ir)
        if needs == "ir_pair":      return fn(ir_a, ir_b)
        if needs == "stderr":       return fn(stderr_text)
        if needs == "ir_and_base":  return fn(obf_ir, base_ir)

    m = re.match(r"budget_clamped_(\d+)", key)
    if m:
        from .budget import budget_clamped
        return budget_clamped(obf_ir, base_ir, int(m.group(1)))
    m = re.match(r"budget_hardcap_(\d+)", key)
    if m:
        from .budget import budget_hardcap
        return budget_hardcap(obf_ir, int(m.group(1)))

    return f"unknown gate: {key}"


# Eager imports so decorators fire.
from . import adec, aes_stub, budget, mba, seed, strenc  # noqa: E402, F401
from . import vm, vm_engine, vm_hardened, vm_regenc       # noqa: E402, F401
