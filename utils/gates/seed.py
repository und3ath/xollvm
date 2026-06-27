"""Seed-comparison gates (determinism and divergence)."""

from __future__ import annotations

from typing import Optional

from . import register


@register("seed_determinism", needs="ir_pair")
def seed_determinism(ir_a: str, ir_b: str) -> Optional[str]:
    if ir_a != ir_b:
        for i, (la, lb) in enumerate(zip(ir_a.splitlines(), ir_b.splitlines()), 1):
            if la != lb:
                return f"IR diverges at line {i}: {la[:80]!r} vs {lb[:80]!r}"
        return "IR lengths differ"
    return None


@register("seed_divergence", needs="ir_pair")
def seed_divergence(ir_a: str, ir_b: str) -> Optional[str]:
    if ir_a == ir_b:
        return "different seeds produced identical IR"
    return None
