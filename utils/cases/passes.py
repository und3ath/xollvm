"""Individual-pass correctness, combo, kitchen-sink, and complex-logic tests."""

from __future__ import annotations

from ._common import (
    ALL_PASSES_WITH_ADEC, PASSES, Registry, TestCase, ann_extra,
)


def register(reg: Registry, **_opts) -> None:
    # ── Individual Pass Correctness ───────────────────────────────────
    for p in PASSES:
        reg.add(name=f"rt_{p}", passes=[p], category="pass")

    # ── Combos ────────────────────────────────────────────────────────
    reg.add(name="rt_combo_all", passes=PASSES[:], category="pass")
    reg.add(
        name="rt_kitchen_sink",
        passes=ALL_PASSES_WITH_ADEC[:],
        ann_override=ann_extra("kitchen_sink"),
        expect_enabled=["mba", "substitution", "vcall", "split", "bcf",
                        "sdiff", "flattening", "shield", "strenc", "adec"],
        category="pass",
    )

    # ── Big Functions / Complex Logic ─────────────────────────────────
    reg.add(name="rt_complex_logic_flat",
            passes=["flattening"], category="pass")
    reg.add(name="rt_complex_logic_heavy",
            passes=["flattening", "bcf", "mba", "split"], category="pass")
