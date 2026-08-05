"""Individual-pass correctness, combo, kitchen-sink, and complex-logic tests."""

from __future__ import annotations

from ._common import (
    ALL_PASSES_WITH_ADEC, PASSES, Registry, TestCase, ann_extra, ann_specs,
    pass_spec,
)


# `vm` conflicts with `flattening` (both restructure the entire CFG —
# enforceConflicts fatal). Strip vm from combos that include flattening so
# rt_combo_all and rt_kitchen_sink can actually run end-to-end. Dedicated
# vm tests live in cases/vm.py.
_COMBO_PASSES         = [p for p in PASSES              if p != "vm"]
_COMBO_PASSES_W_ADEC  = [p for p in ALL_PASSES_WITH_ADEC if p != "vm"]


def register(reg: Registry, **_opts) -> None:
    # ── Individual Pass Correctness ───────────────────────────────────
    for p in PASSES:
        reg.add(name=f"rt_{p}", passes=[p], category="pass")

    # ── vcall: encrypted, runtime-initialized vtable (encryptTable) ────
    # Non-merged path only. Off (default) must stay byte-identical to the
    # plaintext vtable -- covered by rt_vcall above and rt_vcall_enctable_off
    # below as an explicit control. On must still be correct: the ctor fills
    # ptrtoint(entry) XOR K into a mutable table at runtime, decrypted again
    # at the callsite.
    reg.add(name="rt_vcall_enctable", passes=["vcall"],
            ann_override=ann_specs([pass_spec("vcall", {"prob": 100, "encTable": 1})]),
            category="pass")
    reg.add(name="rt_vcall_enctable_off", passes=["vcall"],
            ann_override=ann_specs([pass_spec("vcall", {"prob": 100, "encTable": 0})]),
            category="pass")
    reg.add(name="rt_vcall_enctable_seed_determinism", passes=["vcall"],
            ann_override=ann_specs([pass_spec("vcall", {"prob": 100, "encTable": 1})]),
            gates=["seed_determinism"], category="pass")

    # ── Combos ────────────────────────────────────────────────────────
    # Combo pipelines stack MBA + Substitution + flattening + bcf etc.,
    # each of which can multiply IR independently. The default 50x IR
    # budget is calibrated for a single pass; under strict-skip
    # enforcement the kitchen-sink pipeline needs a much larger headroom
    # so flattening (post-bcf) does not bail out via the budget gate.
    _COMBO_BUDGET = ["--obf-ir-budget-multiplier=500"]

    reg.add(name="rt_combo_all", passes=_COMBO_PASSES,
            extra_opts=_COMBO_BUDGET, category="pass")
    reg.add(
        name="rt_kitchen_sink",
        passes=_COMBO_PASSES_W_ADEC,
        ann_override=ann_extra("kitchen_sink"),
        extra_opts=_COMBO_BUDGET,
        expect_enabled=["mba", "substitution", "vcall", "split", "bcf",
                        "sdiff", "flattening", "shield", "strenc", "adec"],
        category="pass",
    )

    # ── Big Functions / Complex Logic ─────────────────────────────────
    reg.add(name="rt_complex_logic_flat",
            passes=["flattening"], category="pass")
    reg.add(name="rt_complex_logic_heavy",
            passes=["flattening", "bcf", "mba", "split"],
            extra_opts=_COMBO_BUDGET, category="pass")
