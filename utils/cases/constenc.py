"""constenc (numeric constant encryption) correctness + leak tests.

Correctness is checked by the differential harness (base-vs-obf output equality
across seeds/inputs); the gates add IR-level assertions (magic constants gone,
materialization markers present). Programs are supplied via src_override so the
dedicated fixtures under programs/constenc/ are used verbatim.
"""

from __future__ import annotations

import programs

from ._common import Registry


_ANN       = "obf: constenc(prob=100,minAbs=2)"
_ANN_FP0   = "obf: constenc(prob=100,minAbs=2,encFP=0)"
_ANN_COMBO = ("obf: constenc(prob=100,minAbs=2), "
              "mba(prob=100,depth=2,maxSites=200), "
              "bcf(prob=100,loop=1)")


def register(reg: Registry, **_opts) -> None:
    # ── Individual pass correctness + leak ────────────────────────────
    reg.add(name="constenc_basic", passes=["constenc"],
            ann_override=_ANN,
            src_override=programs.render("constenc.basic", annotation=_ANN),
            gates=["constenc_magic_encoded", "constenc_materialized"],
            category="constenc")

    # ── Skip-list traps: switch / GEP / memcpy / phi / inline-asm /
    #    i64 / float+double. Compile-or-die + output equality. ─────────
    reg.add(name="constenc_traps", passes=["constenc"],
            ann_override=_ANN,
            src_override=programs.render("constenc.traps", annotation=_ANN),
            gates=["constenc_materialized"],
            category="constenc")

    # encFP=0: float/double constants stay literal, ints still encoded.
    reg.add(name="constenc_no_fp", passes=["constenc"],
            ann_override=_ANN_FP0,
            src_override=programs.render("constenc.traps", annotation=_ANN_FP0),
            gates=["constenc_materialized"],
            category="constenc")

    # ── Ordering / interaction: constenc runs first, mba+bcf then bury
    #    the materialization. Correctness must still hold. ─────────────
    reg.add(name="constenc_combo", passes=["constenc", "mba", "bcf"],
            ann_override=_ANN_COMBO,
            src_override=programs.render("constenc.basic", annotation=_ANN_COMBO),
            extra_opts=["--obf-ir-budget-multiplier=200"],
            category="constenc")

    # ── Determinism / divergence across seeds (ir_pair gates; handled
    #    on their own early-return path — keep single-gate). ───────────
    reg.add(name="constenc_seed_determinism", passes=["constenc"],
            ann_override=_ANN,
            src_override=programs.render("constenc.basic", annotation=_ANN),
            gates=["seed_determinism"], category="constenc")
    reg.add(name="constenc_seed_divergence", passes=["constenc"],
            ann_override=_ANN,
            src_override=programs.render("constenc.basic", annotation=_ANN),
            gates=["seed_divergence"], category="constenc")
