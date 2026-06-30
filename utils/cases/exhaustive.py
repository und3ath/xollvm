"""--exhaustive-combos: every k-subset of passes with 2 ≤ k ≤ combo_max_size."""

from __future__ import annotations

import itertools

from ._common import PASSES, Registry


def register(reg: Registry, *,
             exhaustive_combos: bool = False,
             combo_max_size: int = 3,
             **_opts) -> None:
    if not exhaustive_combos:
        return

    all_passes = PASSES + ["adec"]
    max_k = max(1, combo_max_size)

    # Combinations that include any inflating CFG pass overflow the
    # default 50x IR budget when stacked. Bump the budget for any
    # subset that contains at least one of the heavy passes so the
    # downstream passes do not get strict-skip-fataled.
    _HEAVY = {"flattening", "bcf", "mba"}
    _COMBO_OPTS = ["--obf-ir-budget-multiplier=500"]

    for k in range(2, max_k + 1):
        for subset in itertools.combinations(all_passes, k):
            subset_list = list(subset)
            # vm + flattening is a declared conflict and will fatal at
            # enforceConflicts — these subsets cannot ever produce a useful
            # test, drop them.
            if "vm" in subset_list and "flattening" in subset_list:
                continue
            # `vm` runs on a per-function `obf_target` whose block count can
            # easily fall outside its min/maxBlocks default range — that
            # would surface as a legitimate "too few blocks" skip, not a
            # regression.
            tolerate = "vm" in subset_list
            extra: list[str] = []
            if any(p in _HEAVY for p in subset_list):
                extra = list(_COMBO_OPTS)
            reg.add(name="exh_" + "_".join(subset_list),
                    passes=subset_list, category="exhaustive",
                    extra_opts=extra,
                    expect_no_skips=False if tolerate else None)
