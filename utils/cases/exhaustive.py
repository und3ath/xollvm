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

    for k in range(2, max_k + 1):
        for subset in itertools.combinations(all_passes, k):
            subset_list = list(subset)
            # `vm` runs on a per-function `obf_target` whose block count can
            # easily fall outside its min/maxBlocks default range — that
            # would surface as a legitimate "too few blocks" skip, not a
            # regression. Pre-existing conflict pairs (vm + flattening) are
            # caught earlier by enforceConflicts and are out of scope here.
            tolerate = "vm" in subset_list
            reg.add(name="exh_" + "_".join(subset_list),
                    passes=subset_list, category="exhaustive",
                    expect_no_skips=False if tolerate else None)
