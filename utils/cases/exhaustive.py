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
            reg.add(name="exh_" + "_".join(subset_list),
                    passes=subset_list, category="exhaustive")
