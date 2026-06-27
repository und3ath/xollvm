"""IR-budget system tests (multiplier, verbose, exhaustion, hardcap)."""

from __future__ import annotations

from ._common import Registry, ann_extra


def register(reg: Registry, **_opts) -> None:
    reg.add(
        name="rt_budget_low", passes=["mba", "bcf", "substitution"],
        ann_override=ann_extra("budget_low"),
        extra_opts=["--obf-ir-budget-multiplier=8"],
        gates=["budget_clamped_8"], category="budget",
    )
    reg.add(
        name="rt_budget_verbose", passes=["mba", "bcf", "substitution"],
        ann_override=ann_extra("budget_low"),
        extra_opts=["--obf-ir-budget-multiplier=20", "--obf-verbose"],
        gates=["budget_verbose"], category="budget",
    )
    reg.add(
        name="rt_budget_exhaust", passes=["mba", "bcf", "substitution"],
        ann_override=ann_extra("budget_low"),
        extra_opts=["--obf-ir-budget-multiplier=3", "--obf-verbose"],
        gates=["budget_exhaustion"], category="budget",
    )
    reg.add(
        name="rt_budget_unlimited", passes=["mba", "bcf"],
        extra_opts=["--obf-ir-budget-multiplier=0"], category="budget",
    )
    reg.add(
        name="rt_budget_hardcap", passes=["mba", "bcf", "substitution"],
        ann_override=ann_extra("budget_low"),
        extra_opts=["--obf-ir-budget-multiplier=100", "--obf-ir-budget-max=2000"],
        gates=["budget_hardcap_2000"], category="budget",
    )
