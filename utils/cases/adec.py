"""Anti-decompiler pass tests."""

from __future__ import annotations

from ._common import Registry, ann_extra


def register(reg: Registry, **_opts) -> None:
    reg.add(name="rt_adec", passes=["adec"],
            gates=["adec_patterns"], category="adec")
    reg.add(name="rt_adec_full", passes=["adec"],
            ann_override=ann_extra("adec_full"),
            gates=["adec_patterns", "adec_type_confusion"], category="adec")
    reg.add(name="rt_adec_combo", passes=["mba", "bcf", "adec"],
            ann_override=ann_extra("adec_combo"),
            gates=["adec_patterns"], category="adec")
    reg.add(name="rt_adec_selective", passes=["adec"],
            ann_override=ann_extra("adec_selective"),
            gates=["adec_patterns"], category="adec")
    reg.add(name="rt_adec_flat", passes=["flattening", "adec"],
            ann_override=ann_extra("adec_with_flat"),
            gates=["adec_patterns"], category="adec")
