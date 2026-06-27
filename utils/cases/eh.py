"""C++ / Exception-Handling tests.

EH functions have invoke/landingpad instructions that make them ineligible
for most obfuscation passes. obf-dump-config will not emit an OBF-CONFIG-FN
block for them, so config_check is suppressed via no_config_check=True.
"""

from __future__ import annotations

from ._common import ALL_PASSES_WITH_ADEC, Registry, ann_extra


def register(reg: Registry, **_opts) -> None:
    reg.add(
        name="rt_cpp_eh_basic",
        passes=["flattening", "mba"],
        no_config_check=True,
        category="cpp",
    )
    reg.add(
        name="rt_cpp_eh_full",
        passes=ALL_PASSES_WITH_ADEC[:],
        ann_override=ann_extra("kitchen_sink"),
        no_config_check=True,
        category="cpp",
    )
