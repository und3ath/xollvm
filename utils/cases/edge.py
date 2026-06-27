"""Edge-case IR shapes: integer widths, switches, indirectbr, recursion,
struct-by-value, vectors, nested loops, tail calls.

Each program lives under programs/edge/. Default test uses a mixed pipeline
(mba + bcf + flattening) — torturing the obfuscator with non-trivial CFG
and value-flow patterns. A subset re-runs through the VM pass to catch
virtualisation regressions on uncommon IR shapes.
"""

from __future__ import annotations

import programs

from ._common import Registry, ann_extra, ann_for


# Programs that the VM pass should also exercise. Skip vector/struct/cgoto
# until the VM pass explicitly supports them — current targets are integer
# arithmetic, calls, switches, recursion.
_VM_EDGE_PROGRAMS = (
    "int_widths",
    "switch_jumptable",
    "switch_sparse",
    "recursion_direct",
    "recursion_mutual",
    "loops_nested",
    "tail_calls",
)

_ALL_EDGE_PROGRAMS = (
    "int_widths",
    "switch_jumptable",
    "switch_sparse",
    "indirectbr_cgoto",
    "recursion_direct",
    "recursion_mutual",
    "struct_value",
    "vector_i32x4",
    "loops_nested",
    "tail_calls",
)


def _combo_passes() -> list[str]:
    return ["mba", "bcf", "flattening"]


def register(reg: Registry, **_opts) -> None:
    combo_passes = _combo_passes()
    combo_ann = ann_for(combo_passes)

    # ── Edge × combo pipeline ──
    for name in _ALL_EDGE_PROGRAMS:
        src = programs.render(f"edge.{name}", annotation=combo_ann)
        reg.add(
            name=f"rt_edge_{name}",
            passes=combo_passes,
            src_override=src,
            category="edge",
        )

    # ── Edge × VM pass ──
    vm_ann = ann_extra("vm_v7")
    for name in _VM_EDGE_PROGRAMS:
        src = programs.render(f"edge.{name}", annotation=vm_ann)
        reg.add(
            name=f"rt_edge_vm_{name}",
            passes=["vm"],
            ann_override=vm_ann,
            src_override=src,
            category="edge",
        )
