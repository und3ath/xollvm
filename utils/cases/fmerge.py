"""fmerge (function merging) correctness + IR gates.

Correctness is the differential harness (base-vs-obf output equality across
inputs/seeds). Gates add IR assertions: a super-function was emitted and the
original group members were folded away. Programs are supplied via src_override
because fmerge needs several annotated functions per group — the single-
obf_target convention does not fit — so config_check is disabled.
"""

from __future__ import annotations

import programs

from ._common import Registry


_ALPHA = "obf: fmerge(group=alpha)"
_BETA  = "obf: fmerge(group=beta)"
_BARE  = "obf: fmerge"
_WORKER = "obf: mba(prob=100,depth=2,maxSites=200), bcf(prob=100,loop=1)"
_IBR_A = "obf: fmerge(group=alpha,dispatch=indirectbr)"
_IBR_B = "obf: fmerge(group=beta,dispatch=indirectbr)"
_THUNK = "obf: fmerge(group=tk,thunk=1)"
_THUNK_IBR = "obf: fmerge(group=tk,thunk=1,dispatch=indirectbr)"
_LAUNDER_A = "obf: fmerge(group=alpha,launder=1)"
_LAUNDER_B = "obf: fmerge(group=beta,launder=1)"


def register(reg: Registry, **_opts) -> None:
    # ── Grouped merge: alpha (3 members incl. void + ptr arg) and beta
    #    (self-recursive fact + square). Two super-functions, all originals
    #    folded away. Correctness + IR gates. ──────────────────────────────
    reg.add(name="fmerge_basic", passes=["fmerge"],
            ann_override=_ALPHA,
            src_override=programs.render("fmerge.basic", ann_a=_ALPHA, ann_b=_BETA),
            gates=["fmerge_merged", "fmerge_folded"],
            no_config_check=True, category="fmerge")

    # ── Bare fmerge → the _auto pool. Default dissimilar=1 shape-distributes
    #    members round-robin across chunks. ────────────────────────────────
    reg.add(name="fmerge_auto_pool", passes=["fmerge"],
            ann_override=_BARE,
            src_override=programs.render("fmerge.basic", ann_a=_BARE, ann_b=_BARE),
            gates=["fmerge_merged"],
            no_config_check=True, category="fmerge")

    # ── _auto pool with dissimilarity grouping disabled → sequential
    #    contiguous chunks. ─────────────────────────────────────────────────
    _SEQ = "obf: fmerge(dissimilar=0)"
    reg.add(name="fmerge_auto_sequential", passes=["fmerge"],
            ann_override=_SEQ,
            src_override=programs.render("fmerge.basic", ann_a=_SEQ, ann_b=_SEQ),
            gates=["fmerge_merged"],
            no_config_check=True, category="fmerge")

    # ── Determinism / divergence across seeds (opaque selector K is seeded). ─
    reg.add(name="fmerge_seed_determinism", passes=["fmerge"],
            ann_override=_ALPHA,
            src_override=programs.render("fmerge.basic", ann_a=_ALPHA, ann_b=_BETA),
            gates=["seed_determinism"], no_config_check=True, category="fmerge")
    reg.add(name="fmerge_seed_divergence", passes=["fmerge"],
            ann_override=_ALPHA,
            src_override=programs.render("fmerge.basic", ann_a=_ALPHA, ann_b=_BETA),
            gates=["seed_divergence"], no_config_check=True, category="fmerge")

    # ── Combo: fmerge on a group + mba/bcf on a non-merged survivor. fmerge
    #    runs first (module pass) and leaves the survivor for the function
    #    pipeline. Correctness under coexistence. ──────────────────────────
    reg.add(name="fmerge_combo", passes=["fmerge"],
            ann_override=_ALPHA,
            src_override=programs.render("fmerge.combo", ann_g=_ALPHA, ann_w=_WORKER),
            extra_opts=["--obf-ir-budget-multiplier=200"],
            gates=["fmerge_merged"],
            no_config_check=True, category="fmerge")

    # ── indirectbr jump-table dispatch. Grouped merge, but each super-
    #    function dispatches via a blockaddress table + indirectbr (no switch). ─
    reg.add(name="fmerge_indirectbr", passes=["fmerge"],
            ann_override=_IBR_A,
            src_override=programs.render("fmerge.basic", ann_a=_IBR_A, ann_b=_IBR_B),
            gates=["fmerge_merged", "fmerge_folded", "fmerge_indirectbr"],
            no_config_check=True, category="fmerge")

    # ── thunks. Address-taken (fn-ptr) + external members keep their
    #    symbols as forwarders; the internal direct-only member is erased. ────
    reg.add(name="fmerge_thunk", passes=["fmerge"],
            ann_override=_THUNK,
            src_override=programs.render("fmerge.thunk", ann=_THUNK),
            gates=["fmerge_merged", "fmerge_thunk"],
            no_config_check=True, category="fmerge")

    # ── thunks + indirectbr together. ───────────────────────────────────────
    reg.add(name="fmerge_thunk_indirectbr", passes=["fmerge"],
            ann_override=_THUNK_IBR,
            src_override=programs.render("fmerge.thunk", ann=_THUNK_IBR),
            gates=["fmerge_merged", "fmerge_thunk", "fmerge_indirectbr"],
            no_config_check=True, category="fmerge")

    # ── selector laundering: call-site selectors come from a mutable global
    #    via a volatile load. Correctness holds under -O2 (the load resists
    #    devirtualization). ────────────────────────────────────────────────
    reg.add(name="fmerge_launder", passes=["fmerge"],
            ann_override=_LAUNDER_A,
            src_override=programs.render("fmerge.basic", ann_a=_LAUNDER_A, ann_b=_LAUNDER_B),
            gates=["fmerge_merged", "fmerge_folded", "fmerge_launder"],
            no_config_check=True, category="fmerge")
