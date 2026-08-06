"""Opt-survival resilience attack — does `shield` actually protect obfuscator
artifacts from LLVM's own optimizer?

`shield` doesn't obfuscate on its own; it defends *other* passes' artifacts
(volatile barriers, opaque identities, dead-store protection, CFG guards)
against being cleaned up by `opt -passes=default<O2>`. So this attack is
inherently a paired comparison: the same underlying mba(depth=1) config,
compiled once with the case's shield tier and once with shield stripped out
entirely (`ground_truth["unshielded_annotation"]`), both run through O2, and
scored on what fraction of the obfuscator's *added* instructions (relative
to the plain unobfuscated baseline) survive optimization.
"""

from __future__ import annotations

import time
from pathlib import Path

from . import AttackResult, register
from .. import cases as cases_mod
from ..runner_glue import compile_and_obfuscate_variant

_TOOL = "opt (default<O2>)"
_TECHNIQUE = "LLVM O2 instruction-survival ratio (shielded vs. unshielded twin)"


def _survival_ratio(pre_base: int, pre_obf: int, post_base: int, post_obf: int) -> float:
    added_pre = pre_obf - pre_base
    if added_pre <= 0:
        return 0.0
    added_post = max(0, post_obf - post_base)
    return max(0.0, min(1.0, added_post / added_pre))


@register("shield")
def run(case: "cases_mod.BenchCase", tools, work: Path, seed: int, *,
        verbose: bool = False, progress=None) -> AttackResult:
    t0 = time.monotonic()
    prog = progress or (lambda msg: None)

    def mk(status: str, resilience, detail: str, extra: dict | None = None) -> AttackResult:
        return AttackResult(case.name, "shield", seed, status, resilience, detail,
                             _TOOL, _TECHNIQUE, time.monotonic() - t0, extra or {})

    try:
        from runner import pipeline
        from runner.util import count_all_instructions, read_text
    except ImportError as e:
        return mk("SKIP", None, f"runner.pipeline not importable: {e}")

    try:
        prog("compiling shielded variant (case's own pass + shield)")
        shielded_ll = compile_and_obfuscate_variant(
            tools, case, work, seed, annotation=case.annotation, tag="shielded", verbose=verbose)
        base_ll = shielded_ll.parent / "base.ll"

        prog("compiling unshielded twin (same base pass, no shield)")
        unshielded_ann = case.ground_truth["unshielded_annotation"]
        unshielded_ll = compile_and_obfuscate_variant(
            tools, case, work, seed, annotation=unshielded_ann, tag="unshielded", verbose=verbose)

        prog("running opt -passes=default<O2> on baseline / shielded / unshielded")
        base_o2 = base_ll.parent / "base_o2.ll"
        shielded_o2 = shielded_ll.parent / "obf_o2.ll"
        unshielded_o2 = unshielded_ll.parent / "obf_o2.ll"
        pipeline.run_o2(tools, base_ll, base_o2, v=verbose)
        pipeline.run_o2(tools, shielded_ll, shielded_o2, v=verbose)
        pipeline.run_o2(tools, unshielded_ll, unshielded_o2, v=verbose)

        pre_base = count_all_instructions(read_text(base_ll))
        pre_shielded = count_all_instructions(read_text(shielded_ll))
        pre_unshielded = count_all_instructions(read_text(unshielded_ll))
        post_base = count_all_instructions(read_text(base_o2))
        post_shielded = count_all_instructions(read_text(shielded_o2))
        post_unshielded = count_all_instructions(read_text(unshielded_o2))

        resilience = _survival_ratio(pre_base, pre_shielded, post_base, post_shielded)
        unshielded_survival = _survival_ratio(pre_base, pre_unshielded, post_base, post_unshielded)

        # Isolates shield's own marginal contribution (instructions shield
        # added *beyond* the unshielded twin) rather than the whole
        # bcf+shield pipeline vs. plain baseline — this is the number that
        # actually answers "did shield's defenses themselves survive O2,"
        # and can go negative (observed): shield's guards can give O2 more
        # to fold elsewhere, so the shielded build ends up *smaller*
        # post-O2 than the unshielded twin despite starting bigger.
        marginal_pre = pre_shielded - pre_unshielded
        marginal_post = post_shielded - post_unshielded
        marginal_survival = (marginal_post / marginal_pre) if marginal_pre > 0 else None

        detail = (f"shielded {pre_shielded}->{post_shielded} insts "
                  f"(survival {resilience*100:.0f}%), unshielded twin {pre_unshielded}->{post_unshielded} "
                  f"(survival {unshielded_survival*100:.0f}%), baseline {pre_base}->{post_base}")
        extra = {
            "pre_o2_base": str(pre_base), "post_o2_base": str(post_base),
            "pre_o2_shielded": str(pre_shielded), "post_o2_shielded": str(post_shielded),
            "pre_o2_unshielded": str(pre_unshielded), "post_o2_unshielded": str(post_unshielded),
            "unshielded_survival": f"{unshielded_survival*100:.1f}%",
            "shield_marginal_added_pre": str(marginal_pre),
            "shield_marginal_added_post": str(marginal_post),
            "shield_marginal_survival": (f"{marginal_survival*100:.1f}%"
                                          if marginal_survival is not None else "n/a (no marginal insts added)"),
        }
        return mk("PASS", resilience, detail, extra)

    except Exception as e:
        return mk("FAIL", None, f"attack crashed: {e}")
