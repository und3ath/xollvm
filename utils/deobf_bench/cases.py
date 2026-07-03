"""Bench case registry.

A BenchCase names a source program (rendered via `programs.render`), the
obfuscator pass(es) under attack, the attack module to run against it, and
whatever ground truth that attack needs to score results (expected simple
op, expected plaintext secrets, ...).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import programs
from cases._common import ann_extra, ann_for, ann_specs, pass_spec
from gates.strenc import SECRET_A, SECRET_B


@dataclass
class BenchCase:
    name: str
    program: str            # dotted programs.render() name
    passes: List[str]       # obfuscator passes under attack (drives -passes=obfuscation gating via annotation)
    attack: str              # attacks registry key ("mba", "cfg", "strenc")
    annotation: str          # full "obf: ..." function annotation
    ground_truth: Dict[str, Any] = field(default_factory=dict)
    render_kwargs: Dict[str, Any] = field(default_factory=dict)  # extra programs.render() kwargs beyond annotation

    def render(self) -> str:
        return programs.render(self.program, annotation=self.annotation, **self.render_kwargs)


_CASES: List[BenchCase] = []


def register(case: BenchCase) -> BenchCase:
    _CASES.append(case)
    return case


def all_cases() -> List[BenchCase]:
    return list(_CASES)


def by_attack(attack: str) -> List[BenchCase]:
    return [c for c in _CASES if c.attack == attack]


def find(name: str) -> Optional[BenchCase]:
    for c in _CASES:
        if c.name == name:
            return c
    return None


# ═════════════════════════════════════════════════════════════════════════════
#  Attack 1 — MBA / SMT: single-op leaf functions, ground truth = op name.
#
# Three strength tiers per op so the report shows *where* the Z3 attack stops
# working, not just a single pass/fail: "weak"/"medium" are cheap linear MBA
# configs Z3 collapses in milliseconds; "strong" is the project's own
# mba_advanced tuning (nonlinear + layered), which holds under the solver's
# timeout budget on every op.
# ═════════════════════════════════════════════════════════════════════════════

_MBA_TIERS = {
    "weak":   ann_specs([pass_spec("mba", {"prob": 100, "depth": 1, "maxSites": 50})]),
    "medium": ann_specs([pass_spec("mba", {"prob": 100, "depth": 2, "maxSites": 150})]),
    "strong": ann_extra("mba_advanced"),
}

for _op_name, _tmpl in (
    ("add32", "mba_ops.add32"),
    ("sub32", "mba_ops.sub32"),
    ("xor32", "mba_ops.xor32"),
    ("and32", "mba_ops.and32"),
    ("or32",  "mba_ops.or32"),
):
    for _tier, _ann in _MBA_TIERS.items():
        register(BenchCase(
            name=f"mba_{_op_name}_{_tier}",
            program=_tmpl,
            passes=["mba"],
            attack="mba",
            annotation=_ann,
            ground_truth={"op": _op_name[:-2]},  # "add"/"sub"/"xor"/"and"/"or"
        ))


# `substitution` rewrites the same straight-line add/sub/xor/and/or ops mba
# does (instruction-equivalent rewriting, not MBA identities specifically) —
# attacks/mba_smt.py's Z3 lifter is a generic straight-line-IR-to-bitvector
# interpreter, it doesn't care which pass produced the arithmetic. Reuse it
# verbatim, just point the annotation at `substitution` instead of `mba`.
_SUBSTITUTION_TIERS = {
    "weak":   ann_specs([pass_spec("substitution", {"loop": 1, "maxSites": 50})]),
    "strong": ann_specs([pass_spec("substitution", {"loop": 10, "maxSites": 400})]),
}

for _op_name, _tmpl in (
    ("add32", "mba_ops.add32"),
    ("sub32", "mba_ops.sub32"),
    ("xor32", "mba_ops.xor32"),
    ("and32", "mba_ops.and32"),
    ("or32",  "mba_ops.or32"),
):
    for _tier, _ann in _SUBSTITUTION_TIERS.items():
        register(BenchCase(
            name=f"sub_{_op_name}_{_tier}",
            program=_tmpl,
            passes=["substitution"],
            attack="mba",
            annotation=_ann,
            ground_truth={"op": _op_name[:-2]},
        ))


# ═════════════════════════════════════════════════════════════════════════════
#  Attack 2 — CFG recovery: bcf / flattening / vm on branchy programs.
#
# "weak"/"strong" tiers per pass show the resilience gradient as the pass's
# own knobs (loop count, block-count cap, hardening) are turned up.
# ═════════════════════════════════════════════════════════════════════════════

_CFG_TIERS = {
    "bcf": {
        "weak":   ann_specs([pass_spec("bcf", {"prob": 100, "loop": 1})]),
        "strong": ann_specs([pass_spec("bcf", {"prob": 100, "loop": 10})]),
    },
    "flattening": {
        "weak":   ann_specs([pass_spec("flattening", {"minBlocks": 3, "maxBlocks": 50})]),
        "strong": ann_specs([pass_spec("flattening", {
            "prob": 100, "minBlocks": 3, "maxBlocks": 4000, "opaqueState": 1,
            "fakeTransitions": 1, "fakeCases": 4, "domain": 1, "ptr": 1, "alias": 1,
        })]),
    },
    "vm": {
        "weak":   ann_specs([pass_spec("vm", {"minBlocks": 1, "obfRegIdx": 0, "encBytecode": 0})]),
        "strong": ann_specs([pass_spec("vm", {
            "minBlocks": 1, "obfRegIdx": 1, "encBytecode": 1, "hardened": 1,
        })]),
    },
    # split just multiplies block/edge count with no semantic hiding — the
    # existing block/edge-deviation scoring already fits it directly.
    "split": {
        "weak":   ann_specs([pass_spec("split", {"num": 2})]),
        "strong": ann_specs([pass_spec("split", {"num": 10})]),
    },
}

for _pass, _tiers in _CFG_TIERS.items():
    for _tier, _ann in _tiers.items():
        for _prog_label, _prog in (("loops", "edge.loops_nested"), ("switch", "edge.switch_jumptable")):
            register(BenchCase(
                name=f"cfg_{_pass}_{_prog_label}_{_tier}",
                program=_prog,
                passes=[_pass],
                attack="cfg",
                annotation=_ann,
                ground_truth={},
            ))


# ═════════════════════════════════════════════════════════════════════════════
#  Attack 3 — string extraction: strenc programs w/ known plaintext secrets.
#
# NOTE: the shared programs/strenc/{multi,minlen}.c.tmpl templates compare a
# literal against itself (`strcmp("{a}", "{a}")`) — Clang constant-folds that
# to `0` at the -O0 frontend level (pointer-identical builtin-call folding,
# independent of `-disable-O0-optnone`) *before* the obfuscator ever runs, so
# no @.str reference and no decrypt call survive to attack. Those templates
# are fine for the existing static IR gates (which only assert plaintext
# doesn't leak — vacuously true either way) but useless for a *dynamic*
# extraction attack. strenc.basic avoids this via a `msg` pointer indirection
# (loaded from a stack slot, not a syntactically-identical literal), so does
# the purpose-built strenc_dyn.multi below.
# ═════════════════════════════════════════════════════════════════════════════

_STRENC_ANN = ann_for(["strenc"])
_STRENC_XOR_ANN = ann_specs([pass_spec("strenc", {"minlen": 4, "aes": 0})])
# ChaCha20 path (strenc MAX redesign A-E): tableless cipher, runtime key
# reconstruction (no flat key), inlined decrypt (no choke-point call),
# lazy+scrub, MBA-encoded recombination.
_STRENC_CHACHA_ANN = ann_specs([pass_spec("strenc", {"cipher": "chacha"})])

register(BenchCase(
    name="strenc_basic",
    program="strenc.basic",
    passes=["strenc"],
    attack="strenc",
    annotation=_STRENC_ANN,
    ground_truth={"secrets": [SECRET_A], "decrypt_abi": "aes"},
    render_kwargs={"secret": SECRET_A},
))
register(BenchCase(
    name="strenc_multi",
    program="strenc_dyn.multi",
    passes=["strenc"],
    attack="strenc",
    annotation=_STRENC_ANN,
    ground_truth={"secrets": [SECRET_A, SECRET_B], "decrypt_abi": "aes"},
    render_kwargs={"a": SECRET_A, "b": SECRET_B},
))
# ChaCha20 variants — exercise the strenc MAX redesign (A-E) end-to-end.
register(BenchCase(
    name="strenc_basic_chacha",
    program="strenc.basic",
    passes=["strenc"],
    attack="strenc",
    annotation=_STRENC_CHACHA_ANN,
    ground_truth={"secrets": [SECRET_A], "decrypt_abi": "aes"},
    render_kwargs={"secret": SECRET_A},
))
register(BenchCase(
    name="strenc_multi_chacha",
    program="strenc_dyn.multi",
    passes=["strenc"],
    attack="strenc",
    annotation=_STRENC_CHACHA_ANN,
    ground_truth={"secrets": [SECRET_A, SECRET_B], "decrypt_abi": "aes"},
    render_kwargs={"a": SECRET_A, "b": SECRET_B},
))
# ═════════════════════════════════════════════════════════════════════════════
#  Attack 4 — opt-survival: does `shield` actually make an obfuscator's
#  artifacts survive `opt -passes=default<O2>`? Paired with `bcf`, not
#  `mba` — verified via `-obf-verbose` that shield finds 0 protectable sites
#  in mba's output (pure arithmetic, nothing volatile/opaque-identity/
#  dead-store/CFG-guard shaped) but 44 in bcf's (opaque-predicate branches
#  are exactly what shield's defenses target). Every case pairs the same
#  bcf(loop=1) config with (a) no shield and (b) shield at a given tier —
#  resilience = fraction of the obfuscator's *added* instructions (vs. the
#  unobfuscated baseline) still there after O2, shielded vs. not.
# ═════════════════════════════════════════════════════════════════════════════

_SHIELD_BCF_BASE = "bcf(prob=100,loop=1)"
_SHIELD_TIERS = {
    "weak":   ann_specs([_SHIELD_BCF_BASE,
                          pass_spec("shield", {"maxSites": 50, "volatile": 0,
                                                "identity": 0, "dse": 0, "cfg": 0})]),
    "strong": ann_specs([_SHIELD_BCF_BASE,
                          pass_spec("shield", {"maxSites": 200, "volatile": 1,
                                                "identity": 1, "dse": 1, "cfg": 1})]),
}
_SHIELD_UNSHIELDED_ANN = ann_specs([_SHIELD_BCF_BASE])  # reference: same bcf, no shield

for _prog_label, _prog in (("loops", "edge.loops_nested"), ("switch", "edge.switch_jumptable")):
    for _tier, _ann in _SHIELD_TIERS.items():
        register(BenchCase(
            name=f"shield_{_prog_label}_{_tier}",
            program=_prog,
            passes=["bcf", "shield"],
            attack="shield",
            annotation=_ann,
            ground_truth={"unshielded_annotation": _SHIELD_UNSHIELDED_ANN},
        ))


# ═════════════════════════════════════════════════════════════════════════════
#  Attack 5 — decompiler quality: adec vs. angr's real Decompiler analysis.
# ═════════════════════════════════════════════════════════════════════════════

_ADEC_TIERS = {
    "weak":   ann_specs([pass_spec("adec", {"prob": 30, "strength": 1, "maxSites": 10})]),
    "strong": ann_extra("adec_full"),  # adec(prob=90,strength=3,maxSites=50)
}

for _prog_label, _prog in (("loops", "edge.loops_nested"), ("switch", "edge.switch_jumptable")):
    for _tier, _ann in _ADEC_TIERS.items():
        register(BenchCase(
            name=f"decomp_{_prog_label}_{_tier}",
            program=_prog,
            passes=["adec"],
            attack="decompile",
            annotation=_ann,
            ground_truth={},
        ))


# ═════════════════════════════════════════════════════════════════════════════
#  Attack 6 — call-target recovery: vcall vs. static disassembly.
# ═════════════════════════════════════════════════════════════════════════════

_VCALL_TIERS = {
    "weak":   ann_specs([pass_spec("vcall", {"prob": 30})]),
    "strong": ann_specs([pass_spec("vcall", {
        "prob": 100, "decoys": 1, "decoyMin": 3, "decoyMax": 6,
        "varyIndex": 1, "indexStrength": 2, "opaqueNames": 1,
    })]),
}

for _tier, _ann in _VCALL_TIERS.items():
    register(BenchCase(
        name=f"vcall_basic_{_tier}",
        program="vcall_ops.basic",
        passes=["vcall"],
        attack="vcall",
        annotation=_ann,
        ground_truth={},
    ))


# ═════════════════════════════════════════════════════════════════════════════
#  Attack 7 — VM bytecode extraction: recovers the plaintext bytecode blob
#  behind VMPass's AES-CTR encryption for encBytecode=1 configs. Only makes
#  sense with encryption actually on (attacking a no-op is meaningless), so
#  both cases keep encBytecode=1 and vary hardening instead of encryption.
# ═════════════════════════════════════════════════════════════════════════════

_VMBC_ANN = ann_specs([pass_spec("vm", {
    "minBlocks": 1, "obfRegIdx": 1, "encBytecode": 1, "hardened": 1,
})])

for _prog_label, _prog in (("loops", "edge.loops_nested"), ("switch", "edge.switch_jumptable")):
    register(BenchCase(
        name=f"vmbc_{_prog_label}",
        program=_prog,
        passes=["vm"],
        attack="vmbc",
        annotation=_VMBC_ANN,
        ground_truth={},
    ))


# ═════════════════════════════════════════════════════════════════════════════
#  Attack 8 — BCF opaque-predicate SMT proof: the real technique (tautology
#  proof on the guard condition), not the cfg attack's block/edge proxy.
# ═════════════════════════════════════════════════════════════════════════════

_OPAQUE_TIERS = {
    "weak":   ann_specs([pass_spec("bcf", {"prob": 100, "loop": 1})]),
    "strong": ann_specs([pass_spec("bcf", {"prob": 100, "loop": 10})]),
}

for _prog_label, _prog in (("loops", "edge.loops_nested"), ("switch", "edge.switch_jumptable")):
    for _tier, _ann in _OPAQUE_TIERS.items():
        register(BenchCase(
            name=f"opaque_{_prog_label}_{_tier}",
            program=_prog,
            passes=["bcf"],
            attack="opaque",
            annotation=_ann,
            ground_truth={},
        ))


# ═════════════════════════════════════════════════════════════════════════════
#  Attack 9 — sdiff (semantic diffusion): reuses attacks/mba_smt.py's Z3
#  equivalence-proof machinery, same as substitution above. Confirmed by
#  inspecting real -obf-verbose'd IR before writing this: sdiff diffuses an
#  `icmp eq/ne` by XOR'ing *both* operands with the *same* two keys
#  (`L1=LHS^K1; L2=L1^K2; R1=RHS^K1; R2=R1^K2; icmp L2,R2`), where the keys
#  come from a genuinely hash-mixed (mul/add/shift/xor) volatile-slot
#  entropy chain. That key-derivation complexity is beside the point
#  algebraically: `(a^k) == (b^k)` iff `a==b` for *any* k, no matter how
#  hard k itself is to compute — so this isn't really a "trace the taint"
#  problem, it's the same equivalence-proof problem mba_smt.py already
#  solves. Real prediction worth checking empirically: does the reused
#  attack in fact find this trivially provable regardless of the slots/prob
#  tier, since XOR-cancellation doesn't care how complex the key is?
# ═════════════════════════════════════════════════════════════════════════════

_SDIFF_TIERS = {
    "weak":   ann_specs([pass_spec("sdiff", {"prob": 100, "slots": 1, "maxSites": 10})]),
    "strong": ann_specs([pass_spec("sdiff", {"prob": 100, "slots": 8, "maxSites": 40})]),
}

for _tier, _ann in _SDIFF_TIERS.items():
    register(BenchCase(
        name=f"sdiff_eq32_{_tier}",
        program="sdiff_ops.eq32",
        passes=["sdiff"],
        attack="mba",
        annotation=_ann,
        ground_truth={"op": "eq"},
    ))


register(BenchCase(
    name="strenc_xor_fallback",
    program="strenc_dyn.xor_fallback",
    passes=["strenc"],
    attack="strenc",
    annotation=_STRENC_XOR_ANN,
    # aes=0 selects the legacy single-byte-XOR decrypt helper — a much
    # weaker cipher, but the dynamic tap doesn't care about cipher strength
    # at all (it reads memory after the call regardless of what ran), so
    # this is expected to show the *same* 0% resilience as the AES cases.
    ground_truth={"secrets": [SECRET_A], "decrypt_abi": "xor"},
    render_kwargs={"secret": SECRET_A},
))
