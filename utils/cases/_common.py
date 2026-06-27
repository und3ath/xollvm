"""Shared definitions used by every cases/*.py module.

This file hosts:
  • The TestCase dataclass.
  • Pass list constants (PASSES, ALL_PASSES_WITH_ADEC).
  • Annotation tables (PASS_ANN, EXTRA_ANN) and helpers
    (ann_for, ann_extra, pass_spec, ann_specs).
  • Thin render_*() wrappers around programs.render(...) used by run_test's
    legacy program-dispatch logic.
  • Registry class — minimal collector that case modules append to.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import programs
from gates.strenc import SECRET_A, SECRET_B, SECRET_C, SHORT


# ═════════════════════════════════════════════════════════════════════════════
#  Pass Definitions & Annotations
# ═════════════════════════════════════════════════════════════════════════════

PASSES: List[str] = [
    "mba",
    "substitution",
    "vcall",
    "split",
    "sdiff",
    "bcf",
    "flattening",
    "vm",
    "shield",
    "strenc",
]

ALL_PASSES_WITH_ADEC: List[str] = PASSES + ["adec"]

PASS_ANN: Dict[str, str] = {
    "flattening":   "flattening(minBlocks=3,maxBlocks=200,opaqueState=1,"
                    "fakeTransitions=1,fakeCases=2,domain=1,ptr=1,alias=1)",
    "bcf":          "bcf(prob=100,loop=1)",
    "split":        "split(num=3)",
    "substitution": "substitution(loop=1)",
    "mba":          "mba(prob=100,depth=2,maxSites=200)",
    "sdiff":        "sdiff(prob=100,slots=2,maxSites=40)",
    "shield":       "shield(maxSites=200,volatile=1,identity=1,dse=1,cfg=1)",
    "vcall":        "vcall(prob=100)",
    "vm":           "vm(minBlocks=1,obfRegIdx=1,encBytecode=1)",
    "strenc":       "strenc(minlen=4,aes=1,keysplit=1)",
    "adec":         "adec(prob=80,strength=2,maxSites=30)",
}

EXTRA_ANN: Dict[str, str] = {
    "mba_advanced": (
        "mba(prob=100,depth=4,maxSites=400,"
        "termsMin=12,termsMax=20,"
        "enableNonLinear=1,nonLinearWeight=70,"
        "enableLayered=1,layeredBudget=4,layeredWindow=72)"
    ),
    "opaque_families": (
        "flattening(prob=100,minBlocks=3,maxBlocks=250,opaqueState=1,"
        "fakeTransitions=1,fakeCases=4,domain=1,ptr=1,alias=1), "
        "bcf(prob=100,loop=1)"
    ),
    "budget_low": (
        "mba(prob=100,depth=3,maxSites=300), "
        "bcf(prob=100,loop=2), "
        "substitution(loop=2)"
    ),
    "adec_full":  "adec(prob=90,strength=3,maxSites=50)",
    "adec_combo": (
        "mba(prob=80,depth=2,maxSites=200), "
        "bcf(prob=60,loop=1), "
        "adec(prob=70,strength=2,maxSites=30)"
    ),
    "adec_selective": "adec(prob=100,strength=2,maxSites=40,asm=0,alias=0)",
    "adec_with_flat": (
        "flattening(minBlocks=3,maxBlocks=120), "
        "adec(prob=70,strength=2,maxSites=25)"
    ),
    "kitchen_sink": (
        "mba(prob=80,depth=2,maxSites=150), "
        "substitution(loop=1), "
        "vcall(prob=50), "
        "split(num=2), "
        "bcf(prob=60,loop=1), "
        "sdiff(prob=80,slots=2,maxSites=30), "
        "flattening(prob=100,minBlocks=3,maxBlocks=120), "
        "shield(maxSites=200,volatile=1,identity=1,dse=1,cfg=1), "
        "strenc(minlen=4,aes=1,keysplit=1), "
        "adec(prob=50,strength=1,maxSites=20)"
    ),
    "vm_v7":                 "vm(minBlocks=1,obfRegIdx=1,encBytecode=1)",
    "vm_v7_bare":            "vm(minBlocks=1,obfRegIdx=0,encBytecode=0)",
    "vm_v7_obfidx":          "vm(minBlocks=1,obfRegIdx=1,encBytecode=0)",
    "vm_v7_enc":             "vm(minBlocks=1,obfRegIdx=0,encBytecode=1)",
    "vm_v7_hardened":        "vm(minBlocks=1,obfRegIdx=1,encBytecode=1,hardened=1)",
    "vm_v7_regenc":          "vm(minBlocks=1,obfRegIdx=1,encBytecode=1,regEncrypt=1)",
    "vm_v7_regenc_hardened": "vm(minBlocks=1,obfRegIdx=1,encBytecode=1,hardened=1)",
}


def ann_for(passes: list[str]) -> str:
    frags = [PASS_ANN[p] for p in passes if p in PASS_ANN]
    return "obf: " + ", ".join(frags)


def ann_extra(key: str) -> str:
    return "obf: " + EXTRA_ANN[key]


def pass_spec(pass_name: str, params: Optional[Dict[str, Any]] = None) -> str:
    if not params:
        return pass_name
    items = [f"{k}={params[k]}" for k in sorted(params.keys())]
    return f"{pass_name}({','.join(items)})"


def ann_specs(specs: list[str]) -> str:
    return "obf: " + ", ".join(specs)


# ═════════════════════════════════════════════════════════════════════════════
#  Test case dataclass + collector
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class TestCase:
    name:         str
    passes:       list[str]
    ann_override: str | None  = None
    extra_opts:   list[str]   = field(default_factory=list)
    gates:        list[str]   = field(default_factory=list)
    expect_enabled: list[str]                 = field(default_factory=list)
    expect_order:   list[str]                 = field(default_factory=list)
    expect_config:  Dict[str, Dict[str, str]] = field(default_factory=dict)
    correctness:  bool        = True
    ir_only:      bool        = False
    category:     str         = "pass"
    no_config_check: bool     = False
    src_override: Optional[str] = None


class Registry:
    """Mutable list wrapper that case modules append to during register()."""
    def __init__(self):
        self.cases: list[TestCase] = []

    def add(self, **kw) -> TestCase:
        tc = TestCase(**kw)
        self.cases.append(tc)
        return tc

    def extend(self, items) -> None:
        self.cases.extend(items)


# ═════════════════════════════════════════════════════════════════════════════
#  Program render wrappers (used by run_test's legacy program-dispatch logic)
# ═════════════════════════════════════════════════════════════════════════════

def render_program(annotation: str, *, want_strenc: bool = False) -> str:
    maybe_puts = f'  puts("{SECRET_A}");' if want_strenc else ""
    return programs.render("base.host_arith",
                           annotation=annotation, maybe_puts=maybe_puts)


def render_cpp_eh_program(annotation: str) -> str:
    return programs.render("eh.throw_catch", annotation=annotation)


def render_complex_logic_program(annotation: str) -> str:
    return programs.render("base.complex_logic", annotation=annotation)


def render_vm_v7_memory_program(annotation: str) -> str:
    return programs.render("vm.memory", annotation=annotation)


def render_vm_v7_gep_chain_program(annotation: str) -> str:
    return programs.render("vm.gep_chain", annotation=annotation)


def render_vm_v7_call_program(annotation: str) -> str:
    return programs.render("vm.call", annotation=annotation)


def render_vm_v7_casts_program(annotation: str) -> str:
    return programs.render("vm.casts", annotation=annotation)


def render_vm_v7_icmp_program(annotation: str) -> str:
    return programs.render("vm.icmp", annotation=annotation)


def render_vm_v7_multiblock_program(annotation: str) -> str:
    return programs.render("vm.multiblock", annotation=annotation)


def render_vm_v7_i64_ops_program(annotation: str) -> str:
    return programs.render("vm.i64_ops", annotation=annotation)


def render_strenc_basic(annotation: str) -> str:
    return programs.render("strenc.basic", annotation=annotation, secret=SECRET_A)


def render_strenc_multi(annotation: str) -> str:
    return programs.render("strenc.multi", annotation=annotation,
                           a=SECRET_A, b=SECRET_B, c=SECRET_C)


def render_strenc_minlen(annotation: str) -> str:
    return programs.render("strenc.minlen", annotation=annotation,
                           short=SHORT, long_=SECRET_A)


def render_strenc_xor_fallback(annotation: str) -> str:
    return programs.render("strenc.xor_fallback", annotation=annotation,
                           secret="XOR_FALLBACK_SECRET_2026")


def render_aes_stub_obfuscated(annotation: str) -> str:
    return programs.render("aes_stub.obfuscated", annotation=annotation,
                           secret="STUB_OBFUSCATION_VERIFY_2026")


def render_aes_stub_passes(annotation: str) -> str:
    return programs.render("aes_stub.passes", annotation=annotation,
                           secret="STUB_PASSES_VERIFY_2026")


def render_vm_v7_float_basic_program(annotation: str) -> str:
    return programs.render("vm.float_basic", annotation=annotation)


def render_vm_v7_float_cast_program(annotation: str) -> str:
    return programs.render("vm.float_cast", annotation=annotation)


def render_vm_v7_float_fcmp_program(annotation: str) -> str:
    return programs.render("vm.float_fcmp", annotation=annotation)


def render_vm_v7_float_mem_program(annotation: str) -> str:
    return programs.render("vm.float_mem", annotation=annotation)


def render_vm_v7_float_ret_program(annotation: str) -> str:
    return programs.render("vm.float_ret", annotation=annotation)


def render_vm_v7_float_comprehensive_program(annotation: str) -> str:
    return programs.render("vm.float_comprehensive", annotation=annotation)


def render_vm_v7_call_i64_args_program(annotation: str) -> str:
    return programs.render("vm.call_i64_args", annotation=annotation)


def render_vm_v7_call_vararg_program(annotation: str) -> str:
    return programs.render("vm.call_vararg", annotation=annotation)


def render_vm_v7_call_i64_ret_program(annotation: str) -> str:
    return programs.render("vm.call_i64_ret", annotation=annotation)


def render_vm_v7_multi_function_program(annotation: str) -> str:
    return programs.render("vm.multi_function", annotation=annotation)


def render_vm_v7_multi_fn_aes_program(annotation: str) -> str:
    return programs.render("vm.multi_fn_aes", annotation=annotation)
