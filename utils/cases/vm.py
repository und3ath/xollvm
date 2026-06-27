"""VM-pass v7 tests: structural, hardening, register-encryption, shared engine."""

from __future__ import annotations

from ._common import (
    Registry, ann_extra,
    render_vm_v7_call_i64_args_program,
    render_vm_v7_call_i64_ret_program,
    render_vm_v7_call_program,
    render_vm_v7_call_vararg_program,
    render_vm_v7_casts_program,
    render_vm_v7_float_basic_program,
    render_vm_v7_float_cast_program,
    render_vm_v7_float_comprehensive_program,
    render_vm_v7_float_fcmp_program,
    render_vm_v7_float_mem_program,
    render_vm_v7_float_ret_program,
    render_vm_v7_gep_chain_program,
    render_vm_v7_i64_ops_program,
    render_vm_v7_icmp_program,
    render_vm_v7_memory_program,
    render_vm_v7_multi_fn_aes_program,
    render_vm_v7_multi_function_program,
    render_vm_v7_multiblock_program,
)


VM_CORE_GATES = [
    "vm_dispatch_present", "vm_entry_present", "vm_bytecode_global",
    "vm_ophandlers_global", "vm_indirectbr", "vm_regs_alloca",
    "vm_pregs_alloca", "vm_no_original_blocks", "vm_opc_blocks",
    "vm_bytecode_nonempty",
]

VM_ENGINE_GATES = [
    "vm_engine_exists", "vm_engine_singleton",
    "vm_wrapper_calls_engine", "vm_wrapper_is_thin",
    "vm_engine_has_handlers", "vm_engine_indirectbr",
    "vm_engine_dispatch",
]

VM_SHARED_GATES = VM_CORE_GATES + VM_ENGINE_GATES

VM_AES_GATES = [
    "vm_aes_ctor", "vm_aes_globals",
    "vm_obf_aes_ctr_present", "vm_aes_no_lcg_constants",
]

VM_FLOAT_GATES = VM_CORE_GATES + ["vm_fregs_alloca", "vm_enc_ctor"]

VM_REGENC_GATES = [
    "vm_regenc_key_alloca", "vm_regenc_key_loads",
    "vm_regenc_key_geps", "vm_regenc_pregs_exempt",
]

_DBG = ["--obf-debug", "--obf-verbose"]


def register(reg: Registry, **_opts) -> None:
    vm_v7 = ann_extra("vm_v7")

    reg.add(name="rt_vm_v7_basic", passes=["vm"],
            ann_override=vm_v7,
            gates=VM_CORE_GATES + ["vm_enc_ctor"],
            extra_opts=_DBG, category="vm")
    reg.add(name="rt_vm_v7_bare", passes=["vm"],
            ann_override=ann_extra("vm_v7_bare"),
            gates=VM_CORE_GATES + ["vm_no_enc_ctor"],
            extra_opts=_DBG, category="vm")
    reg.add(name="rt_vm_v7_obfidx", passes=["vm"],
            ann_override=ann_extra("vm_v7_obfidx"),
            gates=VM_CORE_GATES + ["vm_no_enc_ctor"],
            extra_opts=_DBG, category="vm")
    reg.add(name="rt_vm_v7_enc", passes=["vm"],
            ann_override=ann_extra("vm_v7_enc"),
            gates=VM_CORE_GATES + ["vm_enc_ctor"],
            extra_opts=_DBG, category="vm")
    reg.add(name="rt_vm_v7_determinism", passes=["vm"],
            ann_override=vm_v7,
            extra_opts=_DBG, gates=["seed_determinism"], category="vm")
    reg.add(name="rt_vm_v7_divergence", passes=["vm"],
            ann_override=vm_v7,
            extra_opts=_DBG, gates=["seed_divergence"], category="vm")

    reg.add(name="rt_vm_v7_memory", passes=["vm"],
            ann_override=vm_v7,
            gates=VM_CORE_GATES + ["vm_enc_ctor"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_memory_program(vm_v7))
    reg.add(name="rt_vm_v7_gep_chain", passes=["vm"],
            ann_override=vm_v7,
            gates=VM_CORE_GATES + ["vm_enc_ctor"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_gep_chain_program(vm_v7))
    reg.add(name="rt_vm_v7_call", passes=["vm"],
            ann_override=vm_v7,
            gates=VM_CORE_GATES + ["vm_enc_ctor", "vm_callees_global"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_call_program(vm_v7))
    reg.add(name="rt_vm_v7_casts", passes=["vm"],
            ann_override=vm_v7,
            gates=VM_CORE_GATES + ["vm_enc_ctor"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_casts_program(vm_v7))
    reg.add(name="rt_vm_v7_icmp", passes=["vm"],
            ann_override=vm_v7,
            gates=VM_CORE_GATES + ["vm_enc_ctor"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_icmp_program(vm_v7))
    reg.add(name="rt_vm_v7_multiblock", passes=["vm"],
            ann_override=vm_v7,
            gates=VM_CORE_GATES + ["vm_enc_ctor"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_multiblock_program(vm_v7))
    reg.add(name="rt_vm_v7_i64_ops", passes=["vm"],
            ann_override=vm_v7,
            extra_opts=_DBG,
            gates=VM_CORE_GATES + ["vm_enc_ctor"],
            category="vm",
            src_override=render_vm_v7_i64_ops_program(vm_v7))

    # ── Float register file tests (Step 01.3) ──
    reg.add(name="rt_vm_v7_float_basic", passes=["vm"],
            ann_override=vm_v7, gates=VM_FLOAT_GATES, category="vm",
            src_override=render_vm_v7_float_basic_program(vm_v7))
    reg.add(name="rt_vm_v7_float_cast", passes=["vm"],
            ann_override=vm_v7, gates=VM_FLOAT_GATES, category="vm",
            src_override=render_vm_v7_float_cast_program(vm_v7))
    reg.add(name="rt_vm_v7_float_fcmp_select", passes=["vm"],
            ann_override=vm_v7, gates=VM_FLOAT_GATES, category="vm",
            src_override=render_vm_v7_float_fcmp_program(vm_v7))
    reg.add(name="rt_vm_v7_float_mem", passes=["vm"],
            ann_override=vm_v7, gates=VM_FLOAT_GATES, category="vm",
            src_override=render_vm_v7_float_mem_program(vm_v7))
    reg.add(name="rt_vm_v7_float_ret", passes=["vm"],
            ann_override=vm_v7, gates=VM_FLOAT_GATES, category="vm",
            src_override=render_vm_v7_float_ret_program(vm_v7))
    reg.add(name="rt_vm_v7_float_comprehensive", passes=["vm"],
            ann_override=vm_v7,
            gates=VM_FLOAT_GATES + ["vm_callees_global"],
            category="vm",
            src_override=render_vm_v7_float_comprehensive_program(vm_v7))

    # ── Extended call ABI tests (Step 02) ──
    reg.add(name="rt_vm_v7_call_i64_args", passes=["vm"],
            ann_override=vm_v7,
            gates=VM_CORE_GATES + ["vm_enc_ctor", "vm_callees_global"],
            category="vm",
            src_override=render_vm_v7_call_i64_args_program(vm_v7))
    reg.add(name="rt_vm_v7_call_vararg", passes=["vm"],
            ann_override=vm_v7,
            gates=VM_CORE_GATES + ["vm_enc_ctor", "vm_callees_global"],
            category="vm",
            src_override=render_vm_v7_call_vararg_program(vm_v7))
    reg.add(name="rt_vm_v7_call_i64_ret", passes=["vm"],
            ann_override=vm_v7,
            gates=VM_CORE_GATES + ["vm_enc_ctor", "vm_callees_global"],
            category="vm",
            src_override=render_vm_v7_call_i64_ret_program(vm_v7))

    # ── Shared-engine architecture tests (Step 06) ──
    reg.add(name="rt_vm_v7_multi_function", passes=["vm"],
            ann_override=vm_v7,
            gates=VM_SHARED_GATES + ["vm_enc_ctor", "vm_callees_global",
                                     "vm_multi_fn_shared", "vm_handlers_permuted"],
            category="vm",
            src_override=render_vm_v7_multi_function_program(vm_v7))
    reg.add(name="rt_vm_v7_shared_engine_basic", passes=["vm"],
            ann_override=vm_v7,
            gates=VM_SHARED_GATES + ["vm_enc_ctor"], category="vm")
    reg.add(name="rt_vm_v7_aes_ctr", passes=["vm"],
            ann_override=vm_v7,
            gates=VM_SHARED_GATES + VM_AES_GATES + ["vm_enc_ctor"],
            category="vm")
    reg.add(name="rt_vm_v7_no_enc_no_aes", passes=["vm"],
            ann_override=ann_extra("vm_v7_bare"),
            gates=VM_ENGINE_GATES + [
                "vm_entry_present", "vm_bytecode_global",
                "vm_ophandlers_global", "vm_bytecode_nonempty",
                "vm_no_enc_ctor",
            ],
            category="vm")
    reg.add(name="rt_vm_v7_multi_fn_aes", passes=["vm"],
            ann_override=vm_v7,
            gates=VM_SHARED_GATES + VM_AES_GATES + [
                "vm_enc_ctor", "vm_callees_global",
                "vm_multi_fn_shared", "vm_engine_singleton",
            ],
            category="vm",
            src_override=render_vm_v7_multi_fn_aes_program(vm_v7))

    # ── Hardened handlers (Step 04) ──
    reg.add(name="rt_vm_v7_hardened", passes=["vm"],
            ann_override=ann_extra("vm_v7_hardened"),
            gates=VM_CORE_GATES + ["vm_enc_ctor",
                   "vm_hardened_mba", "vm_hardened_dead_blocks",
                   "vm_hardened_dispatch_guard", "vm_hardened_handler_guards"],
            extra_opts=_DBG, category="vm")

    # ── Register-value encryption (Step 05) ──
    vm_v7_regenc = ann_extra("vm_v7_regenc")
    reg.add(name="rt_vm_v7_regenc", passes=["vm"],
            ann_override=vm_v7_regenc,
            gates=VM_CORE_GATES + VM_REGENC_GATES + ["vm_enc_ctor"],
            extra_opts=_DBG, category="vm")
    reg.add(name="rt_vm_v7_regenc_float", passes=["vm"],
            ann_override=vm_v7_regenc,
            gates=VM_FLOAT_GATES + VM_REGENC_GATES + ["vm_regenc_freg_key"],
            category="vm",
            src_override=render_vm_v7_float_basic_program(vm_v7_regenc))
    reg.add(name="rt_vm_v7_regenc_i64", passes=["vm"],
            ann_override=vm_v7_regenc,
            gates=VM_CORE_GATES + VM_REGENC_GATES + ["vm_enc_ctor", "vm_callees_global"],
            category="vm",
            src_override=render_vm_v7_call_i64_args_program(vm_v7_regenc))
    reg.add(name="rt_vm_v7_regenc_multi_fn", passes=["vm"],
            ann_override=vm_v7_regenc,
            gates=VM_SHARED_GATES + VM_REGENC_GATES + [
                "vm_enc_ctor", "vm_callees_global", "vm_multi_fn_shared",
            ],
            category="vm",
            src_override=render_vm_v7_multi_function_program(vm_v7_regenc))
    reg.add(name="rt_vm_v7_regenc_hardened", passes=["vm"],
            ann_override=ann_extra("vm_v7_regenc_hardened"),
            gates=VM_CORE_GATES + VM_REGENC_GATES + [
                "vm_enc_ctor",
                "vm_hardened_mba", "vm_hardened_dead_blocks",
                "vm_hardened_dispatch_guard", "vm_hardened_handler_guards",
            ],
            extra_opts=_DBG, category="vm")
    reg.add(name="rt_vm_v7_regenc_seed_determinism", passes=["vm"],
            ann_override=vm_v7_regenc,
            gates=["seed_determinism"], category="vm")
    reg.add(name="rt_vm_v7_regenc_seed_divergence", passes=["vm"],
            ann_override=vm_v7_regenc,
            gates=["seed_divergence"], category="vm")
