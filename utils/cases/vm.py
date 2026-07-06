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
    render_vm_v7_switch_dispatch_program,
    render_vm_v7_i64_ret_highslot_program,
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

    # ── P1 handler polymorphism (handlerVariants=3) ──
    # Multi-function programs so per-function random variant binding is
    # actually exercised across >1 virtualised function sharing one engine.
    # Differential-output check (built in) proves the K distinct MBA-diversified
    # handler variants are semantics-preserving; VM_SHARED_GATES proves the
    # shared engine + expanded indirectbr still verify.
    vm_v7_var3 = ann_extra("vm_v7_variants3")
    vm_v7_var3_hard = ann_extra("vm_v7_variants3_hardened")

    reg.add(name="rt_vm_v7_variants3_multi_fn", passes=["vm"],
            ann_override=vm_v7_var3,
            gates=VM_SHARED_GATES + ["vm_enc_ctor", "vm_callees_global",
                                     "vm_multi_fn_shared", "vm_handlers_permuted"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_multi_function_program(vm_v7_var3))
    reg.add(name="rt_vm_v7_variants3_multi_fn_aes", passes=["vm"],
            ann_override=vm_v7_var3,
            gates=VM_SHARED_GATES + VM_AES_GATES + [
                "vm_enc_ctor", "vm_multi_fn_shared", "vm_engine_singleton"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_multi_fn_aes_program(vm_v7_var3))
    reg.add(name="rt_vm_v7_variants3_hardened", passes=["vm"],
            ann_override=vm_v7_var3_hard,
            gates=VM_SHARED_GATES + ["vm_enc_ctor", "vm_multi_fn_shared"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_multi_function_program(vm_v7_var3_hard))
    reg.add(name="rt_vm_v7_variants3_determinism", passes=["vm"],
            ann_override=vm_v7_var3,
            extra_opts=_DBG, gates=["seed_determinism"], category="vm",
            src_override=render_vm_v7_multi_function_program(vm_v7_var3))

    # ── P2 keyed dispatch (encDispatch=1) ──
    # Encrypted per-opcode->handler index indirection. Correctness gate:
    # differential-output check proves the dmap decrypt path recovers the
    # right handler; run standalone, stacked with variants, and full-stack.
    vm_v7_encd = ann_extra("vm_v7_encdispatch")
    vm_v7_encd_var3 = ann_extra("vm_v7_encdispatch_variants3")
    vm_v7_encd_hard = ann_extra("vm_v7_encdispatch_hardened")

    reg.add(name="rt_vm_v7_encdispatch_multi_fn", passes=["vm"],
            ann_override=vm_v7_encd,
            gates=VM_SHARED_GATES + ["vm_enc_ctor", "vm_multi_fn_shared"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_multi_function_program(vm_v7_encd))
    reg.add(name="rt_vm_v7_encdispatch_variants3", passes=["vm"],
            ann_override=vm_v7_encd_var3,
            gates=VM_SHARED_GATES + ["vm_enc_ctor", "vm_multi_fn_shared"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_multi_function_program(vm_v7_encd_var3))
    reg.add(name="rt_vm_v7_encdispatch_hardened", passes=["vm"],
            ann_override=vm_v7_encd_hard,
            gates=VM_SHARED_GATES + ["vm_enc_ctor", "vm_multi_fn_shared"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_multi_function_program(vm_v7_encd_hard))
    reg.add(name="rt_vm_v7_encdispatch_determinism", passes=["vm"],
            ann_override=vm_v7_encd_var3,
            extra_opts=_DBG, gates=["seed_determinism"], category="vm",
            src_override=render_vm_v7_multi_function_program(vm_v7_encd_var3))

    # ── P3-A strong bytecode keystream (strongBytecode=1) ──
    # Correctness gate: the compile-time PRF keystream (ksByteCT) and the
    # runtime IR mix (ksByteIR) must agree byte-for-byte; differential output
    # proves the Layer-1 round-trip decodes. Standalone + full-stack + determinism.
    vm_v7_sbc = ann_extra("vm_v7_strongbc")
    vm_v7_sbc_full = ann_extra("vm_v7_strongbc_full")

    reg.add(name="rt_vm_v7_strongbc_multi_fn", passes=["vm"],
            ann_override=vm_v7_sbc,
            gates=VM_SHARED_GATES + ["vm_enc_ctor", "vm_multi_fn_shared"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_multi_function_program(vm_v7_sbc))
    reg.add(name="rt_vm_v7_strongbc_full", passes=["vm"],
            ann_override=vm_v7_sbc_full,
            gates=VM_SHARED_GATES + ["vm_enc_ctor", "vm_multi_fn_shared"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_multi_function_program(vm_v7_sbc_full))
    reg.add(name="rt_vm_v7_strongbc_determinism", passes=["vm"],
            ann_override=vm_v7_sbc,
            extra_opts=_DBG, gates=["seed_determinism"], category="vm",
            src_override=render_vm_v7_multi_function_program(vm_v7_sbc))

    # ── P3-B branch-target blinding (blindTargets=1) + full P2/P3 stack ──
    # multi_function has a loop + if/else => exercises JMP/JMPC target blinding;
    # differential output proves the emitter blind (target^K) and the handler
    # un-blind (via tgtKeyIR, MBA-diversified) agree. p3_full stacks every
    # P1/P2/P3 hardening simultaneously.
    vm_v7_bt = ann_extra("vm_v7_blindtgt")
    vm_v7_p3full = ann_extra("vm_v7_p3_full")

    reg.add(name="rt_vm_v7_blindtgt_multi_fn", passes=["vm"],
            ann_override=vm_v7_bt,
            gates=VM_SHARED_GATES + ["vm_enc_ctor", "vm_multi_fn_shared"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_multi_function_program(vm_v7_bt))
    reg.add(name="rt_vm_v7_p3_full_multi_fn", passes=["vm"],
            ann_override=vm_v7_p3full,
            gates=VM_SHARED_GATES + ["vm_enc_ctor", "vm_multi_fn_shared"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_multi_function_program(vm_v7_p3full))
    reg.add(name="rt_vm_v7_blindtgt_determinism", passes=["vm"],
            ann_override=vm_v7_bt,
            extra_opts=_DBG, gates=["seed_determinism"], category="vm",
            src_override=render_vm_v7_multi_function_program(vm_v7_bt))
    # Switch-heavy program: the ONLY case that exercises OP_SWITCH targets +
    # blindTargets + the verifier's switch-target range check under -obf-verify.
    # (Regression guard for the P3-B verifier miss — multi_function has no switch.)
    reg.add(name="rt_vm_v7_blindtgt_switch", passes=["vm"],
            ann_override=vm_v7_bt,
            gates=VM_SHARED_GATES + ["vm_enc_ctor", "vm_multi_fn_shared"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_switch_dispatch_program(vm_v7_bt))
    reg.add(name="rt_vm_v7_switch_default_stack", passes=["vm"],
            ann_override=ann_extra("vm_v7_p3_full"),
            gates=VM_SHARED_GATES + ["vm_enc_ctor", "vm_multi_fn_shared"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_switch_dispatch_program(ann_extra("vm_v7_p3_full")))

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

    # ── P4-C rolling register cipher (rollingRegKey=1) ──
    # Per-slot XOR key evolves on each store; the wrapper decrypts the return
    # value with the final (mutated) keystate. Differential output proves the
    # engine store-evolve and wrapper return-decrypt stay in sync across i32/
    # i64/f64 register files.
    vm_v7_roll = ann_extra("vm_v7_rolling")
    reg.add(name="rt_vm_v7_rolling_multi_fn", passes=["vm"],
            ann_override=vm_v7_roll,
            gates=VM_SHARED_GATES + VM_REGENC_GATES + ["vm_enc_ctor", "vm_multi_fn_shared"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_multi_function_program(vm_v7_roll))
    reg.add(name="rt_vm_v7_rolling_i64", passes=["vm"],
            ann_override=vm_v7_roll,
            gates=VM_CORE_GATES + VM_REGENC_GATES + ["vm_enc_ctor"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_i64_ops_program(vm_v7_roll))
    reg.add(name="rt_vm_v7_rolling_float", passes=["vm"],
            ann_override=vm_v7_roll,
            gates=VM_FLOAT_GATES + VM_REGENC_GATES + ["vm_regenc_freg_key"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_float_basic_program(vm_v7_roll))
    reg.add(name="rt_vm_v7_rolling_determinism", passes=["vm"],
            ann_override=vm_v7_roll,
            extra_opts=_DBG, gates=["seed_determinism"], category="vm",
            src_override=render_vm_v7_multi_function_program(vm_v7_roll))

    # i64-return-with-high-slot: regression guard for the OP_RET_INT verifier
    # false-positive (i64 return slot >= NVR was rejected as a vreg index).
    # Must VIRTUALIZE under -obf-verify (runner default), not skip to native.
    reg.add(name="rt_vm_v7_i64_ret_highslot", passes=["vm"],
            ann_override=vm_v7,
            gates=VM_SHARED_GATES + ["vm_enc_ctor", "vm_multi_fn_shared"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_i64_ret_highslot_program(vm_v7))
    reg.add(name="rt_vm_v7_i64_ret_highslot_rolling", passes=["vm"],
            ann_override=vm_v7_roll,
            gates=VM_SHARED_GATES + VM_REGENC_GATES + ["vm_enc_ctor", "vm_multi_fn_shared"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_i64_ret_highslot_program(vm_v7_roll))

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
