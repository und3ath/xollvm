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

# lazyDecrypt: AES layer removed per-instruction at fetch instead of by the
# ctor decrypting the whole runtime buffer up front. Feature-active gate:
# the engine must actually call the per-block keystream helper, and the
# ctor must NOT still call the whole-buffer decrypt.
VM_LAZYDECRYPT_GATES = [
    "vm_lazydecrypt_keystream_call", "vm_lazydecrypt_ctor_no_bulk_decrypt",
]

# constInStream: int/i64/fp constants are seeded from an encrypted-bytecode
# prologue instead of plaintext wrapper stores. Feature-active gate: a known
# magic constant used by the switch-dispatch program must not appear as a
# plaintext `store i32 <magic>` immediate once constInStream moves it into
# the bytecode stream.
VM_CONSTINSTREAM_GATES = ["vm_constinstream_no_plaintext_magic"]

# nestedVM: BINOP/BINOP64/ICMP/ICMP64/FCMP/CAST handlers call a pure helper
# that is itself virtualized against a second shared engine. Feature-active
# gate: both @__vm_engine and @__vm_engine.nest must exist, and at least one
# @__vm_h_* helper must have been virtualized (its own handler table targets
# the plain @__vm_engine). Off: neither .nest nor __vm_h_* present.
VM_NESTEDVM_GATES = ["vm_nestedvm_dual_engine", "vm_nestedvm_helper_virtualized"]

# threadedDispatch: no single central vm.dispatch/vm.fetch pair, so the
# structural gates that assert one (vm_dispatch_present, vm_engine_dispatch)
# don't apply -- everything else in VM_CORE_GATES/VM_ENGINE_GATES still holds
# (each handler still ends in its own indirectbr, opcode blocks are named the
# same way, the wrapper is still thin, etc).
VM_THREADED_CORE_GATES = [g for g in VM_CORE_GATES if g != "vm_dispatch_present"]
VM_THREADED_ENGINE_GATES = [g for g in VM_ENGINE_GATES if g != "vm_engine_dispatch"]
VM_THREADED_SHARED_GATES = VM_THREADED_CORE_GATES + VM_THREADED_ENGINE_GATES
VM_THREADED_GATES = ["vm_threaded_no_central_dispatch"]

# keyedDispatch: each opcode byte is XOR'd with a per-IP compile-time key at
# emit time and un-XOR'd at fetch time. Purely a byte-value transform on the
# existing dispatch path -- doesn't change dispatch structure, so it composes
# with any of the CORE/ENGINE/THREADED gate sets above.
VM_KEYEDDISP_GATES = ["vm_keyeddisp_ip_xor"]

_DBG = ["--obf-debug", "--obf-verbose"]


def register(reg: Registry, **_opts) -> None:
    vm_v7 = ann_extra("vm_v7")

    reg.add(name="rt_vm_v7_basic", passes=["vm"],
            ann_override=vm_v7,
            gates=VM_CORE_GATES + ["vm_enc_ctor", "vm_no_threaded_dispatch", "vm_no_keyeddisp"],
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

    # ── P5-A lazy decrypt (lazyDecrypt=1) ──
    # AES layer removed per bytecode-fetch instead of by the ctor decrypting
    # the whole runtime buffer up front. Correctness gate: differential
    # output proves the per-block keystream + windowed cache round-trips the
    # same bytecode the eager path decrypts in one shot. Feature-active gate
    # (VM_LAZYDECRYPT_GATES) proves the lazy path was actually taken, not
    # silently ignored/back off to eager.
    vm_v7_lazy = ann_extra("vm_v7_lazydecrypt")
    vm_v7_lazy_multi = ann_extra("vm_v7_lazydecrypt_multi_fn")

    reg.add(name="rt_vm_v7_lazydecrypt_multi_fn", passes=["vm"],
            ann_override=vm_v7_lazy_multi,
            gates=VM_SHARED_GATES + VM_AES_GATES + VM_LAZYDECRYPT_GATES + [
                "vm_enc_ctor", "vm_callees_global", "vm_multi_fn_shared",
            ],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_multi_fn_aes_program(vm_v7_lazy_multi))
    reg.add(name="rt_vm_v7_lazydecrypt_i64", passes=["vm"],
            ann_override=vm_v7_lazy,
            gates=VM_CORE_GATES + VM_AES_GATES + VM_LAZYDECRYPT_GATES + ["vm_enc_ctor"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_i64_ops_program(vm_v7_lazy))
    reg.add(name="rt_vm_v7_lazydecrypt_float", passes=["vm"],
            ann_override=vm_v7_lazy,
            gates=VM_FLOAT_GATES + VM_AES_GATES + VM_LAZYDECRYPT_GATES,
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_float_basic_program(vm_v7_lazy))
    reg.add(name="rt_vm_v7_lazydecrypt_switch", passes=["vm"],
            ann_override=vm_v7_lazy,
            gates=VM_SHARED_GATES + VM_AES_GATES + VM_LAZYDECRYPT_GATES + [
                "vm_enc_ctor", "vm_multi_fn_shared",
            ],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_switch_dispatch_program(vm_v7_lazy))
    reg.add(name="rt_vm_v7_lazydecrypt_determinism", passes=["vm"],
            ann_override=vm_v7_lazy,
            extra_opts=_DBG, gates=["seed_determinism"], category="vm",
            src_override=render_vm_v7_multi_function_program(vm_v7_lazy))

    # ── constInStream (int/i64/fp constants seeded from the encrypted
    # bytecode stream instead of plaintext wrapper preload stores) ──
    # Correctness gate: differential output proves the OP_LOADI/OP_LOADI64/
    # OP_LOADI_F prologue seeds the same values the plaintext stores used to.
    # Feature-active gate (VM_CONSTINSTREAM_GATES, switch case only) proves
    # the constant actually left the plaintext wrapper.
    vm_v7_cis = ann_extra("vm_v7_constinstream")
    vm_v7_cis_lazy = ann_extra("vm_v7_constinstream_lazy")

    reg.add(name="rt_vm_v7_constinstream_multi_fn", passes=["vm"],
            ann_override=vm_v7_cis,
            gates=VM_SHARED_GATES + [
                "vm_enc_ctor", "vm_callees_global", "vm_multi_fn_shared",
            ],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_multi_fn_aes_program(vm_v7_cis))
    reg.add(name="rt_vm_v7_constinstream_i64", passes=["vm"],
            ann_override=vm_v7_cis,
            gates=VM_CORE_GATES + ["vm_enc_ctor"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_i64_ops_program(vm_v7_cis))
    reg.add(name="rt_vm_v7_constinstream_float", passes=["vm"],
            ann_override=vm_v7_cis,
            gates=VM_FLOAT_GATES,
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_float_basic_program(vm_v7_cis))
    reg.add(name="rt_vm_v7_constinstream_switch", passes=["vm"],
            ann_override=vm_v7_cis,
            gates=VM_SHARED_GATES + VM_CONSTINSTREAM_GATES + [
                "vm_enc_ctor", "vm_multi_fn_shared",
            ],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_switch_dispatch_program(vm_v7_cis))
    reg.add(name="rt_vm_v7_constinstream_determinism", passes=["vm"],
            ann_override=vm_v7_cis,
            extra_opts=_DBG, gates=["seed_determinism"], category="vm",
            src_override=render_vm_v7_multi_function_program(vm_v7_cis))
    # constInStream + lazyDecrypt combined: proves the encrypted-stream
    # prologue round-trips correctly under the per-instruction fetch-time AES
    # keystream path too, not just the whole-buffer-decrypt-in-ctor path.
    reg.add(name="rt_vm_v7_constinstream_lazy", passes=["vm"],
            ann_override=vm_v7_cis_lazy,
            gates=VM_CORE_GATES + VM_AES_GATES + VM_LAZYDECRYPT_GATES,
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_i64_ops_program(vm_v7_cis_lazy))

    # ── nestedVM (BINOP/BINOP64/ICMP/ICMP64/FCMP/CAST call an inner-
    # virtualized pure helper instead of computing inline) ──
    # Correctness gate: differential output proves the depth-2 interpretation
    # (outer engine -> helper call -> plain engine) computes the exact same
    # result as the inline handlers. Feature-active gate (VM_NESTEDVM_GATES)
    # proves both engines exist and the helper was actually virtualized.
    vm_v7_nvm = ann_extra("vm_v7_nestedvm")
    vm_v7_nvm_multi = ann_extra("vm_v7_nestedvm_multi_fn")

    reg.add(name="rt_vm_v7_nestedvm_multi_fn", passes=["vm"],
            ann_override=vm_v7_nvm_multi,
            gates=VM_SHARED_GATES + VM_NESTEDVM_GATES + [
                "vm_enc_ctor", "vm_callees_global", "vm_multi_fn_shared",
            ],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_multi_fn_aes_program(vm_v7_nvm_multi))
    reg.add(name="rt_vm_v7_nestedvm_i64", passes=["vm"],
            ann_override=vm_v7_nvm,
            gates=VM_CORE_GATES + VM_NESTEDVM_GATES + ["vm_enc_ctor"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_i64_ops_program(vm_v7_nvm))
    reg.add(name="rt_vm_v7_nestedvm_float", passes=["vm"],
            ann_override=vm_v7_nvm,
            gates=VM_FLOAT_GATES + VM_NESTEDVM_GATES,
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_float_fcmp_program(vm_v7_nvm))
    reg.add(name="rt_vm_v7_nestedvm_cast", passes=["vm"],
            ann_override=vm_v7_nvm,
            gates=VM_CORE_GATES + VM_NESTEDVM_GATES + ["vm_enc_ctor"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_casts_program(vm_v7_nvm))
    reg.add(name="rt_vm_v7_nestedvm_cmp", passes=["vm"],
            ann_override=vm_v7_nvm,
            gates=VM_CORE_GATES + VM_NESTEDVM_GATES + ["vm_enc_ctor"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_icmp_program(vm_v7_nvm))
    reg.add(name="rt_vm_v7_nestedvm_determinism", passes=["vm"],
            ann_override=vm_v7_nvm,
            extra_opts=_DBG, gates=["seed_determinism"], category="vm",
            src_override=render_vm_v7_multi_function_program(vm_v7_nvm))

    # ── threadedDispatch (every handler inlines its own fetch/decode/
    # indirectbr tail instead of routing through one shared vm.dispatch/
    # vm.fetch pair) ──
    # Correctness gate: differential output proves the per-handler inlined
    # tail fetches/decodes/dispatches the exact same bytecode stream as the
    # central-dispatch build. Feature-active gate (VM_THREADED_GATES) proves
    # the central dispatch loop signature is actually gone, not silently
    # falling back to it.
    vm_v7_thr = ann_extra("vm_v7_threaded")
    vm_v7_thr_multi = ann_extra("vm_v7_threaded_multi_fn")
    vm_v7_thr_hard = ann_extra("vm_v7_threaded_hardened")
    vm_v7_thr_stack = ann_extra("vm_v7_threaded_stack")

    reg.add(name="rt_vm_v7_threaded_multi_fn", passes=["vm"],
            ann_override=vm_v7_thr_multi,
            gates=VM_THREADED_SHARED_GATES + VM_THREADED_GATES + [
                "vm_enc_ctor", "vm_callees_global", "vm_multi_fn_shared",
            ],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_multi_fn_aes_program(vm_v7_thr_multi))
    reg.add(name="rt_vm_v7_threaded_i64", passes=["vm"],
            ann_override=vm_v7_thr,
            gates=VM_THREADED_CORE_GATES + VM_THREADED_GATES + ["vm_enc_ctor"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_i64_ops_program(vm_v7_thr))
    reg.add(name="rt_vm_v7_threaded_float", passes=["vm"],
            ann_override=vm_v7_thr,
            gates=VM_THREADED_CORE_GATES + VM_THREADED_GATES + [
                "vm_fregs_alloca", "vm_enc_ctor",
            ],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_float_basic_program(vm_v7_thr))
    reg.add(name="rt_vm_v7_threaded_switch", passes=["vm"],
            ann_override=vm_v7_thr,
            gates=VM_THREADED_SHARED_GATES + VM_THREADED_GATES + [
                "vm_enc_ctor", "vm_multi_fn_shared",
            ],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_switch_dispatch_program(vm_v7_thr))
    # hardened + threadedDispatch: the dead-block/pre-dispatch-split hardening
    # (vm_hardened_dead_blocks/vm_hardened_dispatch_guard) is a structural
    # no-op under threadedDispatch (no SS->Dispatch to split -- see
    # hardenVMEngine's `if (!ThreadedDispatch && SS->Dispatch)` gate), so
    # those two gates are intentionally excluded here. MBA and handler-entry
    # guards stay active and are still checked.
    reg.add(name="rt_vm_v7_threaded_hardened", passes=["vm"],
            ann_override=vm_v7_thr_hard,
            gates=VM_THREADED_CORE_GATES + VM_THREADED_GATES + [
                "vm_enc_ctor", "vm_hardened_mba", "vm_hardened_handler_guards",
            ],
            extra_opts=_DBG, category="vm")
    # Full-stack composition: threadedDispatch + lazyDecrypt + constInStream +
    # nestedVM together. Proves nextInsn()/emitThreadedTail() composes with
    # the lazy-AES fetch path, the encrypted-stream constant prologue, and
    # the inner nested-VM engine (whose own InnerCfg copies threadedDispatch
    # from the outer Cfg, so both engines dispatch the same way).
    reg.add(name="rt_vm_v7_threaded_stack", passes=["vm"],
            ann_override=vm_v7_thr_stack,
            gates=VM_THREADED_SHARED_GATES + VM_THREADED_GATES
                + VM_AES_GATES + VM_LAZYDECRYPT_GATES + VM_CONSTINSTREAM_GATES
                + VM_NESTEDVM_GATES + ["vm_enc_ctor", "vm_multi_fn_shared"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_switch_dispatch_program(vm_v7_thr_stack))
    reg.add(name="rt_vm_v7_threaded_determinism", passes=["vm"],
            ann_override=vm_v7_thr,
            extra_opts=_DBG, gates=["seed_determinism"], category="vm",
            src_override=render_vm_v7_multi_function_program(vm_v7_thr))

    # ── keyedDispatch (XOR every opcode byte with a per-IP compile-time key
    # at write time in BytecodeEmitter::bop(), un-XOR at fetch time in
    # emitThreadedTail/buildDispatch and verifyBytecode) ──
    # Correctness gate: differential output proves the same physical bytecode
    # decodes correctly through the per-IP un-XOR at every fetch site.
    # Feature-active gate (VM_KEYEDDISP_GATES) proves the IR actually emits
    # the per-IP key mix and opcode-byte XOR, not silently falling back to a
    # plain fetch.
    vm_v7_kd = ann_extra("vm_v7_keyeddisp")
    vm_v7_kd_multi = ann_extra("vm_v7_keyeddisp_multi_fn")
    vm_v7_kd_hard = ann_extra("vm_v7_keyeddisp_hardened")
    vm_v7_kd_stack = ann_extra("vm_v7_keyeddisp_stack")

    reg.add(name="rt_vm_v7_keyeddisp_multi_fn", passes=["vm"],
            ann_override=vm_v7_kd_multi,
            gates=VM_SHARED_GATES + VM_KEYEDDISP_GATES + [
                "vm_enc_ctor", "vm_callees_global", "vm_multi_fn_shared",
            ],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_multi_fn_aes_program(vm_v7_kd_multi))
    reg.add(name="rt_vm_v7_keyeddisp_i64", passes=["vm"],
            ann_override=vm_v7_kd,
            gates=VM_SHARED_GATES + VM_KEYEDDISP_GATES + ["vm_enc_ctor"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_i64_ops_program(vm_v7_kd))
    reg.add(name="rt_vm_v7_keyeddisp_float", passes=["vm"],
            ann_override=vm_v7_kd,
            gates=VM_SHARED_GATES + VM_KEYEDDISP_GATES + [
                "vm_fregs_alloca", "vm_enc_ctor",
            ],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_float_basic_program(vm_v7_kd))
    reg.add(name="rt_vm_v7_keyeddisp_switch", passes=["vm"],
            ann_override=vm_v7_kd,
            gates=VM_SHARED_GATES + VM_KEYEDDISP_GATES + [
                "vm_enc_ctor", "vm_multi_fn_shared",
            ],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_switch_dispatch_program(vm_v7_kd))
    # hardened + keyedDispatch: hardening operates on handler-block bodies
    # (MBA, dead blocks, dispatch/handler guards) which are all still present
    # under keyedDispatch (a pure byte-value transform on the opcode fetch,
    # not a dispatch-structure change), so the full hardened gate set applies
    # unchanged (cf. rt_vm_v7_hardened above).
    reg.add(name="rt_vm_v7_keyeddisp_hardened", passes=["vm"],
            ann_override=vm_v7_kd_hard,
            gates=VM_CORE_GATES + VM_KEYEDDISP_GATES + [
                "vm_enc_ctor", "vm_hardened_mba", "vm_hardened_dead_blocks",
                "vm_hardened_dispatch_guard", "vm_hardened_handler_guards",
            ],
            extra_opts=_DBG, category="vm")
    # Full-stack composition: keyedDispatch + threadedDispatch + encDispatch +
    # lazyDecrypt + constInStream + nestedVM together. Proves the per-IP
    # opcode un-XOR composes with the inlined threaded fetch tail, the
    # encrypted dispatch map, the lazy-AES fetch path, the encrypted-stream
    # constant prologue, and the inner nested-VM engine.
    reg.add(name="rt_vm_v7_keyeddisp_stack", passes=["vm"],
            ann_override=vm_v7_kd_stack,
            gates=VM_THREADED_SHARED_GATES + VM_THREADED_GATES + VM_KEYEDDISP_GATES
                + VM_AES_GATES + VM_LAZYDECRYPT_GATES + VM_CONSTINSTREAM_GATES
                + VM_NESTEDVM_GATES + ["vm_enc_ctor", "vm_multi_fn_shared"],
            extra_opts=_DBG, category="vm",
            src_override=render_vm_v7_switch_dispatch_program(vm_v7_kd_stack))
    reg.add(name="rt_vm_v7_keyeddisp_determinism", passes=["vm"],
            ann_override=vm_v7_kd,
            extra_opts=_DBG, gates=["seed_determinism"], category="vm",
            src_override=render_vm_v7_multi_function_program(vm_v7_kd))
