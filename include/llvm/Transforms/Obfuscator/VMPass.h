#pragma once
// ============================================================================
// VMPass.h — Code Virtualisation pass
//
// Architecture: custom bytecode ISA + fetch-decode-execute interpreter.
//
// The pass compiles each eligible function body into a private variable-width
// bytecode stream stored in a read-only global.  The function body is then
// replaced with a minimal wrapper that tail-calls a single module-level
// `__vm_engine` interpreter with per-function globals.  No original basic
// blocks or instruction patterns survive in the emitted IR.
//
// ── Authoritative references ──────────────────────────────────────────────
//   ISA, opcode list, opcode count, encoding widths   → VMPass_ISA.h
//   Engine signature, hardening flow, code emission   → VMPass_Impl.h /
//                                                        VMPass_Emitter.h
//   Full user-facing reference (knobs, layers, perf)  → VM.md
//
// The opcode set, byte layout, and OP_COUNT are defined in VMPass_ISA.h.
// Do NOT duplicate the ISA description here — it drifts.  Treat VMPass_ISA.h
// as the source of truth.
//
// ── Interpreter state (allocas materialised in the per-function wrapper) ──
//   vm.ip       i32         bytecode instruction pointer
//   vm.salt     i32         compile-time seed (volatile — opaque to optimizer)
//   vm.regs     [N x i32]   integer  virtual register file
//   vm.regs64   [N x i64]   64-bit   virtual register file
//   vm.fregs    [N x f64]   floating virtual register file
//   vm.pregs    [N x ptr]   pointer  virtual register file
//
// ── Per-function globals ──────────────────────────────────────────────────
//   @fn.vm.bytecode    [L x i8]            private constant   encoded program
//   @fn.vm.ophandlers  [OP_COUNT x ptr]    private constant   opcode dispatch
//                                                             table (permuted)
//   @fn.vm.callees     [C x ptr]           private constant   callee table
//
//   Register indices in bytecode are XOR'd with CTSaltByte when obfRegIdx=1.
//   Each function uses a per-function Fisher-Yates opcode bijection — two
//   virtualised functions never share dispatch-table layout.
//
// ── Hardening layers (toggled via VMPassConfig) ───────────────────────────
//   obfRegIdx   (default on)  XOR register-index bytes with a compile-time
//                             salt; handlers re-XOR from a volatile load.
//   encBytecode (default on)  .init_array constructor decrypts @fn.vm.bytecode
//                             at process load.  LCG keystream by default;
//                             AES-128-CTR when useAES=1.
//   useAES      (default on)  Replace LCG with AES-128-CTR via the shared
//                             __obf_aes_ctr_decrypt() runtime (same engine
//                             used by `strenc`).
//   regEncrypt  (opt-in)      Per-slot XOR of register file values at rest.
//   hardened    (opt-in)      Wrapper junk/MBA/flattening, engine hardening,
//                             FNV-1a integrity ctor, callee XOR masking.
//   antiDebug   (with hardened) RDTSC-based dispatch + per-handler timing
//                             gates; failure path corrupts salt (silent
//                             miscompute, never abort).
// ============================================================================
#include "llvm/IR/PassManager.h"
namespace llvm {
	class VMPass : public PassInfoMixin<VMPass> {
	public:
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM);
		static bool isRequired() { return true; }
	};
} // namespace llvm