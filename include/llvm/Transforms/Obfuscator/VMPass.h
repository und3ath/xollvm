#pragma once
// ============================================================================
// VMPass.h — Code Virtualisation pass (v7)
//
// Architecture: custom bytecode ISA + fetch-decode-execute interpreter.
//
// The pass compiles each eligible function body into a private variable-width
// bytecode stream stored in a read-only global.  The function body is then
// replaced with a minimal interpreter that runs the stream.  No original
// basic blocks or instruction patterns survive in the emitted IR.
//
// ── Interpreter state (allocas in vm.entry) ───────────────────────────────
//   vm.ip       i32   bytecode instruction pointer
//   vm.salt     i32   compile-time seed (volatile — opaque to optimizer)
//   vm.regs     [N x i32]   integer virtual register file
//   vm.pregs    [M x ptr]   pointer virtual register file
//
// ── Globals emitted per function ──────────────────────────────────────────
//   @fn.vm.bytecode    [L x i8]     private constant   the encoded program
//   @fn.vm.ophandlers  [18 x ptr]   private constant   opcode dispatch table
//   @fn.vm.callees     [C x ptr]    private constant   callee address table
//
// ── ISA summary (18 opcodes, variable-width, little-endian immediates) ─────
//   OP_LOADI      0x00   dst:u8 imm:i32le                       (6 B total)
//   OP_MOVR       0x01   dst:u8 src:u8                          (3 B)
//   OP_BINOP      0x02   dst:u8 a:u8 b:u8 subop:u8              (5 B)
//   OP_ICMP       0x03   dst:u8 a:u8 b:u8 pred:u8               (5 B)
//   OP_CAST       0x04   dst:u8 src:u8 kind:u8                  (4 B)
//   OP_PTRTOINT   0x05   dst:u8 srcp:u8                         (3 B)
//   OP_INTTOPTR   0x06   dstp:u8 src:u8                         (3 B)
//   OP_LOAD32     0x07   dst:u8 ptrreg:u8                       (3 B)
//   OP_STORE32    0x08   val:u8 ptrreg:u8                       (3 B)
//   OP_GEP        0x09   dstp:u8 basep:u8 idx:u8                (4 B)
//   OP_JMP        0x0A   target:u32le                           (5 B)
//   OP_JMPC       0x0B   cond:u8 tgt_t:u32le tgt_f:u32le       (10 B)
//   OP_RET_VOID   0x0C                                          (1 B)
//   OP_RET_INT    0x0D   src:u8                                 (2 B)
//   OP_RET_PTR    0x0E   srcp:u8                                (2 B)
//   OP_CALL_VOID  0x0F   fn:u8 nargs:u8 args*                   (3+n B)
//   OP_CALL_INT   0x10   dst:u8 fn:u8 nargs:u8 args*            (4+n B)
//   OP_CALL_PTR   0x11   dstp:u8 fn:u8 nargs:u8 args*           (4+n B)
//
//   Arg byte encoding for CALL*: bit7=1 → preg index, bit7=0 → vreg index.
//   Register indices in bytecode are XOR'd with CTSaltByte when obfRegIdx=1.
//
// ── Hardening ─────────────────────────────────────────────────────────────
//   obfRegIdx   (default on)  XOR every register-index byte in the bytecode
//               with a compile-time salt.  Each opcode handler re-XORs with
//               the same volatile salt load — correct at runtime, opaque to
//               static analysis and the LLVM optimizer.
//
//   encBytecode (default on)  A .init_array constructor encrypts
//               @fn.vm.bytecode in-place before main() using an LCG stream
//               keyed by ptrtoint(@fn.vm.bytecode) XOR COMPILE_TIME_SEED
//               (ASLR-derived, different per process load).  The dispatch
//               loop additionally decrypts each opcode byte with
//               (salt XOR ip) & 0xFF before dispatching.
//
//
//   useAES      (default on)  [Step 03] Replace the LCG keystream (Layer 2)
//               with AES-128-CTR.  When enabled, a per-function 128-bit key
//               is generated from the RNG hierarchy and the runtime ctor calls
//               __obf_aes_ctr_decrypt() (shared with strenc) instead of LCG.
// ============================================================================
#include "llvm/IR/PassManager.h"
namespace llvm {
	class VMPass : public PassInfoMixin<VMPass> {
	public:
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM);
		static bool isRequired() { return true; }
	};
} // namespace llvm