#pragma once
// ============================================================================
// VMPass_ISA.h — Code Virtualisation pass: ISA definitions
//
// This header is included by ALL VM pass translation units.  Keep it
// dependency-free (only primitive headers, no LLVM IR headers).
//
// Exports:
//   VMOp        — logical opcode enum (0x00 .. 0x2B, OP_COUNT = 0x2C)
//   CallArgType — 2-bit per-arg encoding for CALL argtypes u16   [Step 02]
//   BinSubop    — sub-opcode byte for OP_BINOP / OP_BINOP64
//   CastKind    — kind byte for OP_CAST  (i32 register file)
//   Cast64Kind  — kind byte for OP_CAST64 (i32 <-> i64 register files)
//   FBinSubop   — sub-opcode byte for OP_BINOP_F (f64 register file) [Step 01.1]
//   FCastKind   — kind byte for OP_FCAST (f64 <-> i32/i64)           [Step 01.1]
//   VMOpcodeMap — per-function logical<->physical opcode bijection
//   LCG_A/C     — LCG constants for bytecode encryption
// ============================================================================

#include <cstdint>

namespace llvm {

	// ============================================================================
	// VMOp — logical opcode identifiers
	// ============================================================================

	enum VMOp : uint8_t {
		// ── Integer / pointer opcodes (0x00..0x20) ─────────────
		OP_LOADI = 0x00,  // dst:u8 imm:i32le
		OP_MOVR = 0x01,  // dst:u8 src:u8
		OP_BINOP = 0x02,  // dst:u8 a:u8 b:u8 subop:u8
		OP_ICMP = 0x03,  // dst:u8 a:u8 b:u8 pred:u8
		OP_CAST = 0x04,  // dst:u8 src:u8 kind:u8
		OP_PTRTOINT = 0x05,  // dst:u8 srcp:u8
		OP_INTTOPTR = 0x06,  // dstp:u8 src:u8
		OP_LOAD32 = 0x07,  // dst:u8 ptrreg:u8
		OP_STORE32 = 0x08,  // val:u8 ptrreg:u8
		OP_GEP = 0x09,  // dstp:u8 basep:u8 idx:u8 elemsz:u16le
		OP_JMP = 0x0A,  // target:u32le
		OP_JMPC = 0x0B,  // cond:u8 tgt_t:u32 tgt_f:u32
		OP_RET_VOID = 0x0C,
		OP_RET_INT = 0x0D,  // src:u8
		OP_RET_PTR = 0x0E,  // srcp:u8
		// Step 02: argtypes is now u16le (2 bits per arg: 00=vreg,01=preg,10=vreg64,11=freg)
		//          nargs is followed by a flags byte: bit0 = isVarArg
		OP_CALL_VOID = 0x0F,  // fn:u8 nargs:u8 flags:u8 types:u16le [arg:u8 * nargs]
		OP_CALL_INT = 0x10,  // dst:u8 fn:u8 nargs:u8 flags:u8 types:u16le [arg:u8 * nargs]
		OP_CALL_PTR = 0x11,  // dstp:u8 fn:u8 nargs:u8 flags:u8 types:u16le [arg:u8 * nargs]
		OP_CALL_INT64 = 0x2A,  // dst64:u8 fn:u8 nargs:u8 flags:u8 types:u16le [arg:u8 * nargs]  [Step 02]
		OP_CALL_F = 0x2B,  // dstf:u8 fn:u8 nargs:u8 flags:u8 types:u16le [arg:u8 * nargs]   [Step 02]
		OP_SELECT = 0x12,  // kind:u8 dst:u8 cond:u8 t:u8 f:u8
		OP_PTRTOINT64 = 0x13,  // dst64:u8 srcp:u8
		OP_LOAD64 = 0x14,  // dst64:u8 ptrreg:u8
		OP_STORE64 = 0x15,  // val64:u8 ptrreg:u8
		OP_CAST64 = 0x16,  // dst:u8 src:u8 kind:u8
		OP_BINOP64 = 0x17,  // dst64:u8 a64:u8 b64:u8 subop:u8
		OP_SWITCH = 0x18,  // cond:u8 ncases:u16le def:u32le [case:u32le tgt:u32le]*ncases
		OP_GEP64 = 0x19,  // dstp:u8 basep:u8 idx64:u8 elemsz:u16le
		OP_ICMP64 = 0x1A,  // dst:u8 a64:u8 b64:u8 pred:u8
		OP_LOAD8 = 0x1B,  // dst:u8 ptrreg:u8
		OP_STORE8 = 0x1C,  // val:u8 ptrreg:u8
		OP_LOAD16 = 0x1D,  // dst:u8 ptrreg:u8
		OP_STORE16 = 0x1E,  // val:u8 ptrreg:u8
		OP_LOADPTR = 0x1F,  // dstp:u8 ptrreg:u8
		OP_STOREPTR = 0x20,  // valp:u8 ptrreg:u8

		// ── Floating-point opcodes (addition, 0x21..0x29) ─────────
		//
		// The VM adds a fourth register file:  vm.fregs  (alloca [NFRAlloc x double]).
		// All float operations work on f64 (double).  f32 values are widened to f64
		// on slot-assignment (newFR) and narrowed back to f32 on OP_STORE_F / OP_RET_F
		// when the IR type is float; the kind byte on OP_FCAST handles explicit
		// fpext / fptrunc across the boundary.
		//
		// FCmp predicate byte: stores the raw LLVM CmpInst::Predicate value
		//   (FCMP_OEQ=1 .. FCMP_TRUE=15; FCMP_FALSE=0).  Fits in a nibble, stored
		//   as a full u8 for alignment / simplicity.
		// FCmp result lands in the vreg (i32) register file as 0 or 1.

		OP_LOADI_F = 0x21,  // dst:u8 imm:f64le  (1+1+8 = 10 bytes)
		OP_MOVR_F = 0x22,  // dst:u8 src:u8     (1+1+1 =  3 bytes)
		OP_BINOP_F = 0x23,  // dst:u8 a:u8 b:u8 subop:u8  (5 bytes) — see FBinSubop
		OP_FCMP = 0x24,  // dst:u8 a:u8 b:u8 pred:u8   (5 bytes) — result → vreg i32
		OP_FCAST_FF = 0x25,  // dst_fr:u8 src_fr:u8 kind:u8 (4 bytes) — FK_FPEXT / FK_FPTRUNC
		OP_LOAD_F = 0x26,  // dst:u8 ptrreg:u8            (3 bytes) — load f64 from memory  (double* only)
		OP_STORE_F = 0x27,  // val:u8 ptrreg:u8            (3 bytes) — store f64 from memory  (double* only)
		OP_RET_F = 0x28,  // src:u8                      (2 bytes) — return f64 from freg
		OP_SELECT_F = 0x29,  // dst:u8 cond:u8 t:u8 f:u8   (5 bytes) — ternary on fregs

		OP_FNEG = 0x2C, // dst_fr:u8 src_fr:u8
		// OP_LOAD_F32 / OP_STORE_F32 — 4-byte float memory operations.
		// OP_LOAD_F   / OP_STORE_F   remain 8-byte (double* only) for f64 source types.
		// Step 1.6 in run() widens local float allocas to double; these opcodes handle
		// the remaining cases where the pointer genuinely points to a 4-byte float slot
		// (e.g. float* function parameters, global float arrays).
		OP_LOAD_F32 = 0x2D,  // dst:u8 ptrreg:u8  (3 bytes) — load 4-byte float, fpext → freg
		OP_STORE_F32 = 0x2E,  // val:u8 ptrreg:u8  (3 bytes) — fptrunc freg → store 4-byte float

		// ── OP_FCAST_* : split float-cast opcodes (Phase 4) ─────────────────────────────────
		// Opcode encodes the register-file pair; kind byte selects signed/unsigned (or ext/trunc).
		// Encoding: opc dst:u8 src:u8 kind:u8 = 4 bytes (same size as old OP_FCAST).
		OP_FCAST_FV = 0x2F,  // freg  → vreg   i32 : FK_FPTOSI   / FK_FPTOUI
		OP_FCAST_FV64 = 0x30,  // freg  → vreg64 i64 : FK_FPTOSI64 / FK_FPTOUI64
		OP_FCAST_VF = 0x31,  // vreg  i32  → freg  : FK_SITOFP   / FK_UITOFP
		OP_FCAST_V64F = 0x32,  // vreg64 i64 → freg  : FK_SI64TOFP / FK_UI64TOFP
		OP_COUNT = 0x33
	};

	// ============================================================================
	// BinSubop — sub-opcode byte for OP_BINOP and OP_BINOP64
	// ============================================================================

	enum BinSubop : uint8_t {
		BS_ADD = 0, BS_SUB = 1, BS_MUL = 2, BS_AND = 3,
		BS_OR = 4, BS_XOR = 5, BS_SHL = 6, BS_LSHR = 7, BS_ASHR = 8,
		BS_SDIV = 9, BS_UDIV = 10, BS_SREM = 11, BS_UREM = 12,
	};

	// ============================================================================
	// CastKind — kind byte for OP_CAST (all widen/narrow within the i32 reg file)
	// ============================================================================

	enum CastKind : uint8_t {
		CK_ZEXT1 = 0, CK_ZEXT8 = 1, CK_ZEXT16 = 2,
		CK_SEXT8 = 3, CK_SEXT16 = 4,
		CK_TRUNC1 = 5, CK_TRUNC8 = 6, CK_TRUNC16 = 7,
	};

	// ============================================================================
	// Cast64Kind — kind byte for OP_CAST64
	//   ZEXT/SEXT : src is VR (i32 file), dst is VR64 (i64 file)
	//   TRUNC     : src is VR64 (i64 file), dst is VR (i32 file)
	// ============================================================================

	enum Cast64Kind : uint8_t {
		C64_ZEXT1 = 0, C64_ZEXT8 = 1, C64_ZEXT16 = 2, C64_ZEXT32 = 3,
		C64_SEXT8 = 4, C64_SEXT16 = 5, C64_SEXT32 = 6,
		C64_TRUNC1 = 7, C64_TRUNC8 = 8, C64_TRUNC16 = 9, C64_TRUNC32 = 10,
	};

	// FBinSubop — sub-opcode byte for OP_BINOP_F (f64 register file)
	//
	// Byte layout:
	//   bits [6:0]  FBinSubop operation (FBS_FADD .. FBS_FREM, values 0-4)
	//   bit  [7]    FBS_F32_FLAG — when set, the f64 result is rounded back to
	//               f32 precision via fptrunc→fpext before being stored in the
	//               freg slot.  Emitted when the source LLVM instruction has
	//               float (not double) type.  Masked out before subop dispatch.
	//
	// All operands (dst, a, b) are freg indices.  Results land in the freg file.
	// FBS_FADD / FBS_FSUB / FBS_FMUL / FBS_FDIV are emitted with the 'fast' flag
	// set — the original LLVM instruction's fast-math flags are preserved during
	// emission.  FBS_FREM maps to llvm.frem (no fast-math, calls libm fmod).
	// ============================================================================

	enum FBinSubop : uint8_t {
		FBS_FADD = 0,  // fadd [fast] f64 a, b → dst
		FBS_FSUB = 1,  // fsub [fast] f64 a, b → dst
		FBS_FMUL = 2,  // fmul [fast] f64 a, b → dst
		FBS_FDIV = 3,  // fdiv [fast] f64 a, b → dst
		FBS_FREM = 4,  // frem       f64 a, b → dst  (fmod, no fast-math)

		// Bit-flag overlay — not a subop value, masked before dispatch.
		FBS_F32_FLAG = 0x80u,  // round result to f32 precision (source type = float)
	};

	// ============================================================================
	// FCastKind — kind byte for OP_FCAST_FF/FV/FV64/VF/V64F (Phase 4: one opcode per reg-file pair)
	//
	// Encoding layout:
	//   dst register file and src register file are determined by kind value.
	//
	//   Kind         src file       dst file      LLVM instruction
	//   ──────────── ──────────── ──────────────  ───────────────────────────────
	//   FK_FPEXT     freg (f32*)  freg (f64)      fpext  double, float
	//   FK_FPTRUNC   freg (f64)   freg (f32*)     fptrunc float,  double
	//   FK_FPTOSI    freg (f64)   vreg (i32)      fptosi i32,    double
	//   FK_FPTOUI    freg (f64)   vreg (i32)      fptoui i32,    double
	//   FK_SITOFP    vreg (i32)   freg (f64)      sitofp double, i32
	//   FK_UITOFP    vreg (i32)   freg (f64)      uitofp double, i32
	//   FK_FPTOSI64  freg (f64)   vreg64 (i64)   fptosi i64,    double
	//   FK_FPTOUI64  freg (f64)   vreg64 (i64)   fptoui i64,    double
	//   FK_SI64TOFP  vreg64 (i64) freg  (f64)    sitofp double, i64
	//   FK_UI64TOFP  vreg64 (i64) freg  (f64)    uitofp double, i64
	//
	// (*) f32 sources/destinations: the freg file stores doubles.  When the LLVM
	//     instruction produces or consumes f32, the handler inserts an implicit
	//     fpext / fptrunc at the register boundary.  This is consistent with
	//     normal calling-convention widening and adds negligible overhead.
	// ============================================================================

	enum FCastKind : uint8_t {
		FK_FPEXT = 0,   // freg(f32)   → freg(f64)    fpext
		FK_FPTRUNC = 1,   // freg(f64)   → freg(f32)    fptrunc
		FK_FPTOSI = 2,   // freg(f64)   → vreg(i32)    fptosi
		FK_FPTOUI = 3,   // freg(f64)   → vreg(i32)    fptoui
		FK_SITOFP = 4,   // vreg(i32)   → freg(f64)    sitofp
		FK_UITOFP = 5,   // vreg(i32)   → freg(f64)    uitofp
		FK_FPTOSI64 = 6,   // freg(f64)   → vreg64(i64)  fptosi
		FK_FPTOUI64 = 7,   // freg(f64)   → vreg64(i64)  fptoui
		FK_SI64TOFP = 8,   // vreg64(i64) → freg(f64)    sitofp
		FK_UI64TOFP = 9,   // vreg64(i64) → freg(f64)    uitofp

		// Bit-flag overlay — same pattern as FBS_F32_FLAG in FBinSubop.
		// When set on int→float casts (FK_SITOFP, FK_UITOFP, FK_SI64TOFP,
		// FK_UI64TOFP), the f64 result is rounded to f32 precision via
		// fptrunc→fpext, matching native `sitofp float` / `uitofp float`.
		FCAST_F32_FLAG = 0x80u,
	};

	// ============================================================================
	// LCG constants — legacy fallback (useAES=0).
	// When useAES=1 (default, Step 03), the LCG layer is replaced by AES-128-CTR
	// and these constants no longer appear in the emitted binary.  They are kept
	// for the useAES=0 regression-safety path.
	// ============================================================================

	static constexpr uint64_t LCG_A = 6364136223846793005ULL;
	static constexpr uint64_t LCG_C = 1442695040888963407ULL;

	// ============================================================================
	// VMOpcodeMap (P02)
	//
	// Per-function logical<->physical opcode bijection.  The emitter calls
	// initPermuted() with the per-function RNG to produce a unique mapping for
	// every protected function.  The interpreter's handler table is indexed by
	// physical byte; because the bijection is unique, two functions cannot share
	// the same dispatch-table layout — defeating cross-function signature matching.
	//
	// CallArgType — 2-bit field encoding for CALL instruction argument types.
	// In the current encoding, argument type info is carried per-callee in
	// GVFTyIndices rather than inline in the bytecode, so the 8-argument
	// bitfield limit no longer applies.  MaxArgs is now 16.
	enum CallArgType : uint8_t {
		CAT_VREG = 0,  // i32  — read from vm.regs
		CAT_PREG = 1,  // ptr  — read from vm.pregs
		CAT_VREG64 = 2,  // i64  — read from vm.regs64
		CAT_FREG = 3,  // f64  — read from vm.fregs   (future, reserved for Step 02 ext)
	};

	// CallFlags byte — follows nargs in CALL encoding  [Step 02]
	// bit 0: isVarArg — the callee is a variadic function (... in its signature)
	enum CallFlags : uint8_t {
		CF_NONE = 0x00,
		CF_VARARG = 0x01,  // callee is variadic; FunctionType must be built with isVarArg=true
	};

	// NOTE (Phase 4):   OP_COUNT grew from 0x2F (47) → 0x33 (51): +OP_FCAST_FV/FV64/VF/V64F
	// arrays are statically sized by OP_COUNT, so this is a compile-time-only
	// change.  The Fisher-Yates shuffle naturally covers all 42 opcodes.
	// ============================================================================

	struct VMOpcodeMap {
		uint8_t L2P[OP_COUNT];  // logical  -> physical
		uint8_t P2L[OP_COUNT];  // physical -> logical

		VMOpcodeMap() { initIdentity(); }

		void initIdentity() {
			for (unsigned i = 0; i < OP_COUNT; ++i) {
				L2P[i] = (uint8_t)i;
				P2L[i] = (uint8_t)i;
			}
		}

		/// Deterministic Fisher-Yates shuffle driven by the per-function RNG.
		/// Produces a bijection between logical VMOp values and physical opcode bytes.
		/// TRand must expose a u32() method returning a uniform 32-bit value.
		template <typename TRand>
		void initPermuted(TRand& R) {
			uint8_t Phys[OP_COUNT];
			for (unsigned i = 0; i < OP_COUNT; ++i) Phys[i] = (uint8_t)i;
			for (unsigned i = OP_COUNT - 1; i > 0; --i) {
				unsigned j = (unsigned)(R.u32() % (i + 1));
				uint8_t tmp = Phys[i];
				Phys[i] = Phys[j];
				Phys[j] = tmp;
			}
			for (unsigned L = 0; L < OP_COUNT; ++L) L2P[L] = Phys[L];
			for (unsigned P = 0; P < OP_COUNT; ++P) P2L[P] = 0;
			for (unsigned L = 0; L < OP_COUNT; ++L) P2L[L2P[L]] = (uint8_t)L;
		}

		uint8_t encode(VMOp Logical)     const { return L2P[(uint8_t)Logical]; }
		VMOp    decode(uint8_t Physical) const { return (VMOp)P2L[(unsigned)Physical % OP_COUNT]; }
	};

} // namespace llvm