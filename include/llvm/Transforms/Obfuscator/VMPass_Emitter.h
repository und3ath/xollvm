#pragma once
// ============================================================================
// VMPass_Emitter.h — Code Virtualisation pass: BytecodeEmitter
//
// BytecodeEmitter is a two-pass IR → bytecode compiler:
//
//   Pass 1  (size)
//       Walk every instruction in RPO and record the byte-offset of each
//       basic block's first instruction.  Also assigns all register slots in
//       declaration order: function arguments first, then entry-block allocas
//       (demoted PHI nodes), then all remaining instruction results.
//
//   Pass 2  (emit)
//       Walk every instruction again and write the actual opcode bytes into
//       the BC vector.  Every register-index byte is XOR'd with the low byte
//       of SaltConst when obfRegIdx=1.
//
// After a successful run() the public output fields are consumed by VMImpl
// to build the interpreter IR.
//
// Step 01.1 additions:
//   - FR   DenseMap<Value*, uint8_t>  — f64 SSA value → freg slot
//   - ImmLoadsF SmallVector            — constant-FP pre-loads into fregs
//   - NFR  uint8_t                    — total freg slots used
//   - newFR / fr                      — slot allocation helpers (private)
//   - f64() bytecode primitive        — emits an 8-byte IEEE-754 double LE
// ============================================================================

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Value.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/Transforms/Obfuscator/VMPass_ISA.h"

#include <cstring>

namespace llvm {

	class BasicBlock;
	class ConstantInt;
	class ConstantFP;
	class DataLayout;
	class Instruction;
	class Type;

	// ============================================================================
	// BytecodeEmitter
	// ============================================================================

	struct BytecodeEmitter {
		static constexpr uint8_t kInvalidSlot = 0xFF;

		// ── Output fields — read by VMImpl after a successful run() ─────────

		SmallVector<uint8_t, 1024>       BC;         // raw bytecode bytes
		DenseMap<BasicBlock*, uint32_t>  BlockIP;    // first IP of each block
		DenseMap<Value*, uint8_t>        VR;         // i32  SSA value  → vreg   slot
		DenseMap<Value*, uint8_t>        VR64;       // i64  SSA value  → vreg64 slot
		DenseMap<Value*, uint8_t>        PR;         // ptr  SSA value  → preg   slot
		DenseMap<Value*, uint8_t>        FR;         // f64  SSA value  → freg   slot [Step 01.1]
		SmallVector<Value*, 8>           CalleeTab;  // callee table (CALL* targets)
		// 6.2: parallel FunctionType table -- one entry per CalleeTab slot.
		SmallVector<FunctionType*, 8>    CalleeFTyTab;

		/// Metadata for an entry-block alloca created by PHI demotion.
		struct PhiAllocaDesc {
			uint8_t     Slot = 0;       // preg slot assigned to this alloca
			Type* AllocTy = nullptr;
			MaybeAlign  A;                // original alignment (if any)
			std::string Name;             // stable debug-friendly name
		};
		SmallVector<PhiAllocaDesc, 8>    PHIAllocas;  // demoted PHI allocas, in preg order

		// Pre-load lists built during slot assignment; consumed by VMImpl::buildVMEntry.
		SmallVector<std::pair<uint8_t, ConstantInt*>, 16>  ImmLoads;    // vreg   slot, ConstantInt (<=32-bit)
		SmallVector<std::pair<uint8_t, ConstantInt*>, 16>  ImmLoads64;  // vreg64 slot, ConstantInt (i64)
		SmallVector<std::pair<uint8_t, Value*>, 16> PtrLoads;    // preg   slot, global/null ptr
		SmallVector<std::pair<uint8_t, ConstantFP*>, 8>  ImmLoadsF;   // freg   slot, ConstantFP (f64/f32) [Step 01.1]

		uint8_t NVR = 0;  // total vreg   slots used
		uint8_t NVR64 = 0;  // total vreg64 slots used
		uint8_t NPR = 0;  // total preg   slots used
		uint8_t NFR = 0;  // total freg   slots used [Step 01.1]


		// When an instruction cannot be virtualised Unsupported is set and run()
		// returns false.  FailReason describes the first problem found.
		bool         Unsupported = false;
		Instruction* FirstUnsupportedInst = nullptr;
		Value* FirstUnsupportedVal = nullptr;
		std::string  FirstUnsupportedWhy;
		std::string  FailReason;

		// ── Public interface ─────────────────────────────────────────────────

		StringRef getFailReason() const { return FailReason; }

		/// Set the per-function opcode permutation map before calling run().
		void setOpcodeMap(const VMOpcodeMap* M) { OpMap = M; }

		/// P3-B: configure branch-target blinding. saltFull is the full 32-bit
		/// per-function salt (SaltConst); on is the blindTargets knob.
		void setTargetBlind(uint32_t saltFull, bool on) { SaltFull = saltFull; BlindTargets = on; }

		/// Compile F into bytecode.  Salt is the CTSalt byte used to XOR register
		/// index bytes (0 when obfRegIdx is disabled).
		/// Returns false on failure; FailReason is populated.
		bool run(Function& F, uint8_t Salt, const DataLayout& DL);

	private:
		uint8_t            Salt = 0;
		const DataLayout* DL = nullptr;
		const VMOpcodeMap* OpMap = nullptr;
		uint32_t           SaltFull = 0;
		bool               BlindTargets = false;

		// P3-B: compile-time branch-target blinding key mix. Mirrors VMImpl::tgtKeyIR
		// op-for-op; distinct constants from ksByteCT (Layer-1 keystream) so the two
		// blinding layers don't share a constant.
		static uint32_t tgtKeyCT(uint32_t salt) {
			uint32_t k = salt ^ 0x2545F491u;
			k *= 0x9E3779B1u;
			k ^= k >> 16;
			return k;
		}

		// ── Idempotent slot allocation (safe to call in both passes) ─────────

		uint8_t newVR(Value* V) {
			auto It = VR.find(V);
			if (It != VR.end()) return It->second;
			if (NVR >= 250) {
				Unsupported = true;
				if (FailReason.empty()) FailReason = "vreg file overflow (>250 slots)";
				return kInvalidSlot;
			}
			uint8_t S = NVR++;
			VR[V] = S;
			return S;
		}

		uint8_t newVR64(Value* V) {
			auto It = VR64.find(V);
			if (It != VR64.end()) return It->second;
			if (NVR64 >= 250) {
				Unsupported = true;
				if (FailReason.empty()) FailReason = "vreg64 file overflow (>250 slots)";
				return kInvalidSlot;
			}
			uint8_t S = NVR64++;
			VR64[V] = S;
			return S;
		}


		uint8_t newPR(Value* V) {
			auto It = PR.find(V);
			if (It != PR.end()) return It->second;
			if (NPR >= 250) {
				Unsupported = true;
				if (FailReason.empty()) FailReason = "preg file overflow (>250 slots)";
				return kInvalidSlot;
			}
			uint8_t S = NPR++;
			PR[V] = S;
			return S;
		}

		// ── Float register slot allocation ───────────────────────
		//
		// The freg file holds f64 (double) values.  f32 values from the LLVM IR
		// are widened to f64 on slot assignment and narrowed to f32 on STORE_F /
		// RET_F by the handler, transparently to the bytecode encoding.

		uint8_t newFR(Value* V) {
			auto It = FR.find(V);
			if (It != FR.end()) return It->second;
			if (NFR >= 250) {
				Unsupported = true;
				if (FailReason.empty()) FailReason = "freg file overflow (>250 slots)";
				return kInvalidSlot;
			}
			uint8_t S = NFR++;
			FR[V] = S;
			return S;
		}

		uint8_t xorSalt(uint8_t S) const { return S ^ Salt; }

		void setFail(StringRef R) { if (FailReason.empty()) FailReason = R.str(); }

		std::string describeUnsupported() const {
			std::string S;
			raw_string_ostream OS(S);
			if (!FirstUnsupportedWhy.empty())
				OS << FirstUnsupportedWhy << ": ";
			if (FirstUnsupportedInst)
				FirstUnsupportedInst->print(OS);
			else if (FirstUnsupportedVal)
				FirstUnsupportedVal->print(OS);
			else
				OS << "<unknown>";
			OS.flush();
			for (char& C : S) if (C == '\n' || C == '\r') C = ' ';
			return S;
		}

		void markUnsupported(Instruction* I, StringRef Why = "unsupported instruction") {
			Unsupported = true;
			if (!FirstUnsupportedInst && !FirstUnsupportedVal) {
				FirstUnsupportedInst = I;
				FirstUnsupportedWhy = Why.str();
			}
		}

		void markUnsupportedValue(Value* V, StringRef Why = "unsupported value") {
			Unsupported = true;
			if (!FirstUnsupportedInst && !FirstUnsupportedVal) {
				FirstUnsupportedVal = V;
				FirstUnsupportedWhy = Why.str();
			}
		}

		// ── Slot resolution with constant materialisation ────────────────────

		// resolve vreg slot, materialising ConstantInt on first use
		uint8_t vr(Value* V) {
			if (auto* CI = dyn_cast<ConstantInt>(V)) {
				if (CI->getType()->getIntegerBitWidth() > 32) { markUnsupportedValue(V); return 0; }
				auto It = VR.find(V);
				if (It != VR.end()) return It->second;
				uint8_t S = newVR(V);
				ImmLoads.push_back({ S, CI });
				return S;
			}
			auto It = VR.find(V);
			assert(It != VR.end() && "vr(): untracked value");
			return It->second;
		}

		uint8_t vr64(Value* V) {
			if (auto* CI = dyn_cast<ConstantInt>(V)) {
				if (!CI->getType()->isIntegerTy(64)) { markUnsupportedValue(V); return 0; }
				auto It = VR64.find(V);
				if (It != VR64.end()) return It->second;
				uint8_t S = newVR64(V);
				ImmLoads64.push_back({ S, CI });
				return S;
			}
			auto It = VR64.find(V);
			assert(It != VR64.end() && "vr64(): untracked value");
			return It->second;
		}

		// resolve preg slot, materialising ptr constant on first use
		uint8_t pr(Value* V) {
			auto It = PR.find(V);
			if (It != PR.end()) return It->second;
			assert(isa<Constant>(V) && "pr(): untracked non-const ptr");
			uint8_t S = newPR(V);
			PtrLoads.push_back({ S, V });
			return S;
		}

		// ── [Step 01.1] Float constant materialisation ───────────────────────
		//
		// resolve freg slot, materialising ConstantFP on first use.
		// Both f32 and f64 ConstantFP values are accepted — the handler widens
		// f32 to f64 when loading the slot via OP_LOADI_F (ImmLoadsF path).

		uint8_t fr(Value* V) {
			if (auto* CFP = dyn_cast<ConstantFP>(V)) {
				Type* Ty = CFP->getType();
				if (!Ty->isFloatTy() && !Ty->isDoubleTy()) {
					markUnsupportedValue(V, "unsupported FP constant type (not f32/f64)");
					return 0;
				}
				auto It = FR.find(V);
				if (It != FR.end()) return It->second;
				uint8_t S = newFR(V);
				ImmLoadsF.push_back({ S, CFP });
				return S;
			}
			auto It = FR.find(V);
			assert(It != FR.end() && "fr(): untracked float value");
			return It->second;
		}

		uint8_t callee(Value* C) {
			for (unsigned I = 0; I < CalleeTab.size(); ++I) if (CalleeTab[I] == C) return (uint8_t)I;
			assert(CalleeTab.size() < 252); CalleeTab.push_back(C);
			return (uint8_t)(CalleeTab.size() - 1);
		}

		// 6.2: callee registration with its FunctionType.
		uint8_t callee(Value* C, FunctionType* FTy) {
			// Vararg callees are never deduplicated: each call site has a
			// unique concrete FTy (arg count may differ between call sites).
			if (!FTy->isVarArg())
				for (unsigned I = 0; I < CalleeTab.size(); ++I) if (CalleeTab[I] == C) return (uint8_t)I;
			assert(CalleeTab.size() < 252); CalleeTab.push_back(C); CalleeFTyTab.push_back(FTy);
			return (uint8_t)(CalleeTab.size() - 1);
		}

		// ── Bytecode emission primitives ──────────────────────────────────────

		uint8_t encOp(VMOp Op) const { return OpMap ? OpMap->encode(Op) : (uint8_t)Op; }
		void bop(VMOp Op) { b8(encOp(Op)); }

		void     b8(uint8_t v) { BC.push_back(v); }
		void     u16(uint16_t v) { b8(v & 0xFF); b8(v >> 8); }
		void     u32(uint32_t v) { b8(v); b8(v >> 8); b8(v >> 16); b8(v >> 24); }
		uint32_t ip() const { return (uint32_t)BC.size(); }

		/// [Step 01.1] Emit an f64 value as 8 bytes, little-endian IEEE-754.
		/// Used by OP_LOADI_F during pass 2 (emit).
		void f64(double V) {
			uint64_t Bits;
			static_assert(sizeof(Bits) == sizeof(V), "f64 size mismatch");
			std::memcpy(&Bits, &V, 8);
			b8((uint8_t)(Bits));
			b8((uint8_t)(Bits >> 8));
			b8((uint8_t)(Bits >> 16));
			b8((uint8_t)(Bits >> 24));
			b8((uint8_t)(Bits >> 32));
			b8((uint8_t)(Bits >> 40));
			b8((uint8_t)(Bits >> 48));
			b8((uint8_t)(Bits >> 56));
		}

		void emit(BasicBlock* BB);
		void emit(Instruction* I);

		// ── Pass 1: sizing (kept for reference; unused by run() after Phase 2) ────────────────
		uint32_t isize(Instruction* I);
		uint32_t bsize(BasicBlock* BB);

	private:
		// ── Forward-branch fixup table ────────────────────────────────────────────────────────
		// fixup_u32() emits a 4-byte placeholder (0x00000000) and records its
		// offset so the patch loop in run() can fill in the resolved BlockIP.
		struct Fixup { uint32_t Offset; BasicBlock* Target; };
		SmallVector<Fixup, 32> Fixups;

		void fixup_u32(BasicBlock* BB) {
			Fixups.push_back({ ip(), BB });
			u32(0);  // placeholder — overwritten by run() patch loop
		}
	};

} // namespace llvm