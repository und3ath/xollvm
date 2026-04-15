#pragma once

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

#include "llvm/IR/Module.h"

namespace llvm::obf {

	class Rng;

	/// Project-wide “opaque factory”.
	/// - Creates/reuses a per-function volatile i32 anchor seeded from entropy
	/// - Builds hardened true/false predicates (robust vs instcombine)
	/// - Builds unpredictable opaque booleans
	/// - Builds opaque constants (equals C at runtime)
	/// - Builds opaque zero offsets (useful for GEP/pointer obfuscation)
	/// - Builds hardened equality/inequality wrappers (useful for switch/compare hiding)
	class OpaqueUtils final {
	public:
		struct Options {
			bool EnableOpaqueConsts = true;   // opaqueI32Const, opaqueU32InRange
			bool EnableOpaqueBools = true;   // opaqueBool
			bool EnableHardPreds = true;   // hardTrue/hardFalse/randomHardTrue/False
			bool VolatileLoads = true;   // mark loads volatile


			// --- Enhanced constant predicates femilies --- 
			bool EnableMBAFamily = true; // (x^y)+2*(x&y) == x+y
			bool EnableModArithFamily = true; // modular arithmetic identities
			bool EnableHashFamily = true; // crafted hash collision identities
			bool EnablePtrFamily = true; // UB-safe pointer eq/ne family

			// 0 = light (legacy hardTrue/hardFalse only)
			// 1 = medium (adds MBA/ptr)
			// 2 = heavy (adds modular/hash + conjunct/or composition)
			// 3 = very heavy (extra noise wrapping)
			unsigned PredStrength = 1;

		};

		/// SlotName should be pass-specific to avoid accidental cross-pass coupling:
		/// e.g. "fla.opaque.salt.i32", "bcf.opaque.salt.i32".
		OpaqueUtils(Module& M, Rng& R, StringRef SlotName, Options Opts);
		OpaqueUtils(Module& M, Rng& R, StringRef SlotName);

		// --- Anchor / salt ---
		AllocaInst* getOrCreateVolatileI32Slot(IRBuilder<>& B);
		Value* loadVolatileI32(IRBuilder<>& B); // returns i32 (freeze(load volatile))

		// --- Hardened constant predicates ---
		Value* hardTrue(IRBuilder<>& B);   // returns i1, always true at runtime
		Value* hardFalse(IRBuilder<>& B);  // returns i1, always false at runtime

		/// Variety to avoid pattern signatures (still always true/false at runtime).
		Value* randomHardTrue(IRBuilder<>& B);
		Value* randomHardFalse(IRBuilder<>& B);


		/// Enhanced families with optional strength hint.
		/// - Uses multiple predicate families and composes them depending on PredStrength.
		/// - Context-sensitive: tries to reuse nearby i32 values first.
		Value* enhancedTrue(IRBuilder<>& B, unsigned StrengthHint = 0);
		Value* enhancedFalse(IRBuilder<>& B, unsigned StrengthHint = 0);


		// --- Unpredictable predicate (not a constant at compile-time) ---
		/// Returns i1 that is *not* provably constant (depends on volatile + entropy).
		Value* opaqueBool(IRBuilder<>& B);

		// --- Opaque constants ---
		/// If EnableOpaqueConsts=false -> ConstantInt(C)
		Value* opaqueI32Const(IRBuilder<>& B, uint32_t C);

		/// Returns i32(0) but anchored to volatile (useful for “add 0” style hiding).
		Value* opaqueZero32(IRBuilder<>& B);

		/// Returns i64(0) but anchored to volatile (useful for GEP offsets).
		Value* opaqueZero64(IRBuilder<>& B);

		/// Returns i32 in [0, MaxExclusive) with non-constant provenance (volatile+entropy).
		/// If MaxExclusive==0 -> returns ConstantInt(0).
		Value* opaqueU32InRange(IRBuilder<>& B, uint32_t MaxExclusive);

		// --- Hardened equality/inequality wrappers ---
		/// Returns (L == R) but wrapped through mixing and volatile anchor.
		Value* hardEqI32(IRBuilder<>& B, Value* L, Value* R);

		/// Returns (L != R) but wrapped through mixing and volatile anchor.
		Value* hardNeI32(IRBuilder<>& B, Value* L, Value* R);

		// --- Convenience “opaque select” wrappers ---
		/// Uses a hard-false condition (so runtime result is AlwaysFalseSide), but not obvious.
		Value* selectHardFalse(IRBuilder<>& B, Value* AlwaysTrueSide, Value* AlwaysFalseSide);

		/// Uses a hard-true condition (so runtime result is AlwaysTrueSide), but not obvious.
		Value* selectHardTrue(IRBuilder<>& B, Value* AlwaysTrueSide, Value* AlwaysFalseSide);

		StringRef getSlotName() const { return SlotName; }
		Options getOptions() const { return Opts; }

	private:
		Module& M;
		Rng& R;
		StringRef SlotName;
		Options Opts;

		// Per-instance cache (safe even if reused across functions)
		Function* CachedFn = nullptr;
		AllocaInst* CachedSlot = nullptr;

		// Mixing primitives (intentionally not “obvious” but UB-safe)
		Value* mix32_v1(IRBuilder<>& B, Value* V, uint32_t K0, uint32_t K1);
		Value* mix32_v2(IRBuilder<>& B, Value* V, uint32_t K0, uint32_t K1);
		Value* mix32_v3(IRBuilder<>& B, Value* V, uint32_t K0, uint32_t K1);
		Value* pickMix(IRBuilder<>& B, Value* V, uint32_t K0, uint32_t K1, unsigned Variant);
		Value* loadEntropyI32(IRBuilder<>& B); // wraps your getObfEntropyI32

		// --- Enhanced predicate internals ---
		Value* pickI32FromContext(IRBuilder<>& B);
		Value* legacySaltEntropyTrue(IRBuilder<>& B);
		Value* legacySaltEntropyFalse(IRBuilder<>& B);

		Value* predMBATrue(IRBuilder<>& B);
		Value* predMBAFalse(IRBuilder<>& B);

		Value* predModTrue(IRBuilder<>& B);
		Value* predModFalse(IRBuilder<>& B);

		Value* predHashTrue(IRBuilder<>& B);
		Value* predHashFalse(IRBuilder<>& B);

		// UB-safe pointer families (no pointer ordering comparisons)
		Value* predPtrEqTrue(IRBuilder<>& B);
		Value* predPtrEqFalse(IRBuilder<>& B);

		// Lazy family generators — avoid eager evaluation of all families
		Value* getStateI32(IRBuilder<>& B);
		Value* generateTrueFamily(IRBuilder<>& B, unsigned FamilyIdx, unsigned Strength);
		Value* generateFalseFamily(IRBuilder<>& B, unsigned FamilyIdx, unsigned Strength);

	};

} // namespace llvm::obf
