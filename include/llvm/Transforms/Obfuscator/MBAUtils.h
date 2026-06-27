#pragma once
// ============================================================================
// MbaUtils.h — Project-wide MBA (Mixed Boolean/Arithmetic) factory
//
// Mirrors OpaqueUtils in design:
//   - Constructed with (Module&, Rng& noiseRng, StringRef slotName, Options)
//   - Manages a per-function volatile i32 noise slot (lazy, cached per function)
//   - All methods take an IRBuilder<>& at their insertion point
//
// Intended callers
//   - MBAObfuscation.cpp  (MbaCtx constructs one; runMBA() uses it)
//   - VMPass_Impl.cpp     (hardenVMEngine() creates one to replace inline helpers)
//
// Rng conventions
//   - R (stored by reference, passed at construction) is the "noise Rng" used for
//     inflation, slot seed, and zero-term shape.
//   - applyMBARecursive / applyLayeredWindow accept an explicit Rng& RecRng so the
//     caller can forward its dedicated "recursion Rng" and preserve determinism.
// ============================================================================

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

namespace llvm::obf {

	class Rng;

	class MbaUtils final {
	public:

		// =========================================================================
		// Options — advanced inflation knobs
		// =========================================================================

		struct Options {
			// ---- Linear term inflation ----
			unsigned LinearTermsMin = 6;    ///< Min additive zero-terms injected per site.
			unsigned LinearTermsMax = 10;   ///< Max (must be >= LinearTermsMin).

			// ---- Nonlinear zero addend ----
			bool     EnableNonLinear = true;
			unsigned NonLinearWeight = 20; ///< Per-site probability 0-100.

			// ---- Layered MBA ----
			bool     EnableLayered = true;
			unsigned LayeredWindow = 48; ///< Backward scan window (instruction count).
			unsigned LayeredBudget = 1;  ///< Max rewrites per applyLayeredWindow call.
		};

		// =========================================================================
		// Construction
		// =========================================================================

		/// @param M         Module — needed for DataLayout + alloca insertion context.
		/// @param R         Noise RNG: inflation shapes, slot seed, zero-term choice.
		///                  Caller retains ownership; must outlive this object.
		/// @param SlotName  Per-function volatile i32 alloca name (pass-specific).
		///                  e.g. "obf.mba.noise.i32", "obf.vm.mba.noise.i32".
		/// @param Opts      Advanced inflation knobs (safe defaults for most callers).
		MbaUtils(Module& M, Rng& R, StringRef SlotName, Options Opts);
		MbaUtils(Module& M, Rng& R, StringRef SlotName);
		// =========================================================================
		// Opcode filter
		// =========================================================================

		/// True for the five opcodes MbaUtils transforms: Add, Sub, And, Or, Xor.
		static bool isTargetOpcode(unsigned Op);

		// =========================================================================
		// Core Value-level transforms
		// =========================================================================
		// Each function rewrites (A op V) into an equivalent expression.
		// - Does NOT require a BinaryOperator (safe to call from VM pass / any context).
		// - Does NOT bump STATISTIC counters (use applyPrimary/applyAlternate for that).
		// - All returned values have the same type and runtime value as (A op V).

		// ---- Add: x + y ----
		Value* add(IRBuilder<>& B, Value* A, Value* V);     ///< (x^y) + 2*(x&y)
		Value* addAlt(IRBuilder<>& B, Value* A, Value* V);  ///< (x|y) + (x&y)
		Value* addAlt2(IRBuilder<>& B, Value* A, Value* V); ///< 2*(x|y) - (x^y)   [VM variant]

		// ---- Sub: x - y ----
		Value* sub(IRBuilder<>& B, Value* A, Value* V);     ///< (x^y) - 2*(~x & y)
		Value* subAlt(IRBuilder<>& B, Value* A, Value* V);  ///< (x & ~y) - (~x & y)
		Value* subAlt2(IRBuilder<>& B, Value* A, Value* V); ///< x + ~y + 1  [VM variant]

		// ---- And: x & y ----
		Value* bitwiseAnd(IRBuilder<>& B, Value* A, Value* V);    ///< (x+y) - (x|y)
		Value* bitwiseAndAlt(IRBuilder<>& B, Value* A, Value* V); ///< ~(~x | ~y)  De Morgan

		// ---- Or: x | y ----
		Value* bitwiseOr(IRBuilder<>& B, Value* A, Value* V);     ///< (x&y) + (x^y)
		Value* bitwiseOrAlt(IRBuilder<>& B, Value* A, Value* V);  ///< (x+y) - (x&y)
		Value* bitwiseOrAlt2(IRBuilder<>& B, Value* A, Value* V); ///< (x^y) | (x&y)  [VM variant]

		// ---- Xor: x ^ y ----
		Value* bitwiseXor(IRBuilder<>& B, Value* A, Value* V);    ///< (x|y) - (x&y)
		Value* bitwiseXorAlt(IRBuilder<>& B, Value* A, Value* V); ///< (~x & y) | (x & ~y)

		// =========================================================================
		// BinaryOperator-level wrappers  (MBAPass primary interface)
		// =========================================================================
		// Extract operands from BO, dispatch to the correct Value-level transform,
		// and bump the per-opcode STATISTIC counter.

		/// Apply the primary transform for BO's opcode. Bumps statistics.
		/// Returns nullptr if opcode is not supported.
		Value* applyPrimary(IRBuilder<>& B, BinaryOperator* BO);

		/// Apply the alternate transform for BO's opcode. Bumps statistics.
		/// Returns nullptr if opcode is not supported.
		Value* applyAlternate(IRBuilder<>& B, BinaryOperator* BO);

		/// Recursively apply MBA up to @p depth levels.
		/// @p RecRng  Caller's dedicated recursion RNG (e.g. MbaCtx::RecRng).
		///            Forwarding a separate RecRng preserves the exact per-pass
		///            random sequence relative to the original MbaImpl code.
		Value* applyMBARecursive(IRBuilder<>& B, BinaryOperator* BO,
			unsigned depth, Rng& RecRng);

		// =========================================================================
		// Advanced inflation helpers
		// =========================================================================
		// All use the internal R (noise Rng) and the managed per-function noise slot.

		/// Add LinearTermsMin..Max runtime-zero linear terms to @p Base.
		/// @p DepthHint  Reduces term count to avoid IR explosion when recursing deeply.
		Value* inflateLinear(IRBuilder<>& B, Value* Base, unsigned DepthHint);

		/// Add a nonlinear (mul / urem-based) runtime-zero term to @p Cur.
		/// @p Orig  Supplies original operands for constructing the term's expression.
		Value* addNonLinearZero(IRBuilder<>& B, BinaryOperator& Orig, Value* Cur);

		/// Add a high-degree (degree 4 or 5 polynomial) runtime-zero to @p Cur.
		Value* addHighDegreeZero(IRBuilder<>& B, BinaryOperator& Orig,
			Value* Cur, unsigned DepthHint);

		/// Add a mixed-mode (rotation + mixing + polynomial) runtime-zero to @p Cur.
		Value* addMixedModeZero(IRBuilder<>& B, BinaryOperator& Orig,
			Value* Cur, unsigned DepthHint);

		// =========================================================================
		// Layered MBA
		// =========================================================================

		/// Walk backward from @p Anchor (up to Opts.LayeredWindow instructions),
		/// collect eligible BinaryOperators, and rewrite up to Opts.LayeredBudget of
		/// them with one level of MBA + inflation.
		/// @p Skip     Excluded from the scan (typically the BO just transformed).
		/// @p RecRng   Forwarded to applyMBARecursive for inner rewrites.
		void applyLayeredWindow(Instruction* Anchor, Instruction* Skip,
			unsigned DepthHint, Rng& RecRng);

		// =========================================================================
		// Noise slot access
		// =========================================================================

		/// Return (creating if necessary) the per-function volatile i32 noise slot.
		/// Internally called by all inflation helpers.
		AllocaInst* getOrCreateNoiseSlot(IRBuilder<>& B);

	private:
		Module& M;
		Rng& R;       ///< Noise RNG (alias to caller-owned Rng).
		std::string SlotName;
		Options   Opts;

		// Per-function cache — reset whenever a different function is detected.
		Function* CachedFn = nullptr;
		AllocaInst* NoiseSlot = nullptr;

		/// Ensure the noise slot exists for the function at B's insert point.
		AllocaInst* ensureNoiseSlot(IRBuilder<>& B);

		/// Inline poison-sensitive flag check used by applyLayeredWindow.
		static bool hasPoisonSensitiveFlags(const BinaryOperator& BO);
	};

} // namespace llvm::obf