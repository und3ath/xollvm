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
//   - MBAObfuscation.cpp  (MbaCtx constructs one; runMBA() uses it — 5-opcode)
//   - VMPass_Impl.cpp     (hardenVMEngine() creates one to replace inline helpers)
//   - VMPass handler-variant diversification (indexed pool, 7-opcode)
//
// Rng conventions
//   - R (stored by reference, passed at construction) is the "noise Rng" used for
//     inflation, slot seed, and zero-term shape.
//   - applyMBARecursive / applyLayeredWindow accept an explicit Rng& RecRng so the
//     caller can forward its dedicated "recursion Rng" and preserve determinism.
//
// Identity pool (23 total; queryable via poolSize/applyByIndex)
//   Add: 4  (add, addAlt, addAlt2, addAlt3)
//   Sub: 4  (sub, subAlt, subAlt2, subAlt3)
//   And: 3  (bitwiseAnd, bitwiseAndAlt, bitwiseAndAlt2)
//   Or : 3  (bitwiseOr,  bitwiseOrAlt,  bitwiseOrAlt2)
//   Xor: 3  (bitwiseXor, bitwiseXorAlt, bitwiseXorAlt2)
//   Mul: 3  (mul, mulAlt, mulAlt2 — indexed pool only; not dispatched by MBA pass)
//   Shl: 3  (shl, shlAlt, shlAlt2 — const-RHS only; indexed pool only)
//
// Only Add/Sub/And/Or/Xor participate in isTargetOpcode /
// applyPrimary / applyAlternate. Mul and Shl are indexed-pool-only,
// intended for VM handler-variant diversification.
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
		Value* addAlt3(IRBuilder<>& B, Value* A, Value* V); ///< (x - ~y) - 1

		// ---- Sub: x - y ----
		Value* sub(IRBuilder<>& B, Value* A, Value* V);     ///< (x^y) - 2*(~x & y)
		Value* subAlt(IRBuilder<>& B, Value* A, Value* V);  ///< (x & ~y) - (~x & y)
		Value* subAlt2(IRBuilder<>& B, Value* A, Value* V); ///< x + ~y + 1  [VM variant]
		Value* subAlt3(IRBuilder<>& B, Value* A, Value* V); ///< ~(~x + y)

		// ---- And: x & y ----
		Value* bitwiseAnd(IRBuilder<>& B, Value* A, Value* V);     ///< (x+y) - (x|y)
		Value* bitwiseAndAlt(IRBuilder<>& B, Value* A, Value* V);  ///< ~(~x | ~y)  De Morgan
		Value* bitwiseAndAlt2(IRBuilder<>& B, Value* A, Value* V); ///< (x|y) - (x^y)  (bit-disjoint identity)

		// ---- Or: x | y ----
		Value* bitwiseOr(IRBuilder<>& B, Value* A, Value* V);     ///< (x&y) + (x^y)
		Value* bitwiseOrAlt(IRBuilder<>& B, Value* A, Value* V);  ///< (x+y) - (x&y)
		Value* bitwiseOrAlt2(IRBuilder<>& B, Value* A, Value* V); ///< (x^y) | (x&y)  [VM variant]

		// ---- Xor: x ^ y ----
		Value* bitwiseXor(IRBuilder<>& B, Value* A, Value* V);     ///< (x|y) - (x&y)
		Value* bitwiseXorAlt(IRBuilder<>& B, Value* A, Value* V);  ///< (~x & y) | (x & ~y)
		Value* bitwiseXorAlt2(IRBuilder<>& B, Value* A, Value* V); ///< (x|y) & ~(x&y)

		// ---- Mul: x * y ----
		Value* mul(IRBuilder<>& B, Value* A, Value* V);      ///< x * y
		Value* mulAlt(IRBuilder<>& B, Value* A, Value* V);   ///< -((-x) * y)
		Value* mulAlt2(IRBuilder<>& B, Value* A, Value* V);  ///< x*(y&0xFFFF) + (x*(y>>>16))<<16  (split-mul; i32+)

		// ---- Shl: x << n (const n only) ----
		// For these three, @p N MUST be a ConstantInt (compile-time shift amount).
		// Callers ensure this at their site; passing a non-const shift will trigger
		// a nullptr return from applyByIndex for opcode Shl.
		Value* shl(IRBuilder<>& B, Value* A, Value* N);      ///< x << n
		Value* shlAlt(IRBuilder<>& B, Value* A, Value* N);   ///< x * (1<<n)
		Value* shlAlt2(IRBuilder<>& B, Value* A, Value* N);  ///< ~((~x) << n) - ((1<<n) - 1)

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

		// =========================================================================
		// Indexed pool access (handler-variant diversification)
		// =========================================================================
		// Unlike applyPrimary/applyAlternate, these give positional access into the
		// full identity pool for a given opcode and do NOT bump STATISTIC counters
		// (callers like VM handler-variant diversification churn through many
		// indices per opcode and must not inflate the MBA pass's own stats).

		/// Number of distinct identities available for opcode @p Op
		/// (e.g. 3 for Add: add/addAlt/addAlt2). Returns 0 if @p Op is not a
		/// target opcode (see isTargetOpcode).
		unsigned poolSize(Instruction::BinaryOps Op) const;

		/// Apply the @p K-th identity from @p Op's pool to (A op V).
		/// @p K is folded modulo poolSize(Op), so any unsigned K is valid and
		/// cycles through the pool. Returns nullptr if @p Op is not a target
		/// opcode. Does NOT bump STATISTIC counters (see above).
		/// For Shl, V must be a ConstantInt (compile-time shift amount);
		/// nullptr otherwise.
		Value* applyByIndex(IRBuilder<>& B, Instruction::BinaryOps Op,
			Value* A, Value* V, unsigned K);

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
		// Input-derived zeros (V1) — memory-free runtime zeros
		// =========================================================================
		// Unlike the inflation helpers above, these build a runtime zero purely from
		// in-scope operands (X, Y) — no volatile noise slot. The value is 0 for all
		// inputs, but the zeroness is a nonlinear-lifted MBA identity engineered to
		// exceed an SMT solver's time budget: there is no alloca for a value-set
		// analysis to fold, and the bitwise-inside-multiply structure does not
		// linearize, so the solver must bit-blast the whole lift (timeout-strong).

		/// Number of distinct input-derived zero forms. Forms use only the two
		/// InstCombine-resistant MBA spellings (add-form (x^y)+2(x&y), sub-form
		/// (x&~y)-(~x&y)) under a nonlinear lift, so they survive an attacker's -O2.
		unsigned inputZeroPoolSize() const;

		/// Build an input-derived runtime zero from @p X, @p Y. @p K selects the form
		/// modulo inputZeroPoolSize(). Result has X's type. Returns nullptr if the
		/// operand types are unusable (non-integer, mismatched, or width < 2).
		Value* inputDerivedZero(IRBuilder<>& B, Value* X, Value* Y, unsigned K);

		/// Add an input-derived zero (built from @p Orig's operands, form @p K) to
		/// @p Cur. Memory-free analogue of addNonLinearZero. Returns @p Cur unchanged
		/// if operands are unusable.
		Value* addInputDerivedZero(IRBuilder<>& B, BinaryOperator& Orig,
			Value* Cur, unsigned K);

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