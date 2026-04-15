#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm {

	/// AntiOptimizationShieldPass — runs as the last function pass in the
	/// obfuscation pipeline (before adec).
	///
	/// Purpose: harden obfuscated IR so that subsequent optimization passes
	/// (especially -O2 / -O3) cannot undo the obfuscation.
	///
	/// Techniques:
	///   1. Volatile barrier injection: wrap "fragile" values (opaque-pred
	///      results, state variables, MBA intermediaries) with volatile
	///      store→load round-trips so InstCombine/GVN/SCCP can't fold them.
	///
	///   2. Opaque identity insertions: replace `add x, 0` / `xor x, 0` /
	///      `mul x, 1` patterns (residue from MBA/sub) with volatile-anchored
	///      equivalents that evaluate to the same value at runtime but are
	///      opaque to the optimizer.
	///
	///   3. Anti-SCCP barriers: for constant-looking values that are actually
	///      runtime-computed, insert a minimal volatile fence so SCCP can't
	///      propagate them.
	///
	///   4. Dead-store protection: mark stores to state variables (fla.state,
	///      bcf.*, sdiff.*) as volatile if they aren't already, preventing
	///      DSE (Dead Store Elimination) from removing them.
	///
	///   5. CFG anti-simplification: insert opaque-predicate guards on
	///      critical edges that SimplifyCFG would otherwise collapse.
	///
	///   6. Metadata annotation: attach `!obf.shield` metadata to hardened
	///      instructions (stripped by a late cleanup if desired).
	///
	class AntiOptimizationShieldPass
		: public PassInfoMixin<AntiOptimizationShieldPass> {
	public:
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM);
		static bool isRequired() { return true; }
	};

} // namespace llvm