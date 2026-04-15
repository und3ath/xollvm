#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm {

	// Function pass: semantic diffusion via volatile paired masking on integer operands.
	// Canonical form (x^k)^k is simplified by instcombine even if k is unknown.
	// We instead use two *distinct* volatile-load keys K1 and K2 that are equal at runtime
	// (same local slot, no store between), but not provably equal for the optimizer:
	//   x' = (x ^ K1) ^ K2   (runtime: K1==K2 => x'==x)
	class SemanticDiffusionPass : public PassInfoMixin<SemanticDiffusionPass> {
	public:
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM);
	};

} // namespace llvm