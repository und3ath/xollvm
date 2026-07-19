#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm {
	struct ConstEncPass : public PassInfoMixin<ConstEncPass> {
	public:
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM);
		static bool isRequired() { return true; }
	};

} // namespace llvm
