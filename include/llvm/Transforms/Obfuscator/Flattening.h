#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm {
	class FlatteningPass : public PassInfoMixin<FlatteningPass> {
	public:
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM);
		static bool isRequired() { return true; }

	};
} // namespace llvm


