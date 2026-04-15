#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm {
	class MBAPass : public PassInfoMixin<MBAPass> {
	public:
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM);
		static bool isRequired() { return true; }
	};

} // namespace llvm

