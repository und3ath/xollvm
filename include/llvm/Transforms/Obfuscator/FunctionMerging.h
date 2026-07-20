#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm {

	class FunctionMergingPass : public PassInfoMixin<FunctionMergingPass> {
	public:
		PreservedAnalyses run(Module& M, ModuleAnalysisManager& AM);
		static bool isRequired() { return true; }
	};

} // namespace llvm
