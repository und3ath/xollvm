#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm {



	class VirtualCallPass : public PassInfoMixin<VirtualCallPass> {
	public:
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM);
		static bool isRequired() { return true; }
	};

} // namespace llvm

