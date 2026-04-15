#pragma once
#include "llvm/IR/PassManager.h"

namespace llvm {
	class AntiDecompilerPass : public PassInfoMixin<AntiDecompilerPass> {
	public:
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM);
		static bool isRequired() { return true; }
	};
} // namespace llvm