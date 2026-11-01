#pragma once
#include "llvm/Transforms/Obfuscator/LLVMCompat.h"

#include "llvm/IR/PassManager.h"

namespace llvm {
	class SplitBasicBlockPass : public ObfPassInfoMixin<SplitBasicBlockPass> {
	public:
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM);
		static bool isRequired() { return true; }
	};
} // namespace llvm

