#pragma once
#include "llvm/Transforms/Obfuscator/LLVMCompat.h"

#include "llvm/IR/PassManager.h"

namespace llvm {
	struct ConstEncPass : public ObfPassInfoMixin<ConstEncPass> {
	public:
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM);
		static bool isRequired() { return true; }
	};

} // namespace llvm
