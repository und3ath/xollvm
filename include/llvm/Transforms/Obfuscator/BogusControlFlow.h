#pragma once
#include "llvm/Transforms/Obfuscator/LLVMCompat.h"
#include "llvm/IR/PassManager.h"

namespace llvm
{
	class BogusControlFlowPass : public ObfPassInfoMixin<BogusControlFlowPass>
	{
	public:
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM);
		static bool isRequired() { return true; }
	};
} // namespace llvm

