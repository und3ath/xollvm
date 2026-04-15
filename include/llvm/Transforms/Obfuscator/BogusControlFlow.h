#pragma once
#include "llvm/IR/PassManager.h"

namespace llvm
{
	class BogusControlFlowPass : public PassInfoMixin<BogusControlFlowPass>
	{
	public:
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM);
		static bool isRequired() { return true; }
	};
} // namespace llvm

