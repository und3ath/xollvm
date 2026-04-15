#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm
{
	class SubstitutionPass : public PassInfoMixin<SubstitutionPass> {
	public:
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM);
		static bool isRequired() { return true; }
	};
} // namespace llvm


