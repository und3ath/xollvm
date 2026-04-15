#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm {

	class StringEncryptionPass : public PassInfoMixin<StringEncryptionPass> {
	public:
		PreservedAnalyses run(Module& M, ModuleAnalysisManager& AM);
		static bool isRequired() { return true; }
	};

} // namespace llvm