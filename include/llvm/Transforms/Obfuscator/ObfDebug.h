#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm {

	class ObfDumpConfigPass : public PassInfoMixin<ObfDumpConfigPass> {
	public:
		PreservedAnalyses run(Module& M, ModuleAnalysisManager& MAM);
		static bool isRequired() { return true; }
	};

} // namespace llvm