#pragma once
#include "llvm/Transforms/Obfuscator/LLVMCompat.h"

#include "llvm/IR/PassManager.h"

namespace llvm {

	class ObfDumpConfigPass : public ObfPassInfoMixin<ObfDumpConfigPass> {
	public:
		PreservedAnalyses run(Module& M, ModuleAnalysisManager& MAM);
		static bool isRequired() { return true; }
	};

} // namespace llvm