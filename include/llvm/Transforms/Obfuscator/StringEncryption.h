#pragma once
#include "llvm/Transforms/Obfuscator/LLVMCompat.h"

#include "llvm/IR/PassManager.h"

namespace llvm {

	class StringEncryptionPass : public ObfPassInfoMixin<StringEncryptionPass> {
	public:
		PreservedAnalyses run(Module& M, ModuleAnalysisManager& AM);
		static bool isRequired() { return true; }
	};

} // namespace llvm