#pragma once
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/Transforms/Obfuscator/Utils.h"
#include <string>

namespace llvm::obf {

	class ObfRepairSSAFunctionPass : public llvm::PassInfoMixin<ObfRepairSSAFunctionPass> {
		std::string Label;

	public:
		explicit ObfRepairSSAFunctionPass(llvm::StringRef L = {}) : Label(L.str()) {}

		llvm::PreservedAnalyses run(llvm::Function& F, llvm::FunctionAnalysisManager&) {
			bool Changed = llvm::obf::repairSSA(F);
			(void)Label; 
			return Changed ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all();
		}

		static bool isRequired() { return true; }
	};

} // namespace llvm::obf
