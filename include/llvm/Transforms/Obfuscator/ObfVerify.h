#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include <string>

namespace llvm::obf {

	class ObfVerifyFunctionPass : public llvm::PassInfoMixin<ObfVerifyFunctionPass> {
		std::string Label;

	public:
		explicit ObfVerifyFunctionPass(llvm::StringRef L = {}) : Label(L.str()) {}

		llvm::PreservedAnalyses run(llvm::Function& F, llvm::FunctionAnalysisManager&) {
			if (!llvm::verifyFunction(F, &llvm::errs()))
				return llvm::PreservedAnalyses::all();

			std::string Msg = "Obfuscator produced invalid IR";
			if (!Label.empty())
				Msg += " after '" + Label + "'";
			Msg += " in function '" + F.getName().str() + "'";
			llvm::report_fatal_error(llvm::StringRef(Msg), /*gen_crash_diag=*/false);
		}

		static bool isRequired() { return true; }
	};

	class ObfVerifyModulePass : public llvm::PassInfoMixin<ObfVerifyModulePass> {
		std::string Label;

	public:
		explicit ObfVerifyModulePass(llvm::StringRef L = {}) : Label(L.str()) {}

		llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {
			if (!llvm::verifyModule(M, &llvm::errs()))
				return llvm::PreservedAnalyses::all();

			std::string Msg = "Obfuscator produced invalid IR";
			if (!Label.empty())
				Msg += " after '" + Label + "'";
			Msg += " in module '" + M.getName().str() + "'";
			llvm::report_fatal_error(llvm::StringRef(Msg), /*gen_crash_diag=*/false);
		}

		static bool isRequired() { return true; }
	};

} // namespace llvm::obf