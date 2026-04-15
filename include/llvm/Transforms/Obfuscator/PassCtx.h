#pragma once
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/PassRng.h"

namespace llvm::obf {

	struct FuncPassCtx {
		llvm::Module& M;
		llvm::Function& F;
		llvm::FunctionAnalysisManager& AM;
		const llvm::ObfuscationAnnotationCache& Ann;
		const llvm::ObfuscationConfig& OC;

		llvm::StringRef PassId;
		uint64_t MasterSeed;
		uint64_t FnSeed;
		uint64_t PassSeed;

		llvm::obf::Rng R; // root RNG for the pass

		FuncPassCtx(llvm::Function& F, llvm::FunctionAnalysisManager& AM,
			llvm::StringRef CanonPassId)
			: M(*F.getParent()), F(F), AM(AM),
			Ann(getObfCache(F, AM)),
			OC(Ann.getConfig(F)),
			PassId(CanonPassId),
			MasterSeed(Ann.ModuleSeed),
			FnSeed(Ann.getFunctionSeed(F)),
			PassSeed(llvm::obf::deriveSeed(FnSeed, CanonPassId)),
			R(llvm::obf::Rng(PassSeed)) {
		}
	};


	struct ModPassCtx {
		llvm::Module& M;
		llvm::ModuleAnalysisManager& MAM;
		const llvm::ObfuscationAnnotationCache& Ann;
		llvm::obf::Rng R;

		ModPassCtx(llvm::Module& M, llvm::ModuleAnalysisManager& MAM,
			llvm::StringRef CanonPassId)
			: M(M), MAM(MAM),
			Ann(MAM.getResult<llvm::ObfuscationAnnotationAnalysis>(M)),
			R(makeModulePassRng(M, MAM, CanonPassId)) {
		}
	};

} // namespace llvm::obf
