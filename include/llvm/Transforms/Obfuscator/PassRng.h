#pragma once

#include <cstdint>
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/Rng.h"

namespace llvm::obf {

	// Derive a deterministic seed for a given “domain” (pass id)
	inline uint64_t deriveSeed(uint64_t Base, llvm::StringRef Domain) {
		// Domain hash is stable (FNV-1a), mix is explicit (SplitMix step)
		return mix64(Base ^ fnv1a64(Domain) ^ 0xD1B54A32D192ED03ull);
	}

	inline Rng makeFunctionPassRng(llvm::Function& F,
		llvm::FunctionAnalysisManager& FAM,
		llvm::StringRef CanonPassId) {
		const auto& Cache = getObfCache(F, FAM);
		uint64_t FnSeed = Cache.getFunctionSeed(F);
		return Rng(deriveSeed(FnSeed, CanonPassId));
	}

	inline Rng makeModulePassRng(llvm::Module& M,
		llvm::ModuleAnalysisManager& MAM,
		llvm::StringRef CanonPassId) {
		auto& Cache = MAM.getResult<llvm::ObfuscationAnnotationAnalysis>(M);
		return Rng(deriveSeed(Cache.ModuleSeed, CanonPassId));
	}

} // namespace llvm::obf
