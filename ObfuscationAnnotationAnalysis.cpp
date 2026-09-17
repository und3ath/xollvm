#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/ADT/Hashing.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/Rng.h"
#include <random>


using namespace llvm;
AnalysisKey ObfuscationAnnotationAnalysis::Key;
uint64_t ObfuscationAnnotationCache::getFunctionSeed(const Function& F) const {
	// Stable across runs if ModuleSeed is stable.
	return llvm::obf::mix64(ModuleSeed ^ llvm::obf::fnv1a64(F.getName()) ^ 0x9E3779B97F4A7C15ull);
}
static uint64_t computeModuleSeed(const Module& M) {
	if (ObfSeed.getNumOccurrences() > 0)
		return ObfSeed;
	if (ObfDeterministic) {
		return llvm::obf::mix64(llvm::obf::fnv1a64(M.getModuleIdentifier()) ^ 0xD1B54A32D192ED03ull);
	}
	// Non-deterministic: OS entropy, mixed full-width so no draw's high bits
	// are discarded (the old shift-and-xor kept only ~16 bits of three draws).
	std::random_device rd;
	auto draw64 = [&] { return ((uint64_t)rd() << 32) | (uint64_t)rd(); };
	uint64_t s = llvm::obf::mix64(draw64());
	s = llvm::obf::mix64(s ^ draw64());
	return s;
}



ObfuscationAnnotationAnalysis::Result
ObfuscationAnnotationAnalysis::run(Module& M, ModuleAnalysisManager& MAM) {
	ObfuscationAnnotationCache Out;

	Out.ModuleSeed = computeModuleSeed(M);

	// Snapshot llvm.global.annotations initializer for content-based invalidation
	if (auto* GA = M.getGlobalVariable("llvm.global.annotations")) {
		Out.AnnotationsInit = GA->hasInitializer() ? GA->getInitializer() : nullptr;
	}
	else {
		Out.AnnotationsInit = nullptr;
	}

	for (Function& F : M) {
		if (F.isDeclaration())
			continue;

		ObfuscationConfig Cfg = AnnotationParser::parseAnnotations(&F);
		if (!Cfg.passes.empty())
			Out.PerFunction[&F] = std::move(Cfg);
	}

	return Out;
}