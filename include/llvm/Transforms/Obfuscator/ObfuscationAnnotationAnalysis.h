#pragma once
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"

#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"

namespace llvm {

	struct ObfuscationAnnotationCache
	{
		DenseMap<const Function*, ObfuscationConfig> PerFunction;
		// Deterministic seed base for this module (filled by analysis)
		uint64_t ModuleSeed = 0;

		const Constant* AnnotationsInit = nullptr;

		const ObfuscationConfig& getConfig(const Function& F) const
		{
			static const ObfuscationConfig Empty{};
			auto It = PerFunction.find(&F);
			return It == PerFunction.end() ? Empty : It->second;
		}

		bool hasAnyConfig() const { return !PerFunction.empty(); }
		// Stable per-function seed derived from ModuleSeed + function name
		uint64_t getFunctionSeed(const Function& F) const;

		bool invalidate(Module& M, const PreservedAnalyses&,
			ModuleAnalysisManager::Invalidator&) {
			const GlobalVariable* GA =
				M.getGlobalVariable("llvm.global.annotations");
			const Constant* CurInit =
				(GA && GA->hasInitializer()) ? GA->getInitializer() : nullptr;

			// If analysis recorded no snapshot, be conservative and keep it
			// valid. (But ideally set AnnotationsInit in run()).
			if (!AnnotationsInit)
				return false;

			// Invalidate only if annotations initializer changed (array
			// replaced).
			return CurInit != AnnotationsInit;
		}



	};
	class ObfuscationAnnotationAnalysis
		: public AnalysisInfoMixin<ObfuscationAnnotationAnalysis> {
	public:
		using Result = ObfuscationAnnotationCache;
		Result run(Module& M, ModuleAnalysisManager& MAM);
	private:
		friend AnalysisInfoMixin<ObfuscationAnnotationAnalysis>;
		static AnalysisKey Key;
	};


	inline const ObfuscationConfig& getObfConfig(Function& F,
		FunctionAnalysisManager& FAM) {
		static const ObfuscationConfig Empty{};
		auto& MAMProxy = FAM.getResult<ModuleAnalysisManagerFunctionProxy>(F);
		auto* Cache =
			MAMProxy.getCachedResult<ObfuscationAnnotationAnalysis>(*F.getParent());
		return Cache ? Cache->getConfig(F) : Empty;

	}


	inline const ObfuscationAnnotationCache& getObfCache(Function& F, FunctionAnalysisManager& FAM) {
		auto& MAMProxy = FAM.getResult<ModuleAnalysisManagerFunctionProxy>(F);
		auto* Cache =
			MAMProxy.getCachedResult<ObfuscationAnnotationAnalysis>(*F.getParent());
		assert(Cache &&
			"ObfuscationAnnotationAnalysis must be computed at module level");
		return *Cache;
	}
} // namespace llvm 