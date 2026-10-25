#pragma once
#include "llvm/Transforms/Obfuscator/LLVMCompat.h"

#include "llvm/IR/PassManager.h"

namespace llvm {

	/// obf-metrics: prints per-function structural metrics (JSON lines) without
	/// modifying IR. Intended for regression tracking and strength proxies.
	class ObfMetricsPass : public ObfPassInfoMixin<ObfMetricsPass> {
	public:
		PreservedAnalyses run(Module& M, ModuleAnalysisManager& MAM);

		static bool isRequired() { return true; }
	};

} // namespace llvm