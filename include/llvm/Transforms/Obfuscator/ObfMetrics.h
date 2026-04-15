#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm {

	/// obf-metrics: prints per-function structural metrics (JSON lines) without
	/// modifying IR. Intended for regression tracking and strength proxies.
	class ObfMetricsPass : public PassInfoMixin<ObfMetricsPass> {
	public:
		PreservedAnalyses run(Module& M, ModuleAnalysisManager& MAM);

		static bool isRequired() { return true; }
	};

} // namespace llvm