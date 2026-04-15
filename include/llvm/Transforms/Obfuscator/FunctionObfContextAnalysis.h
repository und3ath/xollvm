#pragma once
#include "llvm/IR/PassManager.h"
#include "FunctionObfContext.h"

namespace llvm {

	class FunctionObfContextAnalysis
		: public AnalysisInfoMixin<FunctionObfContextAnalysis> {
	public:
		using Result = std::unique_ptr<FunctionObfContext>;

		Result run(Function& F, FunctionAnalysisManager& AM);

	private:
		friend AnalysisInfoMixin<FunctionObfContextAnalysis>;
		static AnalysisKey Key;
	};

} // namespace llvm
