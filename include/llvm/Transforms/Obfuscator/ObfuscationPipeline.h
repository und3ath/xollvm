#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include <functional>
#include <vector>
#include <string>

namespace llvm {

	/// A single pass to run in the obfuscation pipeline.
	/// This is used by the budget-aware driver to run passes one-by-one instead
	/// of through an opaque FunctionPassManager.
	struct ObfPassEntry {
		std::string Name;

		/// Functor that runs the pass and returns PreservedAnalyses.
		std::function<PreservedAnalyses(Function&, FunctionAnalysisManager&)> Run;

		/// If true, run SSA repair after this pass.
		bool NeedsSSARepair = false;
	};

	class ObfuscationPipeline {
	public:
		// Build a function pass pipeline based on configuration (legacy).
		static void buildPipeline(FunctionPassManager& FPM,
			const ObfuscationConfig& config);

		/// Build an ordered list of pass entries for budget-aware execution.
		/// Each entry can be run individually, with budget checks between them.
		static std::vector<ObfPassEntry> getPassEntries(
			const ObfuscationConfig& config);

		// Get recommended pass ordering
		static std::vector<std::string> getRecommendedOrder(
			const std::vector<std::string>& requestedPasses);

	private:
		// Pass dependencies and ordering rules
		struct PassOrderingRules {
			// Passes that should run before this one
			std::vector<std::string> before;
			// Passes that should run after this one
			std::vector<std::string> after;
			// Passes that conflict with this one
			std::vector<std::string> conflicts;
		};

		static std::unordered_map<std::string, PassOrderingRules> getOrderingRules();

		// Topological sort for pass ordering
		static std::vector<std::string> topologicalSort(
			const std::vector<std::string>& passes,
			const std::unordered_map<std::string, PassOrderingRules>& rules);
	};

} // namespace llvm