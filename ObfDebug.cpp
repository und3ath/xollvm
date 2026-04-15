#include "llvm/Transforms/Obfuscator/ObfDebug.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/ObfuscationPipeline.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <vector>

using namespace llvm;

static void printList(raw_ostream& OS, const std::vector<std::string>& V) {
	bool First = true;
	for (const auto& S : V) {
		if (!First) OS << ' ';
		First = false;
		OS << S;
	}
}

PreservedAnalyses ObfDumpConfigPass::run(Module& M, ModuleAnalysisManager& MAM) {
	const auto& Cache = MAM.getResult<ObfuscationAnnotationAnalysis>(M);

	outs() << "OBF-MODULE-SEED " << format_hex(Cache.ModuleSeed, 18) << "\n";

	// Deterministic iteration: sort by function name.
	std::vector<const Function*> Funcs;
	Funcs.reserve(Cache.PerFunction.size());
	for (const auto& KV : Cache.PerFunction)
		Funcs.push_back(KV.first);
	std::sort(Funcs.begin(), Funcs.end(),
		[](const Function* A, const Function* B) {
			return A->getName() < B->getName();
		});

	for (const Function* F : Funcs) {
		const auto& Cfg = Cache.getConfig(*F);
		outs() << "OBF-CONFIG-FN " << F->getName() << "\n";

		auto Enabled = Cfg.getEnabledPasses();
		outs() << "  enabled: ";
		printList(outs(), Enabled);
		outs() << "\n";

		auto Ordered = ObfuscationPipeline::getRecommendedOrder(Enabled);
		outs() << "  ordered: ";
		printList(outs(), Ordered);
		outs() << "\n";

		// Stable param printing: sort keys.
		for (const auto& PC : Cfg.passes) {
			if (!PC.enabled)
				continue;
			outs() << "  pass." << PC.passName << ":";
			std::vector<std::string> Keys;
			Keys.reserve(PC.params.size());
			for (const auto& KV : PC.params)
				Keys.push_back(KV.first);
			std::sort(Keys.begin(), Keys.end());
			for (const auto& K : Keys)
				outs() << " " << K << "=" << PC.params.at(K);
			outs() << "\n";
		}
	}

	return PreservedAnalyses::all();
}