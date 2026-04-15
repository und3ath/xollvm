
#include "llvm/Transforms/Obfuscator/ObfuscationPipeline.h"
#include "llvm/Transforms/Obfuscator/AntiOptimizationShield.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/ObfVerify.h"
#include "llvm/Transforms/Obfuscator/AntiDecompiler.h"
#include "llvm/Transforms/Obfuscator/BogusControlFlow.h"
#include "llvm/Transforms/Obfuscator/Flattening.h"
#include "llvm/Transforms/Obfuscator/SplitBasicBlock.h"
#include "llvm/Transforms/Obfuscator/Substitution.h"
#include "llvm/Transforms/Obfuscator/MBAObfuscation.h"
#include "llvm/Transforms/Obfuscator/SemanticDiffusion.h"
#include "llvm/Transforms/Obfuscator/StringEncryption.h"
#include "llvm/Transforms/Obfuscator/VirtualCall.h"
#include "llvm/Transforms/Obfuscator/ObfRepairSSA.h"
#include "llvm/Transforms/Obfuscator/VMPass.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <unordered_set>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <functional>

using namespace llvm;

std::unordered_map<std::string, ObfuscationPipeline::PassOrderingRules>
ObfuscationPipeline::getOrderingRules() {
	std::unordered_map<std::string, PassOrderingRules> rules;

	// MBA should run early (modifies arithmetic)
	rules["mba"] = PassOrderingRules{
		{},
		{"substitution", "split", "bcf", "flattening"},
		{}
	};

	// Substitution should run early
	rules["substitution"] = PassOrderingRules{
		{"mba"},
		{"split", "bcf", "flattening"},
		{}
	};



	// Virtual calls should run early
	rules["vcall"] = PassOrderingRules{
		{"mba"},
		{"split", "bcf", "flattening"},
		{}
	};

	// Split should run before structural changes
	rules["split"] = PassOrderingRules{
		{"mba", "substitution", "vcall"},
		{"bcf", "flattening"},
		{}
	};

	// Semantic diffusion should happen before CFG-heavy passes.
	rules["sdiff"] = PassOrderingRules{
		{"mba", "substitution", "vcall", "split"},
		{"bcf", "flattening"},
		{}
	};

	// BCF can run independently but better before flattening
	rules["bcf"] = PassOrderingRules{
		{"mba", "substitution", "split", "sdiff", "vcall"},
		{"flattening"},
		{}
	};

	// Flattening should run before anti-decompiler
	rules["flattening"] = PassOrderingRules{
		{"mba", "substitution", "split","sdiff", "bcf", "vcall"},
		{"adec"},
		{}
	};

	// Shield runs after all obfuscation but before adec.
	rules["shield"] = PassOrderingRules{
		{"mba", "substitution", "split", "sdiff", "bcf", "vcall", "flattening"},
		{"adec"},
		{}
	};

	// Anti-decompiler runs last.
	rules["adec"] = PassOrderingRules{
		{"mba", "substitution", "split", "sdiff", "bcf", "vcall", "flattening", "shield"},
		{},
		{}
	};

	rules["vm"] = PassOrderingRules{
		/*before=*/ {"mba", "substitution", "vcall", "split", "sdiff", "bcf"},
		/*after=*/  {"shield", "adec"},
		/*conflicts=*/ {"flattening"},  // both restructure the whole CFG
    };

	return rules;
}

static bool containsPass(const std::vector<std::string>& sortedUnique,
	const std::string& p) {
	return std::binary_search(sortedUnique.begin(), sortedUnique.end(), p);
}

std::vector<std::string> ObfuscationPipeline::topologicalSort(
	const std::vector<std::string>& passes,
	const std::unordered_map<std::string, PassOrderingRules>& rules) {

	std::vector<std::string> nodes = passes;
	std::sort(nodes.begin(), nodes.end());
	nodes.erase(std::unique(nodes.begin(), nodes.end()), nodes.end());

	std::map<std::string, std::set<std::string>> adj;
	std::map<std::string, unsigned> indeg;

	for (const auto& n : nodes) {
		adj[n];
		indeg[n] = 0;
	}

	auto addEdge = [&](const std::string& u, const std::string& v) {
		if (u == v)
			return;
		if (!containsPass(nodes, u) || !containsPass(nodes, v))
			return;

		// IMPORTANT: only increment indegree if edge is new
		if (adj[u].insert(v).second) {
			indeg[v]++;
		}
		};

	for (const auto& p : nodes) {
		auto it = rules.find(p);
		if (it == rules.end())
			continue;

		const PassOrderingRules& r = it->second;

		// after: a -> p
		for (const auto& a : r.after)
			addEdge(a, p);

		// before: p -> b
		for (const auto& b : r.before)
			addEdge(p, b);
	}

	std::set<std::string> ready;
	for (const auto& n : nodes) {
		if (indeg[n] == 0)
			ready.insert(n);
	}

	std::vector<std::string> out;
	out.reserve(nodes.size());

	while (!ready.empty()) {
		std::string u = *ready.begin();
		ready.erase(ready.begin());
		out.push_back(u);

		for (const auto& v : adj[u]) {
			auto& d = indeg[v];
			if (d > 0)
				--d;
			if (d == 0)
				ready.insert(v);
		}
	}

	if (out.size() != nodes.size()) {
		std::set<std::string> seen(out.begin(), out.end());
		for (const auto& n : nodes)
			if (!seen.count(n))
				out.push_back(n);
	}

	return out;
}

std::vector<std::string> ObfuscationPipeline::getRecommendedOrder(
	const std::vector<std::string>& requestedPasses) {

	auto rules = getOrderingRules();
	return topologicalSort(requestedPasses, rules);
}

void ObfuscationPipeline::buildPipeline(FunctionPassManager& FPM,
	const ObfuscationConfig& config) {

	auto enabledPasses = config.getEnabledPasses();

	if (enabledPasses.empty()) {
		return;
	}

	auto orderedPasses = getRecommendedOrder(enabledPasses);



	if (ObfVerbose)
	{
		errs() << "Building obfuscation pipeline: ";
		for (const auto& pass : orderedPasses)
			errs() << pass << " ";
		errs() << "\n";
	}

	auto add = [&](auto Pass, llvm::StringRef Label, bool RepairSSA)
		{
			FPM.addPass(std::move(Pass));
			if (RepairSSA)
				FPM.addPass(llvm::obf::ObfRepairSSAFunctionPass(Label));
			if (ObfVerify)
				FPM.addPass(llvm::obf::ObfVerifyFunctionPass(Label));
		};

	if (ObfVerify)
		FPM.addPass(llvm::obf::ObfVerifyFunctionPass("pre"));

	// Add passes in order
	for (const auto& passName : orderedPasses) {
		if (passName == "strenc") {
			continue; // module pass only
		}

		if (passName == "mba") {
			add(MBAPass(), passName, false);
		}
		else if (passName == "substitution") {
			add(SubstitutionPass(), passName, false);
		}
		else if (passName == "vcall") {
			add(VirtualCallPass(), passName, false);
		}
		else if (passName == "split") {
			add(SplitBasicBlockPass(), passName, false);
		}
		else if (passName == "sdiff")
		{
			add(SemanticDiffusionPass(), passName, false);
		}
		else if (passName == "bcf") {
			add(BogusControlFlowPass(), passName, false);
		}
		else if (passName == "flattening") {
			add(FlatteningPass(), passName, false);
		}
		else if (passName == "adec") {
			add(AntiDecompilerPass(), passName, false);
		}
		else if (passName == "shield") {
			add(AntiOptimizationShieldPass(), passName, false);	
		}
		else if (passName == "vm") {
			add(VMPass(), passName, false);
		}
	}

	if (ObfVerify)
		FPM.addPass(llvm::obf::ObfVerifyFunctionPass("final"));
}



std::vector<ObfPassEntry> ObfuscationPipeline::getPassEntries(
	const ObfuscationConfig& config) {

	auto enabledPasses = config.getEnabledPasses();
	if (enabledPasses.empty())
		return {};

	auto orderedPasses = getRecommendedOrder(enabledPasses);

	std::vector<ObfPassEntry> Entries;
	Entries.reserve(orderedPasses.size());

	for (const auto& passName : orderedPasses) {
		if (passName == "strenc")
			continue; // module pass only

		ObfPassEntry E;
		E.Name = passName;
		E.NeedsSSARepair = false;

		if (passName == "mba") {
			E.Run = [](Function& F, FunctionAnalysisManager& AM) {
				return MBAPass().run(F, AM);
				};
		}
		else if (passName == "substitution") {
			E.Run = [](Function& F, FunctionAnalysisManager& AM) {
				return SubstitutionPass().run(F, AM);
				};
		}
		else if (passName == "vcall") {
			E.Run = [](Function& F, FunctionAnalysisManager& AM) {
				return VirtualCallPass().run(F, AM);
				};
		}
		else if (passName == "split") {
			E.Run = [](Function& F, FunctionAnalysisManager& AM) {
				return SplitBasicBlockPass().run(F, AM);
				};
		}
		else if (passName == "sdiff") {
			E.Run = [](Function& F, FunctionAnalysisManager& AM) {
				return SemanticDiffusionPass().run(F, AM);
				};
		}
		else if (passName == "bcf") {
			E.Run = [](Function& F, FunctionAnalysisManager& AM) {
				return BogusControlFlowPass().run(F, AM);
				};
		}
		else if (passName == "flattening") {
			E.Run = [](Function& F, FunctionAnalysisManager& AM) {
				return FlatteningPass().run(F, AM);
				};
		}
		else if (passName == "adec") {
			E.Run = [](Function& F, FunctionAnalysisManager& AM) {
				return AntiDecompilerPass().run(F, AM);
				};
		}
		else if (passName == "shield") {
			E.Run = [](Function& F, FunctionAnalysisManager& AM) {
				return AntiOptimizationShieldPass().run(F, AM);
				};
		}
		else if (passName == "vm") {
			E.Run = [](Function& F, FunctionAnalysisManager& AM) {
				return VMPass().run(F, AM);
				};
			E.NeedsSSARepair = true;   // restructures CFG aggressively
		}
		else {
			continue; // unknown pass, skip
		}

		Entries.push_back(std::move(E));
	}

	return Entries;
}