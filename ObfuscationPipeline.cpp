
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
#include "llvm/Transforms/Obfuscator/ConstantEncryption.h"
#include "llvm/Transforms/Obfuscator/SemanticDiffusion.h"
#include "llvm/Transforms/Obfuscator/StringEncryption.h"
#include "llvm/Transforms/Obfuscator/VirtualCall.h"
#include "llvm/Transforms/Obfuscator/ObfRepairSSA.h"
#include "llvm/Transforms/Obfuscator/VMPass.h"
#include "llvm/Support/ErrorHandling.h"
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

	// ConstEnc should run first (encrypts numeric constants before any
	// other pass rewrites the arithmetic around them).
	rules["constenc"] = PassOrderingRules{
		{},
		{"mba", "substitution", "vcall", "split", "sdiff", "bcf", "flattening", "shield"},
		{}
	};

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



	// Virtual calls must run *after* flattening: vcall converts direct
	// calls to indirect, but flattening bails out on functions that
	// already contain indirect calls (Cfg.AllowIndirect=false by
	// default). Sequencing flattening first lets both passes coexist
	// in combo pipelines under strict-skip enforcement.
	rules["vcall"] = PassOrderingRules{
		{"mba", "split", "sdiff", "bcf", "flattening"},
		{},
		{}
	};

	// Split should run before structural changes (vcall moved after flattening)
	rules["split"] = PassOrderingRules{
		{"mba", "substitution"},
		{"bcf", "flattening"},
		{}
	};

	// Semantic diffusion should happen before CFG-heavy passes.
	rules["sdiff"] = PassOrderingRules{
		{"mba", "substitution", "split"},
		{"bcf", "flattening"},
		{}
	};

	// BCF can run independently but better before flattening
	rules["bcf"] = PassOrderingRules{
		{"mba", "substitution", "split", "sdiff"},
		{"flattening"},
		{}
	};

	// Flattening should run before anti-decompiler. vcall must follow
	// flattening (see vcall rule above) so the flattening transformer
	// sees only direct calls.
	rules["flattening"] = PassOrderingRules{
		{"mba", "substitution", "split","sdiff", "bcf"},
		{"vcall", "adec"},
		{}
	};

	// Shield runs after all obfuscation but before adec.
	rules["shield"] = PassOrderingRules{
		{"mba", "substitution", "split", "sdiff", "bcf", "vcall", "flattening"},
		{"adec"},
		{}
	};

	// strenc is a module-only pass (StringEncryptionPass runs before the
	// function pipeline). The ordering below only affects display in
	// obf-dump-config and the meta-order tests — place it after all
	// CFG/IR-mutating passes and before adec to match real-world intent:
	// encrypt strings on already-obfuscated code, before final anti-decompiler.
	rules["strenc"] = PassOrderingRules{
		{"mba", "substitution", "split", "sdiff", "bcf", "vcall", "flattening", "shield"},
		{"adec"},
		{}
	};

	// Anti-decompiler runs last.
	rules["adec"] = PassOrderingRules{
		{"mba", "substitution", "split", "sdiff", "bcf", "vcall", "flattening", "shield", "strenc"},
		{},
		{}
	};

	rules["vm"] = PassOrderingRules{
		// vm rewrites the function body into a bytecode interpreter and
		// builds a static callee table. It must run *before* vcall —
		// after vcall the call sites have indirect (runtime) callees,
		// which vm cannot emit into its constant CalleeTab.
		/*before=*/ {"mba", "substitution", "split", "sdiff", "bcf"},
		/*after=*/  {"vcall", "shield", "adec"},
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

		// before: b runs before p  =>  edge b -> p
		for (const auto& b : r.before)
			addEdge(b, p);

		// after: a runs after p   =>  edge p -> a
		for (const auto& a : r.after)
			addEdge(p, a);
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

void ObfuscationPipeline::enforceConflicts(
	const std::vector<std::string>& passes,
	const std::unordered_map<std::string, PassOrderingRules>& rules) {

	std::unordered_set<std::string> enabled(passes.begin(), passes.end());
	for (const auto& p : enabled) {
		auto it = rules.find(p);
		if (it == rules.end())
			continue;
		for (const auto& c : it->second.conflicts) {
			if (!enabled.count(c))
				continue;
			// Stable ordering for the error message (avoids duplicate fatal
			// from the symmetric pair).
			if (p < c) {
				report_fatal_error(
					Twine("obfuscator: conflicting passes both enabled: '")
					+ p + "' and '" + c + "'",
					/*gen_crash_diag=*/false);
			}
		}
	}
}

void ObfuscationPipeline::validateExplicitOrder(
	std::vector<std::string>& cliOrder,
	const std::unordered_map<std::string, PassOrderingRules>& rules) {

	std::unordered_set<std::string> seen;
	std::vector<std::string> deduped;
	deduped.reserve(cliOrder.size());

	for (const auto& name : cliOrder) {
		if (rules.find(name) == rules.end()) {
			report_fatal_error(
				Twine("obfuscator: -obf-pipeline-ordering: unknown pass name '")
				+ name + "'",
				/*gen_crash_diag=*/false);
		}
		if (seen.insert(name).second)
			deduped.push_back(name);
	}
	cliOrder = std::move(deduped);
}

std::vector<std::string> ObfuscationPipeline::getPassOrder(
	const std::vector<std::string>& enabledPasses) {

	auto rules = getOrderingRules();

	// Conflict check covers both BUG-06 (topo path) and CLI override path:
	// if two mutually exclusive passes are enabled together, fail loud
	// regardless of which ordering mode is active.
	enforceConflicts(enabledPasses, rules);

	// Priority 1: explicit CLI order.
	std::string cliRaw = std::string(ObfPipelineOrdering);
	if (!cliRaw.empty()) {
		std::vector<std::string> cli = ParsePipelineOrdering(cliRaw);
		validateExplicitOrder(cli, rules);

		std::unordered_set<std::string> enabledSet(
			enabledPasses.begin(), enabledPasses.end());

		std::vector<std::string> result;
		result.reserve(enabledPasses.size());
		std::unordered_set<std::string> placed;

		// Emit CLI-listed passes that are actually enabled, in CLI order.
		for (const auto& name : cli) {
			if (enabledSet.count(name) && placed.insert(name).second)
				result.push_back(name);
			else if (!enabledSet.count(name) && ObfVerbose)
				errs() << "obfuscator: CLI-ordered pass '" << name
				       << "' not enabled for this function; skipping\n";
		}

		// Append remaining enabled passes in topo order so partial CLI lists
		// still get a sensible tail.
		std::vector<std::string> remaining;
		remaining.reserve(enabledPasses.size());
		for (const auto& name : enabledPasses)
			if (!placed.count(name))
				remaining.push_back(name);

		auto tail = topologicalSort(remaining, rules);
		for (const auto& name : tail)
			result.push_back(name);

		return result;
	}

	// Priority 2: per-annotation order verbatim.
	if (ObfPipelineOrderingAnn)
		return enabledPasses;

	// Priority 3: topological sort (default).
	return topologicalSort(enabledPasses, rules);
}

void ObfuscationPipeline::buildPipeline(FunctionPassManager& FPM,
	const ObfuscationConfig& config) {

	auto enabledPasses = config.getEnabledPasses();

	if (enabledPasses.empty()) {
		return;
	}

	auto orderedPasses = getPassOrder(enabledPasses);



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

		if (passName == "constenc") {
			add(ConstEncPass(), passName, false);
		}
		else if (passName == "mba") {
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

	auto orderedPasses = getPassOrder(enabledPasses);

	std::vector<ObfPassEntry> Entries;
	Entries.reserve(orderedPasses.size());

	for (const auto& passName : orderedPasses) {
		if (passName == "strenc")
			continue; // module pass only

		ObfPassEntry E;
		E.Name = passName;
		E.NeedsSSARepair = false;

		if (passName == "constenc") {
			E.Run = [](Function& F, FunctionAnalysisManager& AM) {
				return ConstEncPass().run(F, AM);
				};
		}
		else if (passName == "mba") {
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