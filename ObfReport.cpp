#include "llvm/Transforms/Obfuscator/ObfReport.h"

#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringRef.h"

#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include "llvm/Support/JSON.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Obfuscator/IRBudget.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <limits>

using namespace llvm;

namespace llvm::obf {

	void ObfReportSink::add(FunctionReport&& R) { Functions.push_back(std::move(R)); }

	static double clamp01(double V) {
		if (V < 0.0)
			return 0.0;
		if (V > 1.0)
			return 1.0;
		return V;
	}

	bool isReportEnabled() {
		return !std::string(ObfReportDir).empty() || !std::string(ObfReportJson).empty();
	}

	std::string getReportDir() {
		return std::string(ObfReportDir);
	}

	std::string getReportJsonPath() {
		std::string J = std::string(ObfReportJson);
		if (!J.empty())
			return J;

		std::string D = std::string(ObfReportDir);
		if (D.empty())
			return "";

		SmallString<256> P(D);
		sys::path::append(P, "obf_report.json");
		return std::string(P.str());
	}

	std::string sanitizePathComponent(StringRef S) {
		std::string Out;
		Out.reserve(S.size());
		for (char C : S) {
			unsigned char UC = static_cast<unsigned char>(C);
			if (std::isalnum(UC) || C == '_' || C == '-' || C == '.')
				Out.push_back(C);
			else
				Out.push_back('_');
		}
		if (Out.empty())
			Out = "unnamed";
		return Out;
	}

	static bool isObfMarkedInst(const Instruction& I) {
		if (I.hasName() && I.getName().starts_with("obf."))
			return true;
		if (I.getMetadata("obf.shield"))
			return true;
		return false;
	}

	DifficultyComponents computeDifficultyComponents(const Function& F) {
		DifficultyComponents C;

		C.Insts = llvm::obf::countInstructions(F);

		unsigned Blocks = 0;
		unsigned Edges = 0;
		for (const BasicBlock& BB : F) {
			++Blocks;
			Edges += succ_size(&BB);

			if (const auto* Br = dyn_cast<BranchInst>(BB.getTerminator()))
				if (Br->isConditional())
					++C.ConditionalBranches;

			for (const Instruction& I : BB) {
				if (isa<ICmpInst>(I) && I.hasName() && I.getName().starts_with("obf."))
					++C.OpaquePredicates;

				if (isa<IndirectBrInst>(I))
					++C.IndirectBrs;
				if (isa<CallBrInst>(I))
					++C.CallBrs;

				if (const auto* CB = dyn_cast<CallBase>(&I)) {
					if (!CB->getCalledFunction())
						++C.IndirectCalls;
				}

				if (I.hasName() && I.getName().starts_with("obf.mba."))
					++C.MbaNodes;
			}
		}

		C.Blocks = Blocks;
		C.Edges = Edges;

		// Cyclomatic complexity: E - N + 2 (for a single-entry graph).
		if (Blocks == 0)
			C.Cyclomatic = 0;
		else {
			int64_t CC = (int64_t)Edges - (int64_t)Blocks + 2;
			C.Cyclomatic = (unsigned)std::max<int64_t>(1, CC);
		}

		// MBA depth: marker-based SSA expression depth among instructions whose names
		// start with "obf.mba.".
		DenseMap<const Instruction*, unsigned> Memo;

		auto Depth = [&](auto&& Self, const Instruction* I) -> unsigned {
			if (!I)
				return 0;
			if (!(I->hasName() && I->getName().starts_with("obf.mba.")))
				return 0;

			auto It = Memo.find(I);
			if (It != Memo.end())
				return It->second;

			unsigned D = 1;
			for (const Use& U : I->operands()) {
				if (const auto* OpI = dyn_cast<Instruction>(U.get())) {
					unsigned OD = Self(Self, OpI);
					if (OD)
						D = std::max(D, 1 + OD);
				}
			}

			Memo[I] = D;
			return D;
			};

		double SumDepth = 0.0;
		unsigned MaxDepth = 0;
		unsigned Count = 0;

		for (const BasicBlock& BB : F) {
			for (const Instruction& I : BB) {
				if (!(I.hasName() && I.getName().starts_with("obf.mba.")))
					continue;
				unsigned D = Depth(Depth, &I);
				MaxDepth = std::max(MaxDepth, D);
				SumDepth += (double)D;
				++Count;
			}
		}

		C.MbaMaxDepth = MaxDepth;
		C.MbaAvgDepth = Count ? (SumDepth / (double)Count) : 0.0;

		return C;
	}

	DifficultyScore scoreDifficulty(const DifficultyComponents& Before,
		const DifficultyComponents& After) {
		DifficultyScore S;

		S.CyclomaticBefore = Before.Cyclomatic;
		S.CyclomaticAfter = After.Cyclomatic;
		S.CyclomaticDelta = (int64_t)After.Cyclomatic - (int64_t)Before.Cyclomatic;

		S.OpaquePredicates = After.OpaquePredicates;
		S.OpaquePer100Insts = After.Insts ? (After.OpaquePredicates * 100.0) / (double)After.Insts
			: 0.0;

		S.MbaNodes = After.MbaNodes;
		S.MbaMaxDepth = After.MbaMaxDepth;
		S.MbaAvgDepth = After.MbaAvgDepth;

		S.IndirectBrs = After.IndirectBrs;
		S.CallBrs = After.CallBrs;
		S.IndirectCalls = After.IndirectCalls;

		// Heuristic score: [0,100]. Tune for monotonicity and stability.
		double CCInc = std::max<int64_t>(0, S.CyclomaticDelta);
		double CC = clamp01(CCInc / 40.0);

		double Opaque = clamp01(S.OpaquePer100Insts / 8.0);

		double Mba = clamp01((double)S.MbaMaxDepth / 12.0);

		double Ind = clamp01((double)S.IndirectBrs / 8.0);

		S.Score = 100.0 * (0.30 * CC + 0.25 * Opaque + 0.25 * Mba + 0.20 * Ind);
		return S;
	}

	static std::string dotEscapeLabel(StringRef S) {
		std::string Out;
		Out.reserve(S.size());
		for (char C : S) {
			switch (C) {
			case '\\': Out += "\\\\"; break;
			case '"':  Out += "\\\""; break;
			case '\n': Out += "\\n"; break;
			case '\r': break;
			case '\t': Out += "\\t"; break;
			default:    Out += C; break;
			}
		}
		return Out;
	}

	Error writeCfgDotSnapshot(const Function& F, StringRef AbsDotPath,
		const DenseMap<const BasicBlock*, unsigned>* PrevInsts,
		DenseMap<const BasicBlock*, unsigned>& OutInsts) {
		// Ensure parent directory exists.
		SmallString<256> Parent(sys::path::parent_path(AbsDotPath));
		if (!Parent.empty()) {
			if (std::error_code EC = sys::fs::create_directories(Parent))
				return createStringError(EC, "create_directories('%s')", Parent.c_str());
		}

		std::error_code EC;
		raw_fd_ostream OS(AbsDotPath, EC, sys::fs::OF_Text);
		if (EC)
			return createStringError(EC, "open('%s')", AbsDotPath.str().c_str());

		// Assign deterministic node IDs (bb0, bb1, ...).
		DenseMap<const BasicBlock*, unsigned> Idx;
		unsigned I = 0;
		for (const BasicBlock& BB : F)
			Idx[&BB] = I++;

		auto NodeId = [&](const BasicBlock* BB) -> std::string {
			return ("bb" + std::to_string(Idx.lookup(BB)));
			};

		auto BlockLabel = [&](const BasicBlock& BB) -> std::string {
			std::string Name = BB.hasName() ? BB.getName().str() : NodeId(&BB);
			return dotEscapeLabel(Name) + "\\ninsts: " + std::to_string(BB.size());
			};

		auto BlockHasObf = [&](const BasicBlock& BB) -> bool {
			for (const Instruction& Inst : BB)
				if (isObfMarkedInst(Inst))
					return true;
			return false;
			};

		OS << "digraph \"cfg.\" {\n";
		OS << "  graph [fontname=\"monospace\", labelloc=t, label=\"CFG: "
			<< dotEscapeLabel(F.getName()) << "\"];\n";
		OS << "  node  [shape=box, style=\"rounded,filled\", fontname=\"monospace\"];\n";
		OS << "  edge  [fontname=\"monospace\"];\n\n";

		for (const BasicBlock& BB : F) {
			const BasicBlock* BBP = &BB;
			unsigned Insts = BB.size();
			OutInsts[BBP] = Insts;

			bool IsNew = false;
			bool IsChanged = false;
			if (PrevInsts) {
				auto It = PrevInsts->find(BBP);
				if (It == PrevInsts->end())
					IsNew = true;
				else if (It->second != Insts)
					IsChanged = true;
			}

			bool HasObf = BlockHasObf(BB);

			// Visual encoding (simple, stable):
			// - new blocks: palegreen fill
			// - changed blocks: khaki fill
			// - blocks containing obf-marked instructions: blue border
			std::string Fill = "white";
			if (IsNew)
				Fill = "palegreen";
			else if (IsChanged)
				Fill = "khaki";

			std::string Border = HasObf ? "deepskyblue4" : "gray50";
			unsigned PenW = HasObf ? 2 : 1;

			OS << "  " << NodeId(BBP)
				<< " [label=\"" << BlockLabel(BB) << "\""
				<< ", fillcolor=\"" << Fill << "\""
				<< ", color=\"" << Border << "\""
				<< ", penwidth=" << PenW
				<< "];\n";
		}

		OS << "\n";

		for (const BasicBlock& BB : F) {
			const BasicBlock* From = &BB;
			for (const BasicBlock* To : successors(From)) {
				OS << "  " << NodeId(From) << " -> " << NodeId(To) << ";\n";
			}
		}

		OS << "}\n";
		return Error::success();
	}

	static json::Object toJson(const DifficultyScore& D) {
		json::Object O;
		O["score"] = D.Score;
		O["cyclomatic_before"] = D.CyclomaticBefore;
		O["cyclomatic_after"] = D.CyclomaticAfter;
		O["cyclomatic_delta"] = D.CyclomaticDelta;
		O["opaque_predicates"] = D.OpaquePredicates;
		O["opaque_per_100_insts"] = D.OpaquePer100Insts;
		O["mba_nodes"] = D.MbaNodes;
		O["mba_max_depth"] = D.MbaMaxDepth;
		O["mba_avg_depth"] = D.MbaAvgDepth;
		O["indirect_branches"] = D.IndirectBrs;
		O["callbrs"] = D.CallBrs;
		O["indirect_calls"] = D.IndirectCalls;
		return O;
	}

	static json::Object toJson(const PassReport& P) {
		json::Object O;
		O["id"] = P.Id;
		O["seed"] = (int64_t)P.Seed;
		O["status"] = P.Skipped ? "skipped" : "ran";
		if (P.Skipped) {
			if (!P.SkipReason.empty())
				O["skip_reason"] = P.SkipReason;
		}
		else {
			O["changed"] = P.Changed;
		}
		O["insts_before"] = (int64_t)P.InstsBefore;
		O["insts_after"] = (int64_t)P.InstsAfter;
		O["delta_insts"] = (int64_t)P.InstsAfter - (int64_t)P.InstsBefore;
		O["budget_util_after"] = P.BudgetUtilAfter;
		return O;
	}

	static json::Object toJson(const FunctionReport& R) {
		json::Object O;

		O["name"] = R.Name;
		O["declaration"] = R.Declaration;

		if (R.Skipped) {
			O["skipped"] = true;
			if (!R.SkipReason.empty())
				O["skip_reason"] = R.SkipReason;
		}
		else {
			O["skipped"] = false;
		}

		json::Object Seed;
		Seed["base"] = (int64_t)R.BaseSeed;
		Seed["module"] = (int64_t)R.ModuleSeed;
		Seed["function"] = (int64_t)R.FunctionSeed;
		O["seed"] = std::move(Seed);

		json::Object Insts;
		Insts["before"] = (int64_t)R.InstsBefore;
		Insts["after"] = (int64_t)R.InstsAfter;
		O["insts"] = std::move(Insts);

		json::Object Budget;
		Budget["enabled"] = R.BudgetEnabled;
		if (R.BudgetEnabled) {
			Budget["limit"] = (int64_t)R.BudgetLimit;
			Budget["remaining"] = (int64_t)R.BudgetRemaining;
			Budget["utilization"] = R.BudgetUtilization;
		}
		O["budget"] = std::move(Budget);

		json::Array Passes;
		for (const auto& P : R.Passes)
			Passes.push_back(toJson(P));
		O["passes"] = std::move(Passes);

		O["difficulty"] = toJson(R.Difficulty);

		// Artifacts
		if (!R.CfgBeforeDot.empty() || !R.CfgAfterDot.empty() || !R.CfgPerPass.empty()) {
			json::Object Art;
			json::Object Cfg;
			if (!R.CfgBeforeDot.empty())
				Cfg["before_dot"] = R.CfgBeforeDot;
			if (!R.CfgAfterDot.empty())
				Cfg["after_dot"] = R.CfgAfterDot;
			if (!R.CfgPerPass.empty()) {
				json::Array Stages;
				for (const auto& S : R.CfgPerPass) {
					json::Object SO;
					SO["pass"] = S.Pass;
					SO["after_dot"] = S.DotAfter;
					if (!S.DotDiff.empty())
						SO["diff_dot"] = S.DotDiff;
					Stages.push_back(std::move(SO));
				}
				Cfg["per_pass"] = std::move(Stages);
			}
			Art["cfg"] = std::move(Cfg);
			O["artifacts"] = std::move(Art);
		}

		return O;
	}

	Error maybeWriteObfReportJson(Module& M, ModuleAnalysisManager& MAM) {
		std::string JsonPath = getReportJsonPath();
		if (JsonPath.empty())
			return Error::success();

		auto& Sink = MAM.getResult<ObfReportAnalysis>(M);

		// Sort functions by name for deterministic output.
		std::vector<const FunctionReport*> Sorted;
		Sorted.reserve(Sink.Functions.size());
		for (const auto& FR : Sink.Functions)
			Sorted.push_back(&FR);
		std::sort(Sorted.begin(), Sorted.end(), [](const FunctionReport* A, const FunctionReport* B) {
			return A->Name < B->Name;
			});

		json::Object Root;
		Root["schema"] = "llvm_obfuscator.obf_map";
		Root["schema_version"] = (int64_t)kObfReportSchemaVersion;

		json::Object Mod;
		Mod["identifier"] = M.getModuleIdentifier();
		if (!M.getSourceFileName().empty())
			Mod["source_file"] = M.getSourceFileName();
		if (!M.getTargetTriple().empty())
			Mod["target_triple"] = M.getTargetTriple().getTriple();
		if (!M.getDataLayoutStr().empty())
			Mod["data_layout"] = M.getDataLayoutStr();
		Root["module"] = std::move(Mod);

		json::Array Funcs;
		for (const FunctionReport* FR : Sorted)
			Funcs.push_back(toJson(*FR));
		Root["functions"] = std::move(Funcs);

		// Ensure parent directory exists.
		if (JsonPath != "-") {
			SmallString<256> Parent(sys::path::parent_path(JsonPath));
			if (!Parent.empty()) {
				if (std::error_code EC = sys::fs::create_directories(Parent))
					return createStringError(EC, "create_directories('%s')", Parent.c_str());
			}
		}

		if (JsonPath == "-") {
			json::OStream J(outs(), 2);
			J.value(std::move(Root));
			outs() << "\n";
			return Error::success();
		}

		std::error_code EC;
		raw_fd_ostream OS(JsonPath, EC, sys::fs::OF_Text);
		if (EC)
			return createStringError(EC, "open('%s')", JsonPath.c_str());

		json::OStream J(OS, 2);
		J.value(std::move(Root));
		OS << "\n";
		return Error::success();
	}

} // namespace llvm::obf

namespace llvm {

	AnalysisKey ObfReportAnalysis::Key;

	ObfReportAnalysis::Result ObfReportAnalysis::run(Module&, ModuleAnalysisManager&) {
		// Start empty. Function passes append to the sink via the MAM proxy.
		return obf::ObfReportSink();
	}

} // namespace llvm