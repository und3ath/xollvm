#include "llvm/Transforms/Obfuscator/ObfMetrics.h"

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

static cl::opt<std::string> ObfMetricsFunction(
	"obf-metrics-function",
	cl::desc("Emit metrics only for this function name (exact match)."),
	cl::init(""));

static cl::opt<bool> ObfMetricsIncludeDeclarations(
	"obf-metrics-include-decls",
	cl::desc("Also emit metrics for function declarations."),
	cl::init(false));

namespace {

	struct FnMetrics {
		std::string Name;
		unsigned Blocks = 0;
		unsigned Edges = 0;
		unsigned Insts = 0;
		unsigned PHIs = 0;

		unsigned Allocas = 0;
		unsigned Loads = 0;
		unsigned Stores = 0;

		unsigned Calls = 0;
		unsigned IndirectCalls = 0;
		unsigned Invokes = 0;
		unsigned CallBrs = 0;

		unsigned Switches = 0;
		unsigned IndirectBrs = 0;

		unsigned Returns = 0;
		unsigned Branches = 0;

		unsigned Cyclomatic = 0; // E - N + 2 (single-entry approximation)
	};

	static FnMetrics computeMetrics(Function& F) {
		FnMetrics M;
		M.Name = F.getName().str();

		if (F.isDeclaration()) {
			// Decls: just name, everything else 0.
			return M;
		}

		M.Blocks = (unsigned)F.size();

		for (BasicBlock& BB : F) {
			M.Edges += (unsigned)succ_size(&BB);

			for (Instruction& I : BB) {
				++M.Insts;

				if (isa<PHINode>(I))
					++M.PHIs;
				if (isa<AllocaInst>(I))
					++M.Allocas;
				if (isa<LoadInst>(I))
					++M.Loads;
				if (isa<StoreInst>(I))
					++M.Stores;

				if (auto* CB = dyn_cast<CallBase>(&I)) {
					++M.Calls;
					if (!CB->getCalledFunction())
						++M.IndirectCalls;
					if (isa<InvokeInst>(I))
						++M.Invokes;
					if (isa<CallBrInst>(I))
						++M.CallBrs;
				}

				if (isa<SwitchInst>(I))
					++M.Switches;
				if (isa<IndirectBrInst>(I))
					++M.IndirectBrs;
			}

			Instruction* T = BB.getTerminator();
			if (isa<ReturnInst>(T))
				++M.Returns;
			else if (isa<BranchInst>(T))
				++M.Branches;
		}

		if (M.Blocks > 0) {
			// Cyclomatic complexity approximation for a single-entry function.
			// For most functions in our use, this is a good proxy for CFG complexity.
			int64_t CC = (int64_t)M.Edges - (int64_t)M.Blocks + 2;
			if (CC < 0)
				CC = 0;
			M.Cyclomatic = (unsigned)CC;
		}

		return M;
	}

	static void emitJsonLine(const FnMetrics& M) {
		json::Object O;
		O["function"] = M.Name;
		O["blocks"] = M.Blocks;
		O["edges"] = M.Edges;
		O["insts"] = M.Insts;
		O["cyclomatic"] = M.Cyclomatic;

		O["phis"] = M.PHIs;
		O["allocas"] = M.Allocas;
		O["loads"] = M.Loads;
		O["stores"] = M.Stores;

		O["calls"] = M.Calls;
		O["indirect_calls"] = M.IndirectCalls;
		O["invokes"] = M.Invokes;
		O["callbrs"] = M.CallBrs;

		O["switches"] = M.Switches;
		O["indirectbrs"] = M.IndirectBrs;

		O["returns"] = M.Returns;
		O["branches"] = M.Branches;

		outs() << json::Value(std::move(O)) << "\n";
	}

} // namespace

PreservedAnalyses ObfMetricsPass::run(Module& M, ModuleAnalysisManager&) {
	for (Function& F : M) {
		if (F.isDeclaration() && !ObfMetricsIncludeDeclarations)
			continue;
		if (!ObfMetricsFunction.empty() && F.getName() != ObfMetricsFunction)
			continue;

		FnMetrics FM = computeMetrics(F);
		emitJsonLine(FM);
	}

	return PreservedAnalyses::all();
}