#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/Hashing.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/Transforms/Obfuscator/AntiOptimizationShield.h"
#include "llvm/Transforms/Obfuscator/DebugInfoPreserver.h"
#include "llvm/Transforms/Obfuscator/EHUtils.h"
#include "llvm/Transforms/Obfuscator/FunctionObfContextAnalysis.h"
#include "llvm/Transforms/Obfuscator/IRBudget.h"
#include "llvm/Transforms/Obfuscator/ObfMetrics.h"
#include "llvm/Transforms/Obfuscator/ObfRepairSSA.h"
#include "llvm/Transforms/Obfuscator/ObfReport.h"
#include "llvm/Transforms/Obfuscator/ObfVerify.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/ObfuscationPipeline.h"
#include "llvm/Transforms/Obfuscator/PassIds.h"
#include "llvm/Transforms/Obfuscator/PassRng.h"
#include "llvm/Transforms/Obfuscator/SeedManifest.h"
#include "llvm/Transforms/Obfuscator/StringEncryption.h"
#include "llvm/Transforms/Obfuscator/TargetCompat.h"

namespace llvm {

	class ObfuscationFunctionDriverPass
		: public PassInfoMixin<ObfuscationFunctionDriverPass> {
	public:
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& FAM) {
			if (F.isDeclaration())
				return PreservedAnalyses::all();

			// Global cost/safety caps (deterministic skip).
			auto& FOC = *FAM.getResult<FunctionObfContextAnalysis>(F);

			std::string FuncSkipReason;
			if (ObfMaxFunctionInsts && FOC.NumInsts > ObfMaxFunctionInsts) {
				if (ObfVerbose)
					errs() << "[obf] skip " << F.getName() << ": NumInsts=" << FOC.NumInsts
					<< " > obf-max-function-insts=" << ObfMaxFunctionInsts << "\n";
				FuncSkipReason = "cap_max_function_insts";
			}
			else if (ObfMaxFunctionBlocks && FOC.NumBlocks > ObfMaxFunctionBlocks) {
				if (ObfVerbose)
					errs() << "[obf] skip " << F.getName() << ": NumBlocks=" << FOC.NumBlocks
					<< " > obf-max-function-blocks=" << ObfMaxFunctionBlocks << "\n";
				FuncSkipReason = "cap_max_function_blocks";
			}
			else if (ObfMaxLoopDepth && FOC.MaxLoopDepth > ObfMaxLoopDepth) {
				if (ObfVerbose)
					errs() << "[obf] skip " << F.getName() << ": MaxLoopDepth=" << FOC.MaxLoopDepth
					<< " > obf-max-loop-depth=" << ObfMaxLoopDepth << "\n";
				FuncSkipReason = "cap_max_loop_depth";
			}

			// If capped, optionally emit a report entry (only if the function actually
			// has passes enabled).
			if (!FuncSkipReason.empty()) {
				if (llvm::obf::isReportEnabled()) {
					const auto& Cache = getObfCache(F, FAM);
					const auto& Cfg = Cache.getConfig(F);

					if (!Cfg.passes.empty()) {
						auto& Proxy = FAM.getResult<ModuleAnalysisManagerFunctionProxy>(F);
						if (auto* Sink = Proxy.getCachedResult<ObfReportAnalysis>(*F.getParent())) {

							llvm::obf::FunctionReport R;
							R.Name = F.getName().str();
							R.Declaration = false;
							R.Skipped = true;
							R.SkipReason = FuncSkipReason;

							R.BaseSeed = (uint64_t)llvm::ObfSeed;
							R.ModuleSeed = Cache.ModuleSeed;
							R.FunctionSeed = Cache.getFunctionSeed(F);

							unsigned Insts = llvm::obf::countInstructions(F);
							R.InstsBefore = Insts;
							R.InstsAfter = Insts;

							// Budget snapshot (still meaningful as "would-have-run" context).

							llvm::obf::IRBudget Budget =
								llvm::obf::IRBudget::fromConfig(Insts, Cfg.budgetMultiplier, Cfg.budgetHardCap);
							R.BudgetEnabled = Budget.isEnabled();
							R.BudgetLimit = Budget.isEnabled() ? Budget.limit() : 0;
							R.BudgetRemaining = Budget.remaining(Insts);
							R.BudgetUtilization = Budget.utilization(Insts);

							// Mark all planned passes as skipped with the cap reason.
							auto Entries = ObfuscationPipeline::getPassEntries(Cfg);
							uint64_t FnSeed = Cache.getFunctionSeed(F);
							for (const auto& E : Entries) {
								llvm::obf::PassReport PR;
								PR.Id = E.Name;
								PR.Seed = llvm::obf::deriveSeed(FnSeed, E.Name);
								PR.Skipped = true;
								PR.SkipReason = FuncSkipReason;
								PR.Changed = false;
								PR.InstsBefore = Insts;
								PR.InstsAfter = Insts;
								PR.BudgetUtilAfter = R.BudgetUtilization;
								R.Passes.push_back(std::move(PR));
							}

							// Difficulty score (before == after).
							auto C0 = llvm::obf::computeDifficultyComponents(F);
							R.Difficulty = llvm::obf::scoreDifficulty(C0, C0);

							// Optional CFG artifacts (before/after identical).
							std::string ReportDir = llvm::obf::getReportDir();
							if (!ReportDir.empty()) {
								std::string FnSafe = llvm::obf::sanitizePathComponent(F.getName());

								DenseMap<const BasicBlock*, unsigned> Snap;

								SmallString<256> RelBefore;
								sys::path::append(RelBefore, "cfg");
								sys::path::append(RelBefore, FnSafe);
								sys::path::append(RelBefore, "before.dot");

								SmallString<256> AbsBefore(ReportDir);
								sys::path::append(AbsBefore, RelBefore);

								if (Error E =
									llvm::obf::writeCfgDotSnapshot(F, AbsBefore, nullptr, Snap)) {
									errs() << "[obf] report: cfg before for " << F.getName() << ": "
										<< toString(std::move(E)) << "\n";
								}
								else {
									R.CfgBeforeDot = std::string(RelBefore.str());
								}

								Snap.clear();

								SmallString<256> RelAfter;
								sys::path::append(RelAfter, "cfg");
								sys::path::append(RelAfter, FnSafe);
								sys::path::append(RelAfter, "after.dot");

								SmallString<256> AbsAfter(ReportDir);
								sys::path::append(AbsAfter, RelAfter);

								if (Error E =
									llvm::obf::writeCfgDotSnapshot(F, AbsAfter, nullptr, Snap)) {
									errs() << "[obf] report: cfg after for " << F.getName() << ": "
										<< toString(std::move(E)) << "\n";
								}
								else {
									R.CfgAfterDot = std::string(RelAfter.str());
								}
							}

							Sink->add(std::move(R));
						}
					}
				}

				return PreservedAnalyses::all();
			}

			const auto& Cache = getObfCache(F, FAM);
			const auto& Cfg = Cache.getConfig(F);
			if (Cfg.passes.empty())
				return PreservedAnalyses::all();

			// ------------------------------------------------------------
			// Reporting setup (LLVM 21: use cached module analysis via proxy)
			// ------------------------------------------------------------
			bool Reporting = llvm::obf::isReportEnabled();
			llvm::obf::ObfReportSink* Sink = nullptr;

			llvm::obf::FunctionReport Report;
			llvm::obf::DifficultyComponents DiffBefore, DiffAfter;

			DenseMap<const BasicBlock*, unsigned> CfgPrev;
			DenseMap<const BasicBlock*, unsigned> CfgTmp;

			std::string ReportDir;
			std::string FnSafe;

			if (Reporting) {
				auto& Proxy = FAM.getResult<ModuleAnalysisManagerFunctionProxy>(F);
				Sink = Proxy.getCachedResult<ObfReportAnalysis>(*F.getParent());
				if (!Sink)
					Reporting = false;
			}

			if (Reporting) {
				Report.Name = F.getName().str();
				Report.Declaration = false;

				Report.BaseSeed = (uint64_t)llvm::ObfSeed;
				Report.ModuleSeed = Cache.ModuleSeed;
				Report.FunctionSeed = Cache.getFunctionSeed(F);

				Report.InstsBefore = llvm::obf::countInstructions(F);
				DiffBefore = llvm::obf::computeDifficultyComponents(F);

				ReportDir = llvm::obf::getReportDir();
				FnSafe = llvm::obf::sanitizePathComponent(F.getName());

				if (!ReportDir.empty()) {
					SmallString<256> Rel;
					sys::path::append(Rel, "cfg");
					sys::path::append(Rel, FnSafe);
					sys::path::append(Rel, "before.dot");

					SmallString<256> Abs(ReportDir);
					sys::path::append(Abs, Rel);

					if (Error E =
						llvm::obf::writeCfgDotSnapshot(F, Abs, nullptr, CfgPrev)) {
						errs() << "[obf] report: cfg before for " << F.getName() << ": "
							<< toString(std::move(E)) << "\n";
					}
					else {
						Report.CfgBeforeDot = std::string(Rel.str());
					}
				}
			}

			// Seed manifest (existing behavior).
			if (llvm::ObfSeedManifest || llvm::ObfSeedManifestMD) {
				auto Enabled = Cfg.getEnabledPasses();
				auto Ordered = ObfuscationPipeline::getRecommendedOrder(Enabled);

				uint64_t FnSeed = Cache.getFunctionSeed(F);
				for (const auto& PassName : Ordered) {
					// module-only passes (strenc) are handled by module pass
					if (llvm::obf::isModuleOnlyPassId(PassName))
						continue;
					uint64_t PassSeed = llvm::obf::deriveSeed(FnSeed, PassName);
					llvm::obf::emitPassLine(
						F, Cache, PassName, PassSeed,
						llvm::ArrayRef<std::pair<llvm::StringRef, uint64_t>>{});
				}
			}

			// ================================================================
			// Budget-aware per-pass execution
			// ================================================================
			unsigned InitialInsts = llvm::obf::countInstructions(F);
			llvm::obf::IRBudget Budget = llvm::obf::IRBudget::fromConfig(
				InitialInsts, Cfg.budgetMultiplier, Cfg.budgetHardCap);

			auto Entries = ObfuscationPipeline::getPassEntries(Cfg);
			if (Entries.empty())
				return PreservedAnalyses::all();

			if (ObfVerbose && Budget.isEnabled()) {
				errs() << "[budget] " << F.getName() << ": initial=" << InitialInsts
					<< "  limit=" << Budget.limit()
					<< "  multiplier=" << (unsigned)ObfIRBudgetMultiplier << "\n";
			}

			if (ObfVerbose) {
				errs() << "Building obfuscation pipeline: ";
				for (const auto& E : Entries)
					errs() << E.Name << " ";
				errs() << "\n";
			}

			// Pre-pipeline verify
			if (ObfVerify)
				llvm::obf::ObfVerifyFunctionPass("pre").run(F, FAM);

			bool AnyChanged = false;
			uint64_t FnSeed = Cache.getFunctionSeed(F);

			for (size_t Idx = 0; Idx < Entries.size(); ++Idx) {
				const auto& Entry = Entries[Idx];

				// --- Budget gate: skip if exhausted ---
				unsigned CurrentInsts = llvm::obf::countInstructions(F);
				if (Budget.isExhausted(CurrentInsts)) {
					if (ObfVerbose)
						errs() << "[budget] " << F.getName() << ": EXHAUSTED (" << CurrentInsts
						<< " >= " << Budget.limit() << "), skipping '" << Entry.Name
						<< "' and remaining passes\n";

					// Record this and remaining passes as skipped.
					for (size_t J = Idx; J < Entries.size(); ++J) {
						uint64_t PassSeed = llvm::obf::deriveSeed(FnSeed, Entries[J].Name);
						Budget.recordPassSkip(Entries[J].Name, CurrentInsts, "budget_exhausted",
							PassSeed);
					}
					break;
				}

				// --- Propagate remaining budget so passes can self-throttle ---
				{
					auto& FOC2 = *FAM.getResult<FunctionObfContextAnalysis>(F);
					FOC2.BudgetRemaining = Budget.remaining(CurrentInsts);
				}

				uint64_t PassSeed = llvm::obf::deriveSeed(FnSeed, Entry.Name);
				Budget.recordPassStart(Entry.Name, CurrentInsts, PassSeed);

				// --- Run the pass ---
				PreservedAnalyses PA = Entry.Run(F, FAM);
				bool Changed = !PA.areAllPreserved();

				if (Changed) {
					AnyChanged = true;
					FAM.invalidate(F, PA);
				}

				// --- Optional SSA repair ---
				if (Changed && Entry.NeedsSSARepair)
					llvm::obf::ObfRepairSSAFunctionPass(Entry.Name).run(F, FAM);

				// --- Optional verify ---
				if (ObfVerify && Changed)
					llvm::obf::ObfVerifyFunctionPass(Entry.Name).run(F, FAM);

				// --- Record post-pass instruction count ---
				unsigned AfterInsts = llvm::obf::countInstructions(F);
				Budget.recordPassEnd(AfterInsts, Changed);

				// --- Optional per-pass CFG snapshot (diff-colored vs previous stage) ---
				if (Reporting && Sink && !ReportDir.empty()) {
					std::string PassSafe = llvm::obf::sanitizePathComponent(Entry.Name);

					SmallString<256> Rel;
					sys::path::append(Rel, "cfg");
					sys::path::append(Rel, FnSafe);
					sys::path::append(Rel,
						("pass_" + std::to_string(Idx) + "_" + PassSafe + ".dot"));

					SmallString<256> Abs(ReportDir);
					sys::path::append(Abs, Rel);

					CfgTmp.clear();
					if (Error E = llvm::obf::writeCfgDotSnapshot(F, Abs, &CfgPrev, CfgTmp)) {
						errs() << "[obf] report: cfg stage for " << F.getName() << ": "
							<< toString(std::move(E)) << "\n";
					}
					else {
						llvm::obf::CfgStageArtifact A;
						A.Pass = Entry.Name;
						A.DotAfter = std::string(Rel.str());
						A.DotDiff = std::string(Rel.str());
						Report.CfgPerPass.push_back(std::move(A));

						CfgPrev.swap(CfgTmp);
					}
				}

				if (ObfVerbose) {
					errs() << "[budget] " << Entry.Name << ": " << CurrentInsts << " -> "
						<< AfterInsts;
					if (AfterInsts > CurrentInsts)
						errs() << " (+" << (AfterInsts - CurrentInsts) << ")";
					if (Budget.isEnabled())
						errs() << "  ["
						<< format("%.0f%%", Budget.utilization(AfterInsts) * 100.0)
						<< " of budget]";
					errs() << "\n";
				}
			}

			// Post-pipeline verify
			if (ObfVerify && AnyChanged)
				llvm::obf::ObfVerifyFunctionPass("final").run(F, FAM);

			// Print final budget summary
			if (ObfVerbose && Budget.isEnabled()) {
				unsigned FinalInsts = llvm::obf::countInstructions(F);
				Budget.printSummary(errs(), F.getName(), FinalInsts);
				Budget.printPerPassBreakdown(errs());
			}

			// Finalize report entry for this function.
			if (Reporting && Sink) {
				unsigned FinalInsts = llvm::obf::countInstructions(F);

				Report.InstsAfter = FinalInsts;

				Report.BudgetEnabled = Budget.isEnabled();
				Report.BudgetLimit = Budget.isEnabled() ? Budget.limit() : 0;
				Report.BudgetRemaining = Budget.remaining(FinalInsts);
				Report.BudgetUtilization = Budget.utilization(FinalInsts);

				for (const auto& R : Budget.records()) {
					llvm::obf::PassReport PR;
					PR.Id = R.PassName;
					PR.Seed = R.PassSeed;
					PR.Skipped = R.Skipped;
					PR.SkipReason = R.SkipReason;
					PR.Changed = R.Changed;
					PR.InstsBefore = R.InstsBefore;
					PR.InstsAfter = R.InstsAfter;
					PR.BudgetUtilAfter = Budget.utilization(R.InstsAfter);
					Report.Passes.push_back(std::move(PR));
				}

				// Final CFG snapshot (no diff coloring).
				if (!ReportDir.empty()) {
					DenseMap<const BasicBlock*, unsigned> Snap;

					SmallString<256> Rel;
					sys::path::append(Rel, "cfg");
					sys::path::append(Rel, FnSafe);
					sys::path::append(Rel, "after.dot");

					SmallString<256> Abs(ReportDir);
					sys::path::append(Abs, Rel);

					if (Error E = llvm::obf::writeCfgDotSnapshot(F, Abs, nullptr, Snap)) {
						errs() << "[obf] report: cfg after for " << F.getName() << ": "
							<< toString(std::move(E)) << "\n";
					}
					else {
						Report.CfgAfterDot = std::string(Rel.str());
					}
				}

				DiffAfter = llvm::obf::computeDifficultyComponents(F);
				Report.Difficulty = llvm::obf::scoreDifficulty(DiffBefore, DiffAfter);

				Sink->add(std::move(Report));
			}

			if (!AnyChanged)
				return PreservedAnalyses::all();

			// If metadata manifest is on, IR was mutated even if pipeline no-ops.
			if (llvm::ObfSeedManifestMD)
				return PreservedAnalyses::none();
			return PreservedAnalyses::none();
		}

		static bool isRequired() { return true; }
	};

	class ObfuscationModulePass : public PassInfoMixin<ObfuscationModulePass> {
	public:
		PreservedAnalyses run(Module& M, ModuleAnalysisManager& MAM) {
			// Prime the report sink early so function passes can append via proxy.
			if (llvm::obf::isReportEnabled())
				(void)MAM.getResult<ObfReportAnalysis>(M);

			auto& Cache = MAM.getResult<ObfuscationAnnotationAnalysis>(M);
			if (!Cache.hasAnyConfig()) {
				// If reporting is enabled, still emit an empty report for the module.
				if (llvm::obf::isReportEnabled()) {
					if (Error E = llvm::obf::maybeWriteObfReportJson(M, MAM))
						errs() << "[obf] report: " << toString(std::move(E)) << "\n";
				}
				return PreservedAnalyses::all();
			}

			ModulePassManager MPM;

			if (ObfVerify)
				MPM.addPass(llvm::obf::ObfVerifyModulePass("pre"));

			// Run module-only pass first (it will no-op if not enabled).
			MPM.addPass(StringEncryptionPass());

			if (ObfVerify)
				MPM.addPass(llvm::obf::ObfVerifyModulePass("strenc"));

			FunctionPassManager FPM;
			FPM.addPass(ObfuscationFunctionDriverPass());
			MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));

			if (ObfVerify)
				MPM.addPass(llvm::obf::ObfVerifyModulePass("final"));

			PreservedAnalyses PA = MPM.run(M, MAM);

			// Emit JSON report at end of module pipeline (if configured).
			if (llvm::obf::isReportEnabled()) {
				if (Error E = llvm::obf::maybeWriteObfReportJson(M, MAM))
					errs() << "[obf] report: " << toString(std::move(E)) << "\n";
			}

			return PA;
		}

		static bool isRequired() { return true; }
	};

} // namespace llvm
