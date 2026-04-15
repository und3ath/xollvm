#pragma once

#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Format.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace llvm::obf {

	/// Lightweight instruction counter.
	inline unsigned countInstructions(const Function& F) {
		unsigned N = 0;
		for (const BasicBlock& BB : F)
			N += BB.size();
		return N;
	}

	/// Per-pass snapshot for post-hoc reporting.
	struct PassBudgetRecord {
		std::string PassName;
		uint64_t PassSeed = 0;

		bool Skipped = false;
		std::string SkipReason;

		bool Changed = false; // "changed IR" as reported by PreservedAnalyses
		unsigned InstsBefore = 0;
		unsigned InstsAfter = 0;

		int64_t DeltaSigned() const {
			return (int64_t)InstsAfter - (int64_t)InstsBefore;

		}

		// Convenience: positive instruction growth only.
		unsigned DeltaGrowth() const {
			return InstsAfter > InstsBefore ? InstsAfter - InstsBefore : 0;
		}
	};

	/// Budget tracker - created once per function pipeline invocation.
	///
	/// The budget is expressed as an absolute instruction ceiling for the function.
	/// It is computed from the *original* instruction count (before any obfuscation)
	/// multiplied by a configurable factor:
	///
	///     budget = clamp(initialInsts * multiplier, minFloor, hardCap)
	///
	/// Passes and the pipeline driver use `isExhausted()` to decide whether to
	/// keep transforming.  Individual passes can call `remaining()` to self-throttle
	/// their own site budgets.
	class IRBudget {
	public:
		/// Construct a budget for function \p F.
		///
		/// \param InitialInsts  Instruction count at pipeline entry (from FOC.NumInsts
		///                      or a fresh count).
		/// \param Multiplier    Budget = InitialInsts * Multiplier.
		///                      0 means "unlimited" (budget disabled).
		/// \param HardCap       Absolute ceiling regardless of multiplier.
		///                      0 means "no cap" (multiplier-only).
		IRBudget(unsigned InitialInsts, unsigned Multiplier, unsigned HardCap)
			: Initial(InitialInsts), Mult(Multiplier), Cap(HardCap) {
			if (Multiplier == 0) {
				// Budget disabled — effectively infinite.
				Limit = UINT_MAX;
			}
			else {
				uint64_t Raw = (uint64_t)InitialInsts * Multiplier;
				// Minimum floor: at least 256 instructions so tiny functions aren't
				// starved.  This avoids edge cases with 5-instruction functions.
				uint64_t Floor = std::max<uint64_t>(256, Raw);
				if (HardCap > 0)
					Floor = std::min<uint64_t>(Floor, HardCap);
				Limit = static_cast<unsigned>(std::min<uint64_t>(Floor, UINT_MAX));
			}
		}

		/// Default constructor: budget disabled.
		IRBudget() : IRBudget(0, 0, 0) {}

		/// Factory: build from CLI options + optional per-function annotation override.
		///
		/// \param InitialInsts     The instruction count before obfuscation.
		/// \param AnnotMultiplier  Per-function override from annotation (0 = use CLI).
		/// \param AnnotHardCap     Per-function override (0 = use CLI).
		static IRBudget fromConfig(unsigned InitialInsts,
			unsigned AnnotMultiplier = 0,
			unsigned AnnotHardCap = 0) {
			unsigned M = AnnotMultiplier ? AnnotMultiplier
				: static_cast<unsigned>(ObfIRBudgetMultiplier);
			unsigned C = AnnotHardCap ? AnnotHardCap
				: static_cast<unsigned>(ObfIRBudgetMax);
			return IRBudget(InitialInsts, M, C);
		}

		// --- Queries -----------------------------------------------------------

		/// The absolute instruction ceiling.
		unsigned limit() const { return Limit; }

		/// Original instruction count at pipeline entry.
		unsigned initial() const { return Initial; }

		/// True when budget tracking is active (multiplier > 0).
		bool isEnabled() const { return Mult > 0; }

		/// True when \p CurrentInsts >= budget limit.
		bool isExhausted(unsigned CurrentInsts) const {
			return isEnabled() && CurrentInsts >= Limit;
		}

		/// How many instructions the function can still grow by.
		/// Returns UINT_MAX when budget is disabled.
		unsigned remaining(unsigned CurrentInsts) const {
			if (!isEnabled())
				return UINT_MAX;
			if (CurrentInsts >= Limit)
				return 0;
			return Limit - CurrentInsts;
		}

		/// Fraction of budget consumed so far: [0.0, ∞).
		/// Returns 0.0 when budget is disabled.
		double utilization(unsigned CurrentInsts) const {
			if (!isEnabled() || Limit == 0)
				return 0.0;
			return static_cast<double>(CurrentInsts) / static_cast<double>(Limit);
		}

		// --- Recording ---------------------------------------------------------

		/// Call before a pass runs.
		void recordPassStart(StringRef PassName, unsigned CurrentInsts, uint64_t PassSeed = 0) {
			PassBudgetRecord R;
			R.PassName = PassName.str();
			R.InstsBefore = CurrentInsts;
			R.InstsAfter = CurrentInsts; // updated by recordPassEnd
			Records.push_back(std::move(R));
		}

		/// Call after a pass runs.
		void recordPassEnd(unsigned CurrentInsts, bool Changed) {
			if (!Records.empty()) {
				Records.back().InstsAfter = CurrentInsts;
				Records.back().Changed = Changed;
			}
		}

		// Call when a pass is skipped by the pipeline driver.
		void recordPassSkip(StringRef PassName, unsigned CurrentInsts, StringRef Reason,
			uint64_t PassSeed = 0) {
			PassBudgetRecord R;
			R.PassName = PassName.str();
			R.PassSeed = PassSeed;
			R.Skipped = true;
			R.SkipReason = Reason.str();
			R.InstsBefore = CurrentInsts;
			R.InstsAfter = CurrentInsts;
			Records.push_back(std::move(R));
		}


		/// All recorded pass snapshots.
		const std::vector<PassBudgetRecord>& records() const { return Records; }

		// --- Diagnostics -------------------------------------------------------

		/// Print a concise budget summary to \p OS.
		void printSummary(raw_ostream& OS, StringRef FnName,
			unsigned FinalInsts) const {
			OS << "[budget] " << FnName << ": initial=" << Initial
				<< "  limit=" << (isEnabled() ? std::to_string(Limit) : "unlimited")
				<< "  final=" << FinalInsts;
			if (isEnabled()) {
				unsigned Growth = FinalInsts > Initial ? FinalInsts - Initial : 0;
				OS << "  growth=" << Growth
					<< "  util=" << format("%.1f%%", utilization(FinalInsts) * 100.0);
			}
			OS << "\n";
		}

		/// Print per-pass breakdown to \p OS.
		void printPerPassBreakdown(raw_ostream& OS) const {
			for (const auto& R : Records) {
				OS << "  " << R.PassName << ": ";
				if (R.Skipped) {
					OS << "SKIP";
					if (!R.SkipReason.empty())
						OS << " (" << R.SkipReason << ")";
					OS << "  @" << R.InstsBefore;

				}
				else {
					OS << R.InstsBefore << " -> " << R.InstsAfter;
					int64_t D = R.DeltaSigned();
					if (D > 0)
						OS << " (+" << D << ")";
					else if (D < 0)
						OS << " (" << D << ")";
					if (isEnabled())
						OS << "  [" << format("%.0f%%", utilization(R.InstsAfter) * 100.0)
						<< " of budget]";
					if (!R.Changed)
						OS << "  (no-change)";

				}
				OS << "\n";
			}
		}

	private:
		unsigned Initial = 0;
		unsigned Mult = 0;
		unsigned Cap = 0;
		unsigned Limit = UINT_MAX;
		std::vector<PassBudgetRecord> Records;
	};

} // namespace llvm::obf