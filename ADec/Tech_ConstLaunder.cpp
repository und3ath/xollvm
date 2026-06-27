// Tech_ConstLaunder.cpp — route literal integer constants through
// per-constant private globals loaded volatile.
//
// For each selected ConstantInt operand, we materialize a private global
// initialized to the constant value, then replace the operand with a
// volatile load of that global. Decompilers see the value as a runtime
// memory load instead of a literal, which inhibits constant propagation
// and breaks pattern-matching against magic numbers (e.g. CRC tables,
// hash multipliers, status codes).

#include "llvm/Transforms/Obfuscator/ADec/Technique.h"
#include "llvm/Transforms/Obfuscator/ADec/Types.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"

#define DEBUG_TYPE "adec"
STATISTIC(ADecLaunderedConsts, "Literal integer constants laundered via globals");

using namespace llvm;
using namespace llvm::obf::adec;

namespace {

// Sites where replacing a ConstantInt operand would break LLVM IR or hurt
// downstream analysis we want to preserve.
static bool isUnsafeUse(llvm::Instruction* User, unsigned OpIdx) {
	// PHI: incoming values must remain constants? Actually PHIs accept
	// non-constants, but rewriting the constant in a PHI's incoming slot
	// would require inserting the load in the predecessor block, which
	// gets gnarly with critical edges. Skip.
	if (llvm::isa<llvm::PHINode>(User))
		return true;

	// Branch condition is fine — but we want to preserve it as a literal
	// because decompilers visually flag ConstantInt branch cond as
	// "always true/false" anyway; laundering it adds little value here.
	if (auto* BR = llvm::dyn_cast<llvm::BranchInst>(User)) {
		if (BR->isConditional() && OpIdx == 0)
			return true;
	}

	// Switch case values must be ConstantInt — cannot replace.
	if (llvm::isa<llvm::SwitchInst>(User))
		return true;

	// GEP indices: most index slots demand a constant or InRange; safer
	// to leave them. (Pointer operand may be at index 0 — also skip.)
	if (llvm::isa<llvm::GetElementPtrInst>(User))
		return true;

	// Intrinsic args: many intrinsics require ConstantInt for certain
	// operand positions (e.g. align, immarg). Skip wholesale.
	if (llvm::isa<llvm::IntrinsicInst>(User))
		return true;

	// Inline asm operands: keep literal — InlineAsm constraints often
	// require immediates.
	if (auto* CI = llvm::dyn_cast<llvm::CallInst>(User)) {
		if (CI->isInlineAsm())
			return true;
	}

	// Insertvalue / extractvalue index args are ArrayRef<unsigned>, not
	// operand-form — so ConstantInt operands here are unusual; skip
	// defensively.
	if (llvm::isa<llvm::InsertValueInst>(User) ||
	    llvm::isa<llvm::ExtractValueInst>(User))
		return true;

	return false;
}

class ConstLaunderTechnique final : public ADecTechnique {
public:
	llvm::StringRef name() const override { return "constLaunder"; }

	bool supportsTarget(const llvm::Triple&) const override { return true; }

	bool isEnabled(const llvm::AntiDecompilerConfig& Cfg) const override {
		return Cfg.enableConstLaunder;
	}

	unsigned run(ADecCtx& Ctx, unsigned Budget) override {
		// Collect (use-site, operand-index, ConstantInt) triples.
		struct Site {
			llvm::Instruction* User;
			unsigned OpIdx;
			llvm::ConstantInt* CI;
		};
		llvm::SmallVector<Site, 64> Sites;

		for (llvm::BasicBlock& BB : Ctx.F) {
			if (BB.isEHPad())
				continue;
			for (llvm::Instruction& I : BB) {
				for (unsigned i = 0, e = I.getNumOperands(); i < e; ++i) {
					auto* C = llvm::dyn_cast<llvm::ConstantInt>(
					    I.getOperand(i));
					if (!C)
						continue;
					// Skip i1 and tiny ints: too low-value, plus i1 ops
					// frequently come from cmp/select shapes the decompiler
					// already handles fine. Also skip wider-than-64
					// constants — cache key uses uint64_t.
					unsigned BW = C->getBitWidth();
					if (BW < 8 || BW > 64)
						continue;
					if (isUnsafeUse(&I, i))
						continue;
					Sites.push_back({ &I, i, C });
				}
			}
		}

		if (Sites.empty())
			return 0;

		Ctx.ShuffleRng.shuffle(llvm::MutableArrayRef<Site>(
		    Sites.data(), Sites.size()));

		// Per-(value,type) cache so identical constants share a global.
		llvm::DenseMap<std::pair<llvm::Type*, uint64_t>,
		               llvm::GlobalVariable*> Cache;

		auto getGlobal = [&](llvm::ConstantInt* CI) -> llvm::GlobalVariable* {
			llvm::Type* Ty = CI->getType();
			uint64_t V = CI->getZExtValue();
			auto Key = std::make_pair(Ty, V);
			auto It = Cache.find(Key);
			if (It != Cache.end())
				return It->second;

			llvm::GlobalVariable* GV = new llvm::GlobalVariable(
			    Ctx.M, Ty, /*isConstant=*/false,
			    llvm::GlobalValue::PrivateLinkage, CI,
			    Ctx.prefixed("clndr.k"));
			GV->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::None);
			Cache.try_emplace(Key, GV);
			return GV;
		};

		int EffProb = Ctx.Cfg.effectiveProb(name());

		unsigned Laundered = 0;
		for (auto& S : Sites) {
			if (Laundered >= Budget)
				break;
			if (Ctx.SelectRng.range(100) >= (uint32_t)EffProb)
				continue;

			llvm::GlobalVariable* GV = getGlobal(S.CI);
			llvm::IRBuilder<> B(S.User);
			auto* Ld = B.CreateLoad(S.CI->getType(), GV,
			                        Ctx.prefixed("clndr.v"));
			Ld->setVolatile(true);
			S.User->setOperand(S.OpIdx, Ld);

			++Laundered;
			++ADecLaunderedConsts;
		}

		return Laundered;
	}
};

} // namespace

namespace llvm {
namespace obf {
namespace adec {

std::unique_ptr<ADecTechnique> makeConstLaunderTechnique() {
	return std::make_unique<ConstLaunderTechnique>();
}

} // namespace adec
} // namespace obf
} // namespace llvm
