// Tech_RdtscStretch.cpp — passive rdtsc anti-trace.
//
// Inserts inline-asm rdtsc reads at randomly selected non-EH, non-entry
// instruction sites. The result is stored to a volatile sink so the
// compiler cannot dead-code-eliminate it. Tracers that single-step the
// process see drastically inflated tsc deltas around these reads, which
// can be picked up by complementary anti-debug logic or detection
// scripts. x86_64 only.

#include "llvm/Transforms/Obfuscator/ADec/Technique.h"
#include "llvm/Transforms/Obfuscator/ADec/Types.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IntrinsicsX86.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/TargetParser/Triple.h"

#define DEBUG_TYPE "adec"
STATISTIC(ADecRdtscReads, "rdtsc anti-trace reads inserted");

using namespace llvm;
using namespace llvm::obf::adec;

namespace {

class RdtscStretchTechnique final : public ADecTechnique {
public:
	llvm::StringRef name() const override { return "rdtscStretch"; }

	bool supportsTarget(const llvm::Triple& T) const override {
		return T.isX86() && T.isArch64Bit();
	}

	bool isEnabled(const llvm::AntiDecompilerConfig& Cfg) const override {
		return Cfg.enableRdtscStretch;
	}

	unsigned run(ADecCtx& Ctx, unsigned Budget) override {
		// Collect insertion points.
		llvm::SmallVector<llvm::Instruction*, 64> InsertPts;
		for (llvm::BasicBlock& BB : Ctx.F) {
			if (&BB == &Ctx.F.getEntryBlock())
				continue;
			if (BB.isEHPad())
				continue;
			for (auto It = BB.getFirstNonPHI()->getIterator(),
			          E = BB.end(); It != E; ++It) {
				llvm::Instruction* I = &*It;
				if (I->isTerminator())
					break;
				if (llvm::isa<llvm::PHINode>(I) ||
				    llvm::isa<llvm::LandingPadInst>(I))
					continue;
				InsertPts.push_back(I);
			}
		}

		if (InsertPts.empty())
			return 0;

		Ctx.ShuffleRng.shuffle(llvm::MutableArrayRef<llvm::Instruction*>(
		    InsertPts.data(), InsertPts.size()));

		llvm::LLVMContext& C = Ctx.F.getContext();
		llvm::Type* I64 = llvm::Type::getInt64Ty(C);

		// Use the x86 rdtsc intrinsic. Returns i64.
		llvm::Function* RdtscFn = llvm::Intrinsic::getOrInsertDeclaration(
		    &Ctx.M, llvm::Intrinsic::x86_rdtsc);

		// Volatile sink slot in entry block.
		llvm::AllocaInst* Sink = nullptr;
		{
			llvm::IRBuilder<> EntryB(
			    &*Ctx.F.getEntryBlock().getFirstInsertionPt());
			Sink = EntryB.CreateAlloca(I64, nullptr,
			                           Ctx.prefixed("rdtsc.sink"));
		}

		int EffProb = Ctx.Cfg.effectiveProb(name());

		unsigned Inserted = 0;
		for (llvm::Instruction* IP : InsertPts) {
			if (Inserted >= Budget)
				break;
			if (Ctx.SelectRng.range(100) >= (uint32_t)EffProb)
				continue;

			llvm::IRBuilder<> B(IP);
			llvm::CallInst* T1 = B.CreateCall(RdtscFn, {},
			                                  Ctx.prefixed("rdtsc.t1"));
			auto* St = B.CreateStore(T1, Sink);
			St->setVolatile(true);

			++Inserted;
			++ADecRdtscReads;
		}

		return Inserted;
	}
};

} // namespace

namespace llvm {
namespace obf {
namespace adec {

std::unique_ptr<ADecTechnique> makeRdtscStretchTechnique() {
	return std::make_unique<RdtscStretchTechnique>();
}

} // namespace adec
} // namespace obf
} // namespace llvm
