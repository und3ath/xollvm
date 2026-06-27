#include "llvm/Transforms/Obfuscator/ADec/Technique.h"
#include "llvm/Transforms/Obfuscator/ADec/Types.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Transforms/Obfuscator/EHUtils.h"

#define DEBUG_TYPE "adec"
STATISTIC(ADecDeadDecoys, "Opaque-predicate dead-code decoy blocks");

using namespace llvm;
using namespace llvm::obf::adec;

namespace {

static void buildDecoyBlock(ADecCtx& Ctx, llvm::BasicBlock* DeadBB,
                            llvm::BasicBlock* MergeBB, unsigned EffStrength) {
	llvm::LLVMContext& C = DeadBB->getContext();
	llvm::IRBuilder<> B(DeadBB);

	llvm::Type* I32 = llvm::Type::getInt32Ty(C);
	llvm::Type* I64 = llvm::Type::getInt64Ty(C);
	llvm::Type* DblTy = llvm::Type::getDoubleTy(C);
	llvm::Type* FltTy = llvm::Type::getFloatTy(C);
	llvm::Type* I8Ty = llvm::Type::getInt8Ty(C);
	llvm::Type* I8ArrTy = llvm::ArrayType::get(I8Ty, 24);

	llvm::AllocaInst* FakeI32 = B.CreateAlloca(I32, nullptr, Ctx.prefixed("dk.i"));
	llvm::AllocaInst* FakeDbl = B.CreateAlloca(DblTy, nullptr, Ctx.prefixed("dk.d"));
	llvm::AllocaInst* FakeArr = B.CreateAlloca(I8ArrTy, nullptr, Ctx.prefixed("dk.a"));

	uint32_t K0 = Ctx.DecoyRng.u32();
	uint32_t K1 = Ctx.DecoyRng.u32();
	auto* StI = B.CreateStore(llvm::ConstantInt::get(I32, K0), FakeI32);
	StI->setVolatile(true);
	llvm::Value* Ld1 = B.CreateLoad(I32, FakeI32, Ctx.prefixed("dk.v1"));
	llvm::cast<llvm::LoadInst>(Ld1)->setVolatile(true);

	llvm::Value* Mix1 =
	    B.CreateXor(Ld1, llvm::ConstantInt::get(I32, K1), Ctx.prefixed("dk.x1"));
	uint32_t MulConst = 0x9e3779b1u;
	if (Ctx.RandomizeConsts)
		MulConst = Ctx.DecoyRng.u32() | 1u; // keep odd
	llvm::Value* Mix2 = B.CreateMul(
	    Mix1, llvm::ConstantInt::get(I32, MulConst), Ctx.prefixed("dk.m1"));
	llvm::Value* Mix3 = B.CreateLShr(
	    Mix2, llvm::ConstantInt::get(I32, 7), Ctx.prefixed("dk.s1"));
	llvm::Value* Mix4 = B.CreateXor(Mix2, Mix3, Ctx.prefixed("dk.x2"));

	llvm::Value* AsFloat = B.CreateSIToFP(Mix4, DblTy, Ctx.prefixed("dk.f1"));
	auto* StD = B.CreateStore(AsFloat, FakeDbl);
	StD->setVolatile(true);

	llvm::Value* LdD = B.CreateLoad(DblTy, FakeDbl, Ctx.prefixed("dk.df"));
	llvm::cast<llvm::LoadInst>(LdD)->setVolatile(true);

	llvm::Value* FTrunc = B.CreateFPToUI(LdD, I32, Ctx.prefixed("dk.fti"));
	auto* StI2 = B.CreateStore(FTrunc, FakeI32);
	StI2->setVolatile(true);

	llvm::Value* ArrGEP0 = B.CreateConstInBoundsGEP2_32(I8ArrTy, FakeArr, 0, 0,
	                                                    Ctx.prefixed("dk.g0"));
	uint8_t Bytes[4];
	for (int i = 0; i < 4; ++i)
		Bytes[i] = (uint8_t)Ctx.DecoyRng.range(128);
	for (int i = 0; i < 4; ++i) {
		llvm::Value* GEP = B.CreateConstInBoundsGEP1_32(I8Ty, ArrGEP0, i,
		                                                Ctx.prefixed("dk.p"));
		auto* St = B.CreateStore(llvm::ConstantInt::get(I8Ty, Bytes[i]), GEP);
		St->setVolatile(true);
	}

	if (EffStrength >= 2) {
		llvm::Value* FConv = B.CreateUIToFP(Mix4, FltTy, Ctx.prefixed("dk.fc"));
		double FpA = 3.14159, FpB = 2.71828;
		if (Ctx.RandomizeConsts) {
			FpA = (double)(Ctx.DecoyRng.u32() & 0xFFFFu) / 1000.0 + 0.5;
			FpB = (double)(Ctx.DecoyRng.u32() & 0xFFFFu) / 1000.0 + 0.5;
		}
		llvm::Value* FMul = B.CreateFMul(
		    FConv, llvm::ConstantFP::get(FltTy, FpA), Ctx.prefixed("dk.fm"));
		llvm::Value* FAdd = B.CreateFAdd(
		    FMul, llvm::ConstantFP::get(FltTy, FpB), Ctx.prefixed("dk.fa"));
		(void)FAdd;

		llvm::Value* Wide = B.CreateZExt(Mix4, I64, Ctx.prefixed("dk.w"));
		llvm::Value* Shl = B.CreateShl(
		    Wide, llvm::ConstantInt::get(I64, 32), Ctx.prefixed("dk.wsh"));
		llvm::Value* Or = B.CreateOr(Wide, Shl, Ctx.prefixed("dk.wor"));
		llvm::AllocaInst* FakeI64 =
		    B.CreateAlloca(I64, nullptr, Ctx.prefixed("dk.i64"));
		auto* St64 = B.CreateStore(Or, FakeI64);
		St64->setVolatile(true);
	}

	B.CreateBr(MergeBB);
}

class DeadDecoyTechnique final : public ADecTechnique {
public:
	llvm::StringRef name() const override { return "deadDecoy"; }

	bool supportsTarget(const llvm::Triple&) const override { return true; }

	bool isEnabled(const llvm::AntiDecompilerConfig& Cfg) const override {
		return Cfg.enableDeadCodeDecoys;
	}

	unsigned run(ADecCtx& Ctx, unsigned Budget) override {
		llvm::SmallVector<llvm::BasicBlock*, 32> Blocks;
		for (llvm::BasicBlock& BB : Ctx.F) {
			if (&BB == &Ctx.F.getEntryBlock())
				continue;
			if (BB.isEHPad())
				continue;
			if (llvm::obf::isInEHRegion(&BB))
				continue;
			if (llvm::isa<llvm::InvokeInst>(BB.getTerminator()))
				continue;
			if (BB.size() < 2)
				continue;
			Blocks.push_back(&BB);
		}

		if (Blocks.empty())
			return 0;

		Ctx.ShuffleRng.shuffle(llvm::MutableArrayRef<llvm::BasicBlock*>(
		    Blocks.data(), Blocks.size()));

		int EffProb = Ctx.Cfg.effectiveProb(name());
		unsigned EffStrength = Ctx.Cfg.effectiveStrength(name());

		unsigned Injected = 0;
		for (llvm::BasicBlock* BB : Blocks) {
			if (Injected >= Budget)
				break;
			if (Ctx.SelectRng.range(100) >= (uint32_t)EffProb)
				continue;

			auto SplitIt = BB->getFirstNonPHIOrDbgOrLifetime();
			while (SplitIt != BB->end() && llvm::isa<llvm::AllocaInst>(&*SplitIt))
				++SplitIt;
			if (SplitIt == BB->end() || SplitIt->isTerminator())
				continue;

			llvm::BasicBlock* RealBB =
			    BB->splitBasicBlock(SplitIt, Ctx.prefixed("real"));

			llvm::BasicBlock* DeadBB = llvm::BasicBlock::Create(
			    BB->getContext(), Ctx.prefixed("dead"), &Ctx.F, RealBB);

			BB->getTerminator()->eraseFromParent();

			llvm::IRBuilder<> B(BB);
			llvm::Value* OpaqueTrue =
			    Ctx.Opaque.enhancedTrue(B, EffStrength);
			B.CreateCondBr(OpaqueTrue, RealBB, DeadBB);

			buildDecoyBlock(Ctx, DeadBB, RealBB, EffStrength);

			++Injected;
			++ADecDeadDecoys;
		}

		return Injected;
	}
};

} // namespace

namespace llvm {
namespace obf {
namespace adec {

std::unique_ptr<ADecTechnique> makeDeadDecoyTechnique() {
	return std::make_unique<DeadDecoyTechnique>();
}

} // namespace adec
} // namespace obf
} // namespace llvm
