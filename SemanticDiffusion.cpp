#include "llvm/Transforms/Obfuscator/SemanticDiffusion.h"
#include "llvm/Transforms/Obfuscator/Utils.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/FunctionObfContextAnalysis.h"
#include "llvm/Transforms/Obfuscator/PassCtx.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/APInt.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

	struct SDiffCtx;
	struct SdiffImpl final {
		static SemanticDiffusionConfig getSDiffConfig(Function& F, FunctionAnalysisManager& AM);
		static AllocaInst* createVolatileI32Slot(SDiffCtx& Ctx, Function& F, StringRef Name);
		static Value* loadVolatileI32(IRBuilder<>& B, AllocaInst* Slot, StringRef N);
		static Value* buildKey(IRBuilder<>& B, ArrayRef<AllocaInst*> Slots, unsigned BitWidth, unsigned Tag);
		static bool isGoodICmpOperand(Value* V);
		static ICmpInst::Predicate toUnsignedRelPred(ICmpInst::Predicate P);
		static bool tryDiffuseICmp(SDiffCtx& Ctx, ICmpInst& Cmp, ArrayRef<AllocaInst*> Slots);
	};


	struct SDiffCtx : llvm::obf::FuncPassCtx {
		SemanticDiffusionConfig Cfg;
		FunctionObfContext& FOC;
		llvm::obf::Rng InitRng;
		llvm::obf::Rng ReseedRng;  // per-BB reseed pick + constant
		llvm::obf::Rng ApplyRng;   // per-site probability gating

		SDiffCtx(Function& F, FunctionAnalysisManager& AM)
			: FuncPassCtx(F, AM, "sdiff"),
			Cfg(SdiffImpl::getSDiffConfig(F, AM)),
			FOC(*AM.getResult<FunctionObfContextAnalysis>(F)),

			InitRng(R.fork("init")),
			ReseedRng(R.fork("reseed")),
			ApplyRng(R.fork("apply")) {
		}
	};



	SemanticDiffusionConfig SdiffImpl::getSDiffConfig(Function& F, FunctionAnalysisManager& AM) {
		const ObfuscationConfig obfConfig = getObfConfig(F, AM);
		auto passConfig = obfConfig.getPassConfig("sdiff");
		if (!passConfig.has_value()) {
			SemanticDiffusionConfig cfg;
			cfg.enable = false;
			return cfg;
		}
		SemanticDiffusionConfig cfg = SemanticDiffusionConfig::fromPassConfig(*passConfig);
		if (!cfg.validate()) {
			errs() << "SDiff: Invalid configuration for function " << F.getName()
				<< ", disabling pass\n";
			cfg.enable = false;
		}
		return cfg;
	}

	AllocaInst* SdiffImpl::createVolatileI32Slot(SDiffCtx& Ctx, Function& F, StringRef Name) {
		LLVMContext& C = F.getContext();
		BasicBlock& Entry = F.getEntryBlock();
		IRBuilder<> B(&*Entry.getFirstInsertionPt());

		auto* AI = B.CreateAlloca(Type::getInt32Ty(C), nullptr, Name);

		// Deterministic *IR*, runtime-varying value source (stack address),
		// combined with deterministic per-pass RNG constant.
		Value* E = llvm::obf::getSDiffEntropyI32(B, AI);
		uint32_t K = Ctx.InitRng.u32();
		Value* Init = B.CreateXor(E, ConstantInt::get(Type::getInt32Ty(C), K), "sdiff.init");


		auto* St = B.CreateStore(Init, AI);
		St->setVolatile(true);
		return AI;
	}

	Value* SdiffImpl::loadVolatileI32(IRBuilder<>& B, AllocaInst* Slot, StringRef N) {
		auto* L = B.CreateLoad(Type::getInt32Ty(B.getContext()), Slot, N);
		L->setVolatile(true);
		return L;
	}

	Value* SdiffImpl::buildKey(IRBuilder<>& B, ArrayRef<AllocaInst*> Slots, unsigned BitWidth, unsigned Tag) {
		LLVMContext& C = B.getContext();
		Type* I32 = Type::getInt32Ty(C);

		// Fresh loads each call (critical): keys must be *not provably equal* between calls.
		Value* Acc = ConstantInt::get(I32, 0x13579BDFu ^ (Tag * 0x9e3779b1u));
		for (unsigned i = 0; i < Slots.size(); ++i) {
			Value* L = loadVolatileI32(B, Slots[i], "sdiff.l");
			// Mix: Acc = (Acc + L*C) ^ (Acc >> r)
			uint32_t Cc = 0x9e3779b1u + (i * 0x85ebca6bu);
			unsigned r = 5 + ((i + Tag) % 11); // 5..15
			Value* M = B.CreateMul(L, ConstantInt::get(I32, Cc), "sdiff.m");
			Acc = B.CreateAdd(Acc, M, "sdiff.a");
			Value* Shr = B.CreateLShr(Acc, ConstantInt::get(I32, r), "sdiff.shr");
			Acc = B.CreateXor(Acc, Shr, "sdiff.x");
		}

		// Cast to requested width
		if (BitWidth <= 32) {
			Type* T = IntegerType::get(C, BitWidth);
			return (BitWidth == 32) ? Acc : B.CreateTrunc(Acc, T, "sdiff.k");
		}
		// >32: zext to i64 and expand
		Type* I64 = Type::getInt64Ty(C);
		Value* Z = B.CreateZExt(Acc, I64, "sdiff.z");
		// extra mixing in 64-bit space
		Value* Z2 = B.CreateXor(Z, B.CreateShl(Z, ConstantInt::get(I64, 17), "sdiff.shl"), "sdiff.x2");
		Type* T = IntegerType::get(C, BitWidth);
		if (BitWidth == 64) return Z2;
		return B.CreateTrunc(Z2, T, "sdiff.k64");
	}

	bool SdiffImpl::isGoodICmpOperand(Value* V) {
		if (!V) return false;
		Type* T = V->getType();
		if (!T->isIntegerTy()) return false;
		unsigned BW = cast<IntegerType>(T)->getBitWidth();
		if (BW < 2 || BW > 64) return false;
		if (isa<Constant>(V)) return false;
		if (isa<PHINode>(V)) return false;
		return true;
	}

	ICmpInst::Predicate SdiffImpl::toUnsignedRelPred(ICmpInst::Predicate P) {
		switch (P) {
		case ICmpInst::ICMP_SLT: return ICmpInst::ICMP_ULT;
		case ICmpInst::ICMP_SLE: return ICmpInst::ICMP_ULE;
		case ICmpInst::ICMP_SGT: return ICmpInst::ICMP_UGT;
		case ICmpInst::ICMP_SGE: return ICmpInst::ICMP_UGE;
		default: return P;

		}

	}

	// Semantic-preserving diffusion for integer icmps:
	//  - EQ/NE: apply the same bijection to both operands (xor-xor).
	//  - Ordered preds: (signed -> bias into unsigned space), then zext to BW+1 and add the same constant.
	//    Using BW+1 guarantees no overflow, so ordering is preserved.
	bool SdiffImpl::tryDiffuseICmp(SDiffCtx& Ctx, ICmpInst& Cmp, ArrayRef<AllocaInst*> Slots) {
		if (Slots.empty())
			return false;

		Value* LHS = Cmp.getOperand(0);
		Value* RHS = Cmp.getOperand(1);
		if (!isGoodICmpOperand(LHS) || !isGoodICmpOperand(RHS))
			return false;

		auto* ITy = dyn_cast<IntegerType>(LHS->getType());
		if (!ITy)
			return false;
		unsigned BW = ITy->getBitWidth();
		if (BW < 2 || BW > 64)
			return false;

		IRBuilder<> B(&Cmp);
		ICmpInst::Predicate Pred = Cmp.getPredicate();

		// EQ / NE: preserve semantics by transforming both sides with the same reversible mapping.
		if (Pred == ICmpInst::ICMP_EQ || Pred == ICmpInst::ICMP_NE) {
			Value* K1 = buildKey(B, Slots, BW, /*Tag=*/1);
			Value* K2 = buildKey(B, Slots, BW, /*Tag=*/2);

			Value* L1 = B.CreateXor(LHS, K1, "sdiff.x1");
			Value* L2 = B.CreateXor(L1, K2, "sdiff.x2");
			Value* R1 = B.CreateXor(RHS, K1, "sdiff.x1");
			Value* R2 = B.CreateXor(R1, K2, "sdiff.x2");

			Cmp.setOperand(0, L2);
			Cmp.setOperand(1, R2);
			return true;

		}

		// Ordered predicates: handle unsigned directly; handle signed by xoring sign bit then using unsigned predicate.
		bool IsSigned = false;
		ICmpInst::Predicate UPred = Pred;
		switch (Pred) {
		case ICmpInst::ICMP_ULT:
		case ICmpInst::ICMP_ULE:
		case ICmpInst::ICMP_UGT:
		case ICmpInst::ICMP_UGE:
			break;
		case ICmpInst::ICMP_SLT:
		case ICmpInst::ICMP_SLE:
		case ICmpInst::ICMP_SGT:
		case ICmpInst::ICMP_SGE:
			IsSigned = true;
			UPred = toUnsignedRelPred(Pred);
			break;
		default:
			return false;

		}

		Value* A = LHS;
		Value* C = RHS;
		if (IsSigned) {
			Constant* SignBit = ConstantInt::get(ITy, APInt::getSignMask(BW));
			A = B.CreateXor(A, SignBit, "sdiff.sbias.lhs");
			C = B.CreateXor(C, SignBit, "sdiff.sbias.rhs");

		}

		// Order-preserving mask: add same constant in BW+1 (no overflow).
		Value* K = buildKey(B, Slots, BW, /*Tag=*/(unsigned)Pred);
		Type* WideTy = IntegerType::get(Cmp.getContext(), BW + 1);
		Value* Az = B.CreateZExt(A, WideTy, "sdiff.zlhs");
		Value* Cz = B.CreateZExt(C, WideTy, "sdiff.zrhs");
		Value* Kz = B.CreateZExt(K, WideTy, "sdiff.zk");
		Value* Ap = B.CreateAdd(Az, Kz, "sdiff.addlhs");
		Value* Cp = B.CreateAdd(Cz, Kz, "sdiff.addrhs");

		auto* NewCmp = cast<ICmpInst>(B.CreateICmp(UPred, Ap, Cp, "sdiff.cmp"));
		NewCmp->copyMetadata(Cmp);
		Cmp.replaceAllUsesWith(NewCmp);
		Cmp.eraseFromParent();
		return true;

	}


} // namespace

PreservedAnalyses SemanticDiffusionPass::run(Function& F, FunctionAnalysisManager& AM) {
	if (F.isDeclaration())
		return PreservedAnalyses::all();

	SDiffCtx Ctx(F, AM);
	if (!Ctx.Cfg.enable)
		return PreservedAnalyses::all();

	auto& DT = AM.getResult<DominatorTreeAnalysis>(F);

	// Create volatile slots
	SmallVector<AllocaInst*, 8> Slots;
	Slots.reserve((unsigned)Ctx.Cfg.slots);
	for (int i = 0; i < Ctx.Cfg.slots; ++i) {
		Slots.push_back(SdiffImpl::createVolatileI32Slot(Ctx, F, ("sdiff.slot." + Twine(i)).str()));
	}

	// Optional per-block reseed of one slot
	for (BasicBlock& BB : F) {
		if (!DT.isReachableFromEntry(&BB))
			continue;

		if (&BB == &F.getEntryBlock()) continue;

		// Use a real insertion point (safe w/ EH pads too).
		auto ItIP = BB.getFirstInsertionPt();
		if (ItIP == BB.end()) continue;
		Instruction* IP = &*ItIP;



		IRBuilder<> B(IP);
		if (Slots.empty()) continue;

		unsigned Pick = (unsigned)Ctx.ReseedRng.range((uint32_t)Slots.size());
		AllocaInst* Slot = Slots[Pick];

		Value* E = llvm::obf::getSDiffEntropyI32(B, Slot);
		uint32_t AddK = (Ctx.ReseedRng.u32() | 1u);
		Value* V = B.CreateAdd(E, ConstantInt::get(Type::getInt32Ty(B.getContext()), AddK), "sdiff.reseed");


		auto* St = B.CreateStore(V, Slot);
		St->setVolatile(true);
	}

	bool Changed = false;
	int Budget = Ctx.Cfg.maxSites;

	// Target: ICmp operands
	for (BasicBlock& BB : F) {
		if (!DT.isReachableFromEntry(&BB))
			continue;


		for (auto It = BB.begin(), End = BB.end(); It != End; ) {
			Instruction* I = &*It++;
			auto* Cmp = dyn_cast<ICmpInst>(I);
			if (!Cmp) continue;
			if (Budget <= 0) break;
			if (Ctx.ApplyRng.range(100) >= (uint32_t)Ctx.Cfg.prob) continue;
			if (!SdiffImpl::tryDiffuseICmp(Ctx, *Cmp, Slots)) continue;
			Changed = true;
			--Budget;

		}


		if (Budget <= 0) break;
	}

	if (!Changed)
		return PreservedAnalyses::all();

	PreservedAnalyses PA = PreservedAnalyses::none();
	PA.preserveSet<CFGAnalyses>();
	return PA;
}
