#include "llvm/Transforms/Obfuscator/Utils.h"
#include "llvm/Transforms/Obfuscator/Rng.h"

#include "llvm/ADT/Twine.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IntrinsicInst.h"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"

#include <sstream>
#include <regex>
#include <unordered_map>
#include <optional>



using namespace llvm;

namespace llvm::obf {

	std::vector<std::string> readAnnotations(Function* F)
	{
		std::vector<std::string> annotations;

		Module* M = F->getParent();
		if (!M)
			return annotations;

		GlobalVariable* GA = M->getGlobalVariable("llvm.global.annotations");
		if (!GA || !GA->hasInitializer())
			return annotations;

		auto* Arr = dyn_cast<ConstantArray>(GA->getInitializer());
		if (!Arr)
			return annotations;

		for (auto& Op : Arr->operands()) {
			auto* CS = dyn_cast<ConstantStruct>(Op);
			if (!CS || CS->getNumOperands() < 2)
				continue;

			// Operand 0: annotated entity
			Value* Annotated = CS->getOperand(0)->stripPointerCasts();
			if (Annotated != F)
				continue;

			// Operand 1: annotation string global
			auto* AnnoGV = dyn_cast<GlobalVariable>(
				CS->getOperand(1)->stripPointerCasts());
			if (!AnnoGV || !AnnoGV->hasInitializer())
				continue;

			auto* Data =
				dyn_cast<ConstantDataArray>(AnnoGV->getInitializer());
			if (!Data || !Data->isString())
				continue;

			// Add each annotation separately (don't convert to lowercase yet)
			annotations.push_back(Data->getAsCString().str());
		}

		return annotations;
	}

	llvm::Value* getSDiffEntropyI32(IRBuilder<>& B, Value* AnchorPtr) {
		LLVMContext& C = B.getContext();
		Type* I64 = Type::getInt64Ty(C);
		Type* I32 = Type::getInt32Ty(C);

		// AnchorPtr is typically an alloca (slot), so this is always non-constant.
		Value* P2I = B.CreatePtrToInt(AnchorPtr, I64, "sdiff.entropy.p2i");
		Value* Tr = B.CreateTrunc(P2I, I32, "sdiff.entropy.i32");
		return B.CreateFreeze(Tr, "sdiff.entropy.freeze");
	}

	llvm::AllocaInst* ensureEntropyAllocaAtEntryBegin(Function& F) {
		LLVMContext& C = F.getContext();
		Type* I8 = Type::getInt8Ty(C);

		static constexpr const char* EntropyAllocName = "obf.entropy.i8";
		BasicBlock& Entry = F.getEntryBlock();

		// Find existing entropy alloca if any.
		AllocaInst* Entropy = nullptr;
		for (Instruction& I : Entry) {
			if (auto* AI = dyn_cast<AllocaInst>(&I)) {
				if (AI->getName() == EntropyAllocName) {
					Entropy = AI;
					break;
				}
			}
		}

		// Earliest legal point in entry (after PHIs).
		Instruction* InsertBefore = nullptr;
		for (Instruction& I : Entry) {
			if (isa<PHINode>(&I))
				continue;
			InsertBefore = &I;
			break;
		}
		if (!InsertBefore)
			InsertBefore = Entry.getTerminator();

		if (!Entropy) {
			IRBuilder<> B(InsertBefore);
			Entropy = B.CreateAlloca(I8, nullptr, EntropyAllocName);
		}
		else if (Entropy != InsertBefore) {
			// Force it to dominate everything in entry, even if other passes reshuffle.
			Entropy->moveBefore(InsertBefore);
		}

		return Entropy;
	}

	llvm::Value* getObfEntropyI32Stable(IRBuilder<>& B) {
		if (BasicBlock* BB = B.GetInsertBlock()) {
			if (Function* F = BB->getParent())
				(void)ensureEntropyAllocaAtEntryBegin(*F);
		}
		return getObfEntropyI32(B);
	}

	llvm::Value* getObfEntropyI32(llvm::IRBuilder<>& B) {
		using namespace llvm;
		BasicBlock* BB = B.GetInsertBlock();
		Function* F = BB ? BB->getParent() : nullptr;
		LLVMContext& C = B.getContext();

		Type* i8Ty = Type::getInt8Ty(C);
		Type* i32Ty = Type::getInt32Ty(C);
		Type* i64Ty = Type::getInt64Ty(C);


		if (!F)
		{
			return ConstantInt::get(i32Ty, 0xC0FFEEu);
		}


		static constexpr const char* EntropyAllocName = "obf.entropy.i8";


		AllocaInst* Entropy = nullptr;
		BasicBlock& Entry = F->getEntryBlock();
		for (Instruction& I : Entry)
		{
			if (auto* AI = dyn_cast<AllocaInst>(&I))
			{
				if (AI->getName() == EntropyAllocName)
				{
					Entropy = AI;
					break;
				}
			}
		}


		if (!Entropy) {
			IRBuilder<> EB(&*Entry.getFirstInsertionPt());
			Entropy = EB.CreateAlloca(i8Ty, nullptr, EntropyAllocName);
		}

		Value* P2I = B.CreatePtrToInt(Entropy, i64Ty, "obf.entropy.p2i");
		Value* Tr = B.CreateTrunc(P2I, i32Ty, "obf.entropy.i32");
		return B.CreateFreeze(Tr, "obf.entropy.freeze");

	}

	AllocaInst* getOrCreateVolatileI32Slot(Function& F, StringRef Name, llvm::obf::Rng& R) {
		LLVMContext& C = F.getContext();
		Type* I32 = Type::getInt32Ty(C);

		BasicBlock& Entry = F.getEntryBlock();
		for (Instruction& I : Entry) {
			if (auto* AI = dyn_cast<AllocaInst>(&I)) {
				if (AI->getName() == Name && AI->getAllocatedType() == I32)
					return AI;
			}
		}

		// IMPORTANT: Pin entropy alloca first and insert *after it*.
		AllocaInst* Entropy = llvm::obf::ensureEntropyAllocaAtEntryBegin(F);

		Instruction* IP = Entropy->getNextNode();
		if (!IP)
			IP = Entry.getTerminator();

		IRBuilder<> EB(IP);

		auto* Slot = EB.CreateAlloca(I32, nullptr, Name);
		Slot->setAlignment(Align(4));

		// Robust init: do NOT call getObfEntropyI32 here (avoids dominance issues entirely).
		// Volatile loads make the value opaque; a constant init is fine.
		uint32_t K = (R.u32() | 1u);
		auto* St = EB.CreateStore(ConstantInt::get(I32, K), Slot);
		St->setVolatile(true);

		return Slot;
	}

	Value* makeRuntimeZero(IRBuilder<>& B, AllocaInst* VolSlot,
		unsigned BitWidth, llvm::obf::Rng& R,
		StringRef Tag) {
		LLVMContext& C = B.getContext();
		if (BitWidth == 0)
			return ConstantInt::get(Type::getInt1Ty(C), 0);

		Type* I32 = Type::getInt32Ty(C);

		auto* L1 = B.CreateLoad(I32, VolSlot, Twine(Tag) + ".l1");
		auto* L2 = B.CreateLoad(I32, VolSlot, Twine(Tag) + ".l2");
		L1->setVolatile(true);
		L2->setVolatile(true);

		// Add a random odd constant to keep shapes varied.
		uint32_t K = (R.u32() | 1u);
		Value* Kc = ConstantInt::get(I32, K);

		Value* A1 = B.CreateAdd(L1, Kc, Twine(Tag) + ".a1");
		Value* A2 = B.CreateAdd(L2, Kc, Twine(Tag) + ".a2");

		// Two common "zero-at-runtime" variants (since L1==L2 at runtime):
		//   sub(a1, a2)  == 0
		//   xor(a1, a2)  == 0
		Value* D = nullptr;
		switch (R.range(2)) {
		default:
		case 0:
			D = B.CreateSub(A1, A2, Twine(Tag) + ".zsub");
			break;
		case 1:
			D = B.CreateXor(A1, A2, Twine(Tag) + ".zxor");
			break;

		}

		Type* DstTy = IntegerType::get(C, BitWidth);
		if (BitWidth == 32)
			return D;
		if (BitWidth < 32)
			return B.CreateTrunc(D, DstTy, Twine(Tag) + ".tr");
		if (BitWidth <= 64)
			return B.CreateZExt(D, DstTy, Twine(Tag) + ".zx");

		// Fallback (you probably won't hit this in your passes).
		Value* Z64 = B.CreateZExt(D, Type::getInt64Ty(C), Twine(Tag) + ".zx64");
		return B.CreateZExtOrTrunc(Z64, DstTy, Twine(Tag) + ".zxN");

	}

	Value* xorWithRuntimeZero(IRBuilder<>& B, Value* V,
		AllocaInst* VolSlot, llvm::obf::Rng& R,
		StringRef Tag, unsigned Prob) {
		if (!V || !VolSlot)
			return V;
		if (!V->getType()->isIntegerTy())
			return V;

		Prob = std::min(Prob, 100u);
		if (Prob < 100 && R.range(100) >= Prob)
			return V;

		unsigned BW = cast<IntegerType>(V->getType())->getBitWidth();
		Value* Z = llvm::obf::makeRuntimeZero(B, VolSlot, BW, R, Tag);
		return B.CreateXor(V, Z, Twine(Tag) + ".xor0");

	}

	static bool valueEscapes(const Instruction& Inst) {
		if (!Inst.getType() || !Inst.getType()->isSized())
			return false;


		const BasicBlock* BB = Inst.getParent();
		for (const User* U : Inst.users()) {
			const Instruction* UI = dyn_cast<Instruction>(U);
			if (!UI) continue;

			if (isa<PHINode>(UI))
				return true;

			if (UI->getParent() != BB)
				return true;
		}
		return false;
	}

	bool repairSSA(Function& F) {
		if (F.isDeclaration())
			return false;

		bool Changed = false;
		BasicBlock* Entry = &F.getEntryBlock();

		// Iterate to a fixed point because demotion can expose more PHIs/escapes.
		for (unsigned Iter = 0; Iter < 16; ++Iter) {
			std::vector<PHINode*> Phis;
			std::vector<Instruction*> Regs;

			for (BasicBlock& BB : F) {
				for (Instruction& I : BB) {
					if (auto* PN = dyn_cast<PHINode>(&I)) {
						Phis.push_back(PN);
						continue;
					}

					// DemoteRegToStack only makes sense for non-void, first-class-ish values.
					if (I.getType()->isVoidTy())
						continue;

					// Token / label types are unsized — AllocaInst asserts on them.
					if (!I.getType()->isSized())
						continue;

					// Keep entry allocas in SSA form.
					if (isa<AllocaInst>(I) && I.getParent() == Entry)
						continue;

					if (valueEscapes(I) || I.isUsedOutsideOfBlock(&BB))
						Regs.push_back(&I);
				}
			}

			if (Regs.empty() && Phis.empty())
				break;

			// Demote regs first, then PHIs .
			for (Instruction* I : Regs) {
				DemoteRegToStack(*I, Entry->getTerminator());
				Changed = true;
			}

			for (PHINode* PN : Phis) {
				DemotePHIToStack(PN, std::nullopt);
				Changed = true;
			}
		}

		return Changed;
	}

	llvm::Instruction* getAllocaIP(llvm::Function& F) {
		llvm::BasicBlock& Entry = F.getEntryBlock();
		auto It = Entry.getFirstNonPHIOrDbgOrAlloca();
		if (It == Entry.end())
			return Entry.getTerminator();
		return &*It;
	}

	static bool valueEscapesForCFG(const llvm::Instruction& Inst) {
		if (!Inst.getType()->isSized())
			return false;
		const llvm::BasicBlock* BB = Inst.getParent();
		for (const llvm::User* U : Inst.users()) {
			const auto* UI = llvm::dyn_cast<llvm::Instruction>(U);
			if (!UI) continue;
			if (UI->getParent() != BB || llvm::isa<llvm::PHINode>(UI))
				return true;
		}
		return false;
	}

	bool demoteForCFGChange(llvm::Function& F, llvm::SmallVectorImpl<llvm::AllocaInst*>& OutNewAllocas) {
		if (F.isDeclaration())
			return false;

		llvm::BasicBlock& Entry = F.getEntryBlock();
		llvm::Instruction* AllocaIP = llvm::obf::getAllocaIP(F);
		if (!AllocaIP)
			AllocaIP = Entry.getTerminator();

		// Snapshot existing allocas so we can robustly collect the new reg2mem ones
		llvm::SmallPtrSet<llvm::AllocaInst*, 32> ExistingAllocas;
		for (llvm::Instruction& I : Entry)
			if (auto* AI = llvm::dyn_cast<llvm::AllocaInst>(&I))
				ExistingAllocas.insert(AI);

		std::vector<llvm::PHINode*> TmpPhi;
		std::vector<llvm::Instruction*> TmpReg;
		bool Changed = false;

		do {
			TmpPhi.clear();
			TmpReg.clear();

			for (llvm::BasicBlock& BB : F) {
				for (llvm::Instruction& I : BB) {
					if (auto* PN = llvm::dyn_cast<llvm::PHINode>(&I)) {
						TmpPhi.push_back(PN);
						continue;
					}

					
					// Never demote allocas (they're memory objects already; demoting their "result" pointer
					// can create non-promotable patterns and is not what we want for CFG safety).
					if (llvm::isa<llvm::AllocaInst>(I))
						continue;

					// Token / label / metadata types are unsized — DemoteRegToStack will
					// assert when creating an AllocaInst.  Skip them unconditionally.
					if (!I.getType()->isSized())
						continue;

					// Demote values that are likely to break once we add router-style edges:
					// - cross-block uses
					// - PHI uses
					if (!(llvm::isa<llvm::AllocaInst>(I) && I.getParent() == &Entry) &&
						(valueEscapesForCFG(I) || I.isUsedOutsideOfBlock(&BB))) {
						TmpReg.push_back(&I);
					}
				}
			}

			for (llvm::Instruction* I : TmpReg) {
				// Avoid trying to demote already-deleted instructions in case of cascades.
				if (!I || I->getParent() == nullptr)
					continue;
				llvm::DemoteRegToStack(*I, AllocaIP);
				Changed = true;
			}

			for (llvm::PHINode* PN : TmpPhi) {
				if (!PN || PN->getParent() == nullptr)
					continue;
				// Your tree already uses the std::optional overload.
				llvm::DemotePHIToStack(PN, std::nullopt);
				Changed = true;
			}

		} while (!TmpReg.empty() || !TmpPhi.empty());

		// Collect newly created allocas
		llvm::SmallPtrSet<llvm::AllocaInst*, 32> Seen;
		for (llvm::AllocaInst* AI : OutNewAllocas)
			Seen.insert(AI);

		for (llvm::Instruction& I : Entry) {
			auto* AI = llvm::dyn_cast<llvm::AllocaInst>(&I);
			if (!AI)
				continue;
			if (ExistingAllocas.count(AI))
				continue;
			if (!Seen.insert(AI).second)
				continue;
			OutNewAllocas.push_back(AI);
		}

		// IMPORTANT: initialize new allocas in entry so promotion doesn't introduce undef/UB
		// on "imaginary" flattened CFG paths.
		for (llvm::AllocaInst* AI : OutNewAllocas) {
			if (!AI || AI->getParent() != &Entry)
				continue;
			llvm::Type* Ty = AI->getAllocatedType();
			if (!Ty || !Ty->isSized())
				continue;
			llvm::Instruction* IP = AI->getNextNode();
			if (!IP) IP = Entry.getTerminator();
			llvm::IRBuilder<> B(IP);
			B.CreateStore(llvm::Constant::getNullValue(Ty), AI);
		}

		return Changed;
	}

	// Strict subset of mem2reg-promotable allocas (chosen to avoid any chance of asserting).
	// Anything that doesn't match stays in memory form (still correct; just not SSA for that value).
	static bool isAllocaPromotableStrict(const llvm::AllocaInst* AI) {
		if (!AI)
			return false;

		// mem2reg expects entry-block allocas and prefers static allocas.
		const llvm::BasicBlock* BB = AI->getParent();
		const llvm::Function* F = BB ? BB->getParent() : nullptr;
		if (!F || &F->getEntryBlock() != BB)
			return false;
		if (!AI->isStaticAlloca() || AI->isArrayAllocation())
			return false;

		llvm::Type* Ty = AI->getAllocatedType();
		if (!Ty || !Ty->isSized())
			return false;
		// Be conservative: only promote single-value types (scalars/vectors/pointers).
	   // This avoids corner cases where aggregate allocas can fail promotability in some LLVM versions.
		if (!Ty->isSingleValueType())
			return false;

		for (const llvm::User* U : AI->users()) {
			if (const auto* LI = llvm::dyn_cast<llvm::LoadInst>(U)) {
				if (LI->isVolatile() || LI->isAtomic())
					return false;
				if (LI->getPointerOperand() != AI)
					return false;
				if (LI->getType() != Ty)
					return false;
				continue;

			}
			if (const auto* SI = llvm::dyn_cast<llvm::StoreInst>(U)) {
				if (SI->isVolatile() || SI->isAtomic())
					return false;
				if (SI->getPointerOperand() != AI)
					return false;
				if (SI->getValueOperand()->getType() != Ty)
					return false;
				continue;

			}

			// Allow debug/lifetime intrinsics (common in debug builds).
			if (const auto* II = llvm::dyn_cast<llvm::IntrinsicInst>(U)) {
				switch (II->getIntrinsicID()) {
				case llvm::Intrinsic::lifetime_start:
				case llvm::Intrinsic::lifetime_end:
				case llvm::Intrinsic::dbg_declare:
				case llvm::Intrinsic::dbg_value:
					continue;
				default:
					return false;

				}
			}
			// Anything else (bitcasts, GEPs, ptrtoint, calls, etc.) => not promotable (strict).
			return false;
		}
		return true;
	}

	bool promoteDemotedAllocas(llvm::Function& F, llvm::ArrayRef<llvm::AllocaInst*> NewAllocas) {
		if (F.isDeclaration() || NewAllocas.empty())
			return false;

		llvm::SmallVector<llvm::AllocaInst*, 64> Work;
		Work.reserve(NewAllocas.size());

		for (llvm::AllocaInst* AI : NewAllocas) {
			if (!AI || !AI->getParent())
				continue;
			// Only promote entry allocas (mem2reg requirement)
			if (AI->getParent() != &F.getEntryBlock())
				continue;


		    // Use a strict filter to guarantee we never feed PromoteMemToReg a non-promotable alloca.
			if (!isAllocaPromotableStrict(AI))
				continue;
			Work.push_back(AI);

			
		}

		if (Work.empty())
			return false;

		llvm::DominatorTree DT(F);
		DT.recalculate(F);
		llvm::PromoteMemToReg(Work, DT);
		return true;
	}

	
	
}
