#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include "llvm/Transforms/Obfuscator/VMPass_Impl.h"
#include "llvm/Transforms/Obfuscator/VMPass_ISA.h"
#include "llvm/Transforms/Obfuscator/VMPass_Emitter.h"
#include "llvm/Transforms/Obfuscator/VMPass_Verifier.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"

#include <functional>
using namespace llvm;

#define DEBUG_TYPE "vm"

STATISTIC(VMFunctions, "Functions virtualised by VMPass");



bool VMImpl::run() {
	// Demote PHI nodes to memory
	SmallVector<PHINode*, 32> Phis;
	for (BasicBlock& BB : F)
		for (Instruction& I : BB)
			if (auto* PN = dyn_cast<PHINode>(&I)) Phis.push_back(PN);
	for (PHINode* PN : Phis) DemotePHIToStack(PN);






	//     Lower/strip intrinsics that clang emits at -O0 but the VM cannot
	//      encode.  Three tiers:
	//        A) Strip  — debug, lifetime, assume: zero runtime semantics.
	//        B) Memory — memcpy/memmove/memset with constant size ≤ 8:
	//                    replace with a single typed load+store or store.
	//        C) Float  — fabs, fmuladd, fma, minnum, maxnum, copysign:
	//                    expand to FNeg/FMul/FAdd/FCmp/Select the VM handles.
	//        D) Int    — abs: expand to ICmp/Sub/Select.
	//      Anything else stays and isize() will markUnsupported gracefully.
	{
		SmallVector<CallInst*, 32> Intrinsics;
		for (BasicBlock& BB : F)
			for (Instruction& I : BB)
				if (auto* CI = dyn_cast<CallInst>(&I))
					if (auto* CF = CI->getCalledFunction(); CF && CF->isIntrinsic())
						Intrinsics.push_back(CI);

		for (CallInst* CI : Intrinsics) {
			Intrinsic::ID IID = CI->getCalledFunction()->getIntrinsicID();
			IRBuilder<> B(CI);

			//  Tier A: strip ─
			switch (IID) {
			case Intrinsic::lifetime_start:
			case Intrinsic::lifetime_end:
			case Intrinsic::dbg_declare:
			case Intrinsic::dbg_value:
			case Intrinsic::dbg_assign:
			case Intrinsic::assume:
				CI->eraseFromParent();
				continue;
			default: break;
			}

			//  Tier B: memcpy / memmove 
			if (IID == Intrinsic::memcpy || IID == Intrinsic::memmove) {
				if (auto* SzC = dyn_cast<ConstantInt>(CI->getArgOperand(2))) {
					Type* ElemTy = nullptr;
					switch (SzC->getZExtValue()) {
					case 1: ElemTy = I8Ty;  break;
					case 2: ElemTy = I16Ty; break;
					case 4: ElemTy = I32Ty; break;
					case 8: ElemTy = I64Ty; break;
					default: break;
					}
					if (ElemTy) {
						B.CreateStore(B.CreateLoad(ElemTy, CI->getArgOperand(1), "mc.ld"),
							CI->getArgOperand(0));
						CI->eraseFromParent();
						continue;
					}
				}
				continue; // non-constant / odd size → markUnsupported later
			}

			//  Tier B: memset ─
			if (IID == Intrinsic::memset) {
				auto* SzC = dyn_cast<ConstantInt>(CI->getArgOperand(2));
				auto* ValC = dyn_cast<ConstantInt>(CI->getArgOperand(1));
				if (SzC && ValC && SzC->getZExtValue() <= 8) {
					uint64_t Sz = SzC->getZExtValue();
					uint8_t  Val = (uint8_t)ValC->getZExtValue();
					uint64_t Fill = 0;
					for (uint64_t i = 0; i < Sz; ++i) Fill |= ((uint64_t)Val << (i * 8));
					Type* ElemTy = IntegerType::get(Ctx, (unsigned)(Sz * 8));
					B.CreateStore(ConstantInt::get(ElemTy, Fill), CI->getArgOperand(0));
					CI->eraseFromParent();
					continue;
				}
				continue;
			}

			//  Tier C: fabs(x) → x >= 0.0 ? x : -x 
			if (IID == Intrinsic::fabs) {
				Value* X = CI->getArgOperand(0);
				Type* FT = X->getType();
				Value* Neg = B.CreateFNeg(X, "fabs.neg");
				Value* Cmp = B.CreateFCmpOGE(X, ConstantFP::get(FT, 0.0), "fabs.cmp");
				Value* R = B.CreateSelect(Cmp, X, Neg, "fabs.r");
				CI->replaceAllUsesWith(R);
				CI->eraseFromParent();
				continue;
			}

			//  Tier C: fmuladd / fma → a*b + c ─
			if (IID == Intrinsic::fmuladd || IID == Intrinsic::fma) {
				Value* A = CI->getArgOperand(0);
				Value* Bv = CI->getArgOperand(1);
				Value* C = CI->getArgOperand(2);
				Value* R = B.CreateFAdd(B.CreateFMul(A, Bv, "fma.mul"), C, "fma.add");
				CI->replaceAllUsesWith(R);
				CI->eraseFromParent();
				continue;
			}

			//  Tier C: minnum / maxnum 
			if (IID == Intrinsic::minnum) {
				Value* A = CI->getArgOperand(0), * Bv = CI->getArgOperand(1);
				Value* R = B.CreateSelect(B.CreateFCmpOLT(A, Bv, "min.cmp"), A, Bv, "min.r");
				CI->replaceAllUsesWith(R);
				CI->eraseFromParent();
				continue;
			}
			if (IID == Intrinsic::maxnum) {
				Value* A = CI->getArgOperand(0), * Bv = CI->getArgOperand(1);
				Value* R = B.CreateSelect(B.CreateFCmpOGT(A, Bv, "max.cmp"), A, Bv, "max.r");
				CI->replaceAllUsesWith(R);
				CI->eraseFromParent();
				continue;
			}

			//  Tier C: copysign(mag, sgn)
			if (IID == Intrinsic::copysign) {
				Value* Mag = CI->getArgOperand(0);
				Value* Sgn = CI->getArgOperand(1);
				Type* FT = Mag->getType();
				Value* Zero = ConstantFP::get(FT, 0.0);
				Value* NegM = B.CreateFNeg(Mag, "cs.nm");
				Value* AbsM = B.CreateSelect(B.CreateFCmpOGE(Mag, Zero, "cs.ac"), Mag, NegM, "cs.am");
				Value* R = B.CreateSelect(B.CreateFCmpOGE(Sgn, Zero, "cs.sc"),
					AbsM, B.CreateFNeg(AbsM, "cs.na"), "cs.r");
				CI->replaceAllUsesWith(R);
				CI->eraseFromParent();
				continue;
			}

			//  Tier D: abs(x, _) → x < 0 ? -x : x ─
			if (IID == Intrinsic::abs) {
				Value* X = CI->getArgOperand(0);
				Type* IT = X->getType();
				Value* Zero = ConstantInt::get(IT, 0);
				Value* Neg = B.CreateSub(Zero, X, "abs.neg");
				Value* R = B.CreateSelect(B.CreateICmpSLT(X, Zero, "abs.cmp"), Neg, X, "abs.r");
				CI->replaceAllUsesWith(R);
				CI->eraseFromParent();
				continue;
			}

			// Anything else: leave in place, isize() will markUnsupported.
		}
	}



	// Widen f32 allocas to f64 so OP_LOAD_F / OP_STORE_F (which always
	// operate on 8 bytes) never read/write past the end of a 4-byte slot.
	// At -O0 each float local is an alloca used only by load/store float;
	// widening is semantics-preserving: fpext on stores, fptrunc on loads.
	{
		SmallVector<AllocaInst*, 16> FloatAllocas;
		for (BasicBlock& BB : F)
			for (Instruction& I : BB)
				if (auto* AI = dyn_cast<AllocaInst>(&I))
					if (AI->getAllocatedType()->isFloatTy())
						FloatAllocas.push_back(AI);

		for (AllocaInst* AI : FloatAllocas) {
			IRBuilder<> AB(AI);
			auto* NewAI = AB.CreateAlloca(DoubleTy, nullptr, AI->getName() + ".f2d");
			NewAI->setAlignment(Align(8));

			SmallVector<Instruction*, 16> ToErase;
			SmallVector<std::pair<Use*, Value*>, 16> ToReplace;

			for (Use& U : AI->uses()) {
				auto* User = cast<Instruction>(U.getUser());
				if (auto* SI = dyn_cast<StoreInst>(User)) {
					IRBuilder<> B(SI);
					B.CreateStore(B.CreateFPExt(SI->getValueOperand(), DoubleTy, "f2d.ext"), NewAI);
					ToErase.push_back(SI);
				}
				else if (auto* LI = dyn_cast<LoadInst>(User)) {
					IRBuilder<> B(LI);
					Value* Dbl = B.CreateLoad(DoubleTy, NewAI, "f2d.ld");
					Value* Trn = B.CreateFPTrunc(Dbl, Type::getFloatTy(Ctx), "f2d.trn");
					LI->replaceAllUsesWith(Trn);
					ToErase.push_back(LI);
				}
				else {
					ToReplace.push_back({ &U, NewAI });
				}
			}
			for (Instruction* I : ToErase)  I->eraseFromParent();
			for (auto& [U, V] : ToReplace)  U->set(V);
			AI->eraseFromParent();
		}
	}



	// Compile function body to bytecode
	E.setOpcodeMap(&OpMap);
	E.setTargetBlind(SaltConst, BlindTargets);
	E.setConstInStream(ConstInStream);
	E.setKeyedDispatch(SaltConst, KeyedDispatch);
	E.setSuperOps(SuperOps);
	E.setISAEnc(&IsaEnc);
	if (!E.run(F, CTSalt, M.getDataLayout())) {
		FailReason = E.getFailReason().str();
		if (FailReason.empty()) FailReason = "bytecode emission failed";
		return false;
	}

	if (ObfVerify) {
		std::string VErr;
		uint32_t BadIP = 0;
		if (!verifyBytecode(E, CTSalt, OpMap, VErr, BadIP, SaltConst, BlindTargets, KeyedDispatch)) {
			FailReason = ("bytecode verify failed at ip " + std::to_string(BadIP) + ": " + VErr);
			return false;
		}
	}

	// Compute power-of-2 padded register file sizes 
	NVRAlloc = nextPow2(E.NVR);
	NVR64Alloc = nextPow2(E.NVR64);
	NPRAlloc = nextPow2(E.NPR);
	NFRAlloc = nextPow2(E.NFR);


	// generate per-slot XOR keys for register encryption ————
	// Keys are compile-time constants derived from a forked RNG with a
	// distinct label ("vm.regkeys") so they do not perturb any existing
	// RNG sequence.  One key per allocated slot (power-of-2 padded).
	if (RegEncrypt) {
		auto KeyRng = R.fork("vm.regkeys");
		RegKeys.resize(NVRAlloc);
		for (auto& K : RegKeys)   K = (uint32_t)KeyRng.u32();
		Reg64Keys.resize(NVR64Alloc);
		for (auto& K : Reg64Keys) K = KeyRng.u64();
		FRegKeys.resize(NFRAlloc);
		for (auto& K : FRegKeys)  K = KeyRng.u64();

		LLVM_DEBUG(dbgs() << "[vm] generated register keys for '"
			<< F.getName() << "' [vreg=" << NVRAlloc
			<< " vreg64=" << NVR64Alloc
			<< " freg=" << NFRAlloc << "]\n");
	}


	// Generate per-function engine-pointer XOR mask 
	// Uses a forked RNG so it does not perturb any existing sequence.
	{
		auto EngRng = R.fork("vm.engine.mask");
		EngineMask = ((uint64_t)EngRng.u32() << 32) | EngRng.u32();
		// Ensure mask is non-zero to avoid storing the raw pointer.
		if (EngineMask == 0) EngineMask = 0xDEADBEEFCAFEBABEULL;
	}

	// generate anti-debug poison key + init TargetInfo 
	{
		auto ADRng = R.fork("vm.antidebug");
		ADPoisonKey = ADRng.u32();
		if (ADPoisonKey == 0) ADPoisonKey = 0xDEAD07u;
	}
	TI = obf::TargetInfo::fromModule(M);

	// generate per-function callee XOR mask 
	{
		auto CMRng = R.fork("vm.callee.mask");
		CalleeMask = ((uint64_t)CMRng.u32() << 32) | CMRng.u32();
		if (CalleeMask == 0) CalleeMask = 0xCAFEBABE08080808ULL;
	}


	// Record return slot before stripping body
	computeReturnInfo();


	// Erase original body
	stripBody();

	// Emit globals
	buildBytecodeGlobal();
	buildCalleeGlobal();

	// Nested-VM: each eligible opcode's helper Function* must exist before
	// buildOpcodeHandlers (inside populateVMEngine, below) can emit a call to
	// it. See the sequencing note above virtualizeNestedHelpersOnce().
	if (NestedVM) {
		for (const auto& H : kNestedHelperOrder)
			if (opcodeNests(H.Op))
				getOrCreateNestedHelper(H.Op);
	}

	// Populate shared vm_engine (first function only)
	populateVMEngine();

	// Nested-VM: inner-virtualize the helper(s), once per module. Must run
	// AFTER populateVMEngine() above -- see sequencing note.
	if (NestedVM)
		virtualizeNestedHelpersOnce();

	// Extend CALL handler switches if this function introduced new FTys
	ensureCallFTyCases();

	// Build per-function handler table (uses shared OpcBB with per-function permutation)
	VMEngine::getSharedState(M, EngineId); // ensure shared state exists before table build
	SharedEngineMode = true;
	buildHandlerTable();
	SharedEngineMode = false;


	// Build thin wrapper that tail-calls vm_engine
	buildWrapper();

	// Split wrapper into phases + insert junk (hardened only)
	hardenWrapper();

	// switch-dispatch flattening of wrapper (hardened only)
	flattenWrapper();

	// MBA substitutions on wrapper arithmetic (hardened only)
	mbaHardenWrapper();

	// Encryption constructor (per-function, targets GVBytecodeRT)
	buildEncryptCtor();

	// .init_array anti-debug key-mask fold (bindAntiDebug only; must be
	// registered at a lower .init_array priority than buildEncryptCtor's
	// AES ctor above so it runs first at startup and corrupts the masked
	// key global before the AES ctor unmasks it)
	buildAntiDebugKeyBindCtor();

	// .init_array bytecode integrity hash (hardened + antiDebug)
	buildIntegrityHashCtor();

	// .init_array callee XOR masking (hardened only)
	buildCalleeXorCtor();

	++VMFunctions;
	return true;
}