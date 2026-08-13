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
#include "llvm/Transforms/Obfuscator/OpaqueUtils.h"
#include "llvm/Transforms/Obfuscator/MBAUtils.h"
#include "llvm/Transforms/Obfuscator/Rng.h"

#include <functional>
using namespace llvm;

#define DEBUG_TYPE "vm"





//  VMImpl method bodies ─

void VMImpl::stripBody() {
	SmallVector<BasicBlock*, 32> BBs;
	for (BasicBlock& BB : F) BBs.push_back(&BB);
	for (BasicBlock* BB : BBs) BB->dropAllReferences();
	for (BasicBlock* BB : BBs) BB->eraseFromParent();
}


//  buildVMEntry 

void VMImpl::buildVMEntry()
{
	Entry = BasicBlock::Create(Ctx, "vm.entry", &F);
	IRBuilder<> B(Entry);



	// IMPORTANT: Re-create the original entry-block allocas *first*.
	//
	// The i64-ops runtime test observes a stack address via ptrtoint64.
	// If we allocate VM state before the original locals, we shift those
	// locals in the frame and change the ptrtoint value (breaking
	// correctness vs the base binary).
	SmallVector<AllocaInst*, 8> Reallocas;
	Reallocas.reserve(E.PHIAllocas.size());
	for (const auto& PA : E.PHIAllocas) {
		auto* NA = B.CreateAlloca(PA.AllocTy, nullptr, Twine(PA.Name) + ".v7");
		if (PA.A) NA->setAlignment(*PA.A);
		Reallocas.push_back(NA);
	}


	VMIP = B.CreateAlloca(I32Ty, nullptr, "vm.ip");
	VMSalt = B.CreateAlloca(I32Ty, nullptr, "vm.salt");
	VMRegs = B.CreateAlloca(I32Ty, B.getInt64(NVRAlloc), "vm.regs");
	VMRegs64 = B.CreateAlloca(I64Ty, B.getInt64(NVR64Alloc), "vm.regs64");
	VMPRegs = B.CreateAlloca(PtrTy, B.getInt64(NPRAlloc), "vm.pregs");
	VMFregs = B.CreateAlloca(DoubleTy, B.getInt64(NFRAlloc), "vm.fregs");

	// Write compile-time salt (volatile so optimizer cannot track its value)
	B.CreateStore(B.getInt32(SaltConst), VMSalt)->setVolatile(true);

	// Integer args -> vregs / vregs64
	for (Argument& A : F.args()) {
		Type* AT = A.getType();
		if (!AT->isIntegerTy()) continue;

		if (AT->isIntegerTy(64)) {
			stVR64(B, B.getInt32(E.VR64.lookup(&A)), &A);
			continue;
		}
		Value* V = (AT == I32Ty) ? (Value*)&A : B.CreateZExt(&A, I32Ty, "vm.ax");
		stVR(B, B.getInt32(E.VR.lookup(&A)), V);
	}
	// Pointer args -> pregs
	for (Argument& A : F.args()) {
		if (A.getType()->isPointerTy()) stPR(B, B.getInt32(E.PR.lookup(&A)), &A);
	}

	// Entry-block allocas -> pregs
	for (unsigned I = 0, N = (unsigned)E.PHIAllocas.size(); I != N; ++I)
		stPR(B, B.getInt32(E.PHIAllocas[I].Slot), Reallocas[I]);

	// Integer constants -> vregs
	for (auto& [S, CI] : E.ImmLoads) {
		Value* V = (CI->getType() == I32Ty)
			? (Value*)CI
			: B.CreateZExt(CI, I32Ty, "vm.cx");
		stVR(B, B.getInt32(S), V);
	}
	// i64 constants -> vregs64
	for (auto& [S, CI] : E.ImmLoads64) {
		Value* V = (CI->getType() == I64Ty) ? (Value*)CI : B.CreateZExtOrTrunc(CI, I64Ty, "vm.c64x");
		stVR64(B, B.getInt32(S), V);
	}
	// Pointer constants / globals -> pregs
	for (auto& [S, PV] : E.PtrLoads)
		stPR(B, B.getInt32(S), cast<Constant>(PV));


	// Float args -> fregs  
	for (Argument& A : F.args()) {
		Type* AT = A.getType();
		if (!AT->isFloatTy() && !AT->isDoubleTy()) continue;
		Value* V = AT->isDoubleTy() ? (Value*)&A
			: B.CreateFPExt(&A, DoubleTy, "vm.fa.ext");
		stFR(B, B.getInt32(E.FR.lookup(&A)), V);
	}
	// Float constants -> fregs  
	for (auto& [Slot, CF] : E.ImmLoadsF) {
		double DV = CF->getType()->isDoubleTy()
			? CF->getValueAPF().convertToDouble()
			: (double)CF->getValueAPF().convertToFloat();
		stFR(B, B.getInt32(Slot), ConstantFP::get(DoubleTy, DV));
	}


	// IP = 0  (entry block is always first, starts at offset 0)
	B.CreateStore(B.getInt32(0), VMIP)->setVolatile(true);
	// Point Eff* at per-function state for handler building
	setupEffLocal();
}





// computeReturnInfo: scan F for ReturnInst before stripBody 
// Records which register file slot the return value occupies so
// buildWrapper() can extract it after vm_engine returns.

void VMImpl::computeReturnInfo() {
	WrapRetSlot = -1;
	WrapRetKind = VMEngine::RK2_VOID;

	for (BasicBlock& BB : F) {
		auto* RI = dyn_cast<ReturnInst>(BB.getTerminator());
		if (!RI) continue;
		Value* RV = RI->getReturnValue();
		if (!RV) {
			WrapRetKind = VMEngine::RK2_VOID;
			WrapRetSlot = -1;
			return;  // void
		}
		Type* RT = RV->getType();
		if (RT->isPointerTy()) {
			auto It = E.PR.find(RV);
			if (It != E.PR.end()) {
				WrapRetKind = VMEngine::RK2_PTR;
				WrapRetSlot = (int)It->second;
			}
		}
		else if (RT->isIntegerTy(64)) {
			auto It = E.VR64.find(RV);
			if (It != E.VR64.end()) {
				WrapRetKind = VMEngine::RK2_I64;
				WrapRetSlot = (int)It->second;
			}
		}
		else if (RT->isFloatTy() || RT->isDoubleTy()) {
			auto It = E.FR.find(RV);
			if (It != E.FR.end()) {
				WrapRetKind = VMEngine::RK2_F64;
				WrapRetSlot = (int)It->second;
			}
		}
		else if (RT->isIntegerTy()) {
			auto It = E.VR.find(RV);
			if (It != E.VR.end()) {
				WrapRetKind = VMEngine::RK2_I32;
				WrapRetSlot = (int)It->second;
			}
		}
		return;  // first ReturnInst is enough
	}
}


//  buildWrapper: thin wrapper that tail-calls vm_engine
// Replaces the per-function interpreter with:
//   1. Stack-allocate register files
//   2. Pre-load arguments + constants into register files
//   3. Call @__vm_engine(bc, bc_len, regs, ..., handlers, fty_indices)
//   4. Extract return value from register file
//   5. Return

void VMImpl::buildWrapper() {
	Entry = BasicBlock::Create(Ctx, "vm.entry", &F);
	IRBuilder<> B(Entry);

	// constant blinding helpers 
	// When hardened=1, security-sensitive constants (salt, masks, register
	// keys, encrypted values, engine-table index) are materialised through
	// opaque expression trees instead of bare immediates.  Structural
	// constants (GEP indices, alloca sizes) are left as-is.
	auto WrapBlindRng = R.fork("vm.wrap.blind");
	llvm::obf::OpaqueUtils WrapOpaque(M, WrapBlindRng, "vm.wrap.opaque.i32");
	const bool Blind = Cfg.hardened;

	auto blindI32 = [&](uint32_t C) -> Value* {
		if (!Blind) return B.getInt32(C);
		return WrapOpaque.opaqueI32Const(B, C);
		};
	auto blindI64 = [&](uint64_t C) -> Value* {
		if (!Blind) return B.getInt64(C);
		Value* Lo = B.CreateZExt(
			WrapOpaque.opaqueI32Const(B, (uint32_t)(C & 0xFFFFFFFF)),
			I64Ty, "vm.w.b64.lo");
		Value* Hi = B.CreateShl(B.CreateZExt(
			WrapOpaque.opaqueI32Const(B, (uint32_t)(C >> 32)),
			I64Ty, "vm.w.b64.hi"),
			B.getInt64(32), "vm.w.b64.sh");
		return B.CreateOr(Lo, Hi, "vm.w.b64");
		};


	// per-function polymorphism RNG
	auto PolyRng = R.fork("vm.wrap.poly");
	const bool Poly = Cfg.hardened;

	// Fisher-Yates shuffle helper
	auto fyShuffle = [&](unsigned* Arr, unsigned N) {
		if (!Poly || N < 2) return;
		for (unsigned i = N - 1; i > 0; --i)
			std::swap(Arr[i], Arr[PolyRng.range(i + 1)]);
		};


	// Re-create original entry-block allocas (PHI demotions) 
	// Same ordering as buildVMEntry to preserve ptrtoint64 stability.
	SmallVector<AllocaInst*, 8> Reallocas;
	Reallocas.reserve(E.PHIAllocas.size());
	for (const auto& PA : E.PHIAllocas) {
		auto* NA = B.CreateAlloca(PA.AllocTy, nullptr, Twine(PA.Name) + ".v7");
		if (PA.A) NA->setAlignment(*PA.A);
		Reallocas.push_back(NA);
	}

	// allocate register files in shuffled order (hardened)
	AllocaInst* WRegs = nullptr;
	AllocaInst* WRegs64 = nullptr;
	AllocaInst* WFregs = nullptr;
	AllocaInst* WPregs = nullptr;
	{
		unsigned AllocOrd[] = { 0, 1, 2, 3 };
		fyShuffle(AllocOrd, 4);
		for (unsigned idx : AllocOrd) {
			switch (idx) {
			case 0: WRegs = B.CreateAlloca(I32Ty, B.getInt64(NVRAlloc), "vm.regs");   break;
			case 1: WRegs64 = B.CreateAlloca(I64Ty, B.getInt64(NVR64Alloc), "vm.regs64"); break;
			case 2: WFregs = B.CreateAlloca(DoubleTy, B.getInt64(NFRAlloc), "vm.fregs");  break;
			case 3: WPregs = B.CreateAlloca(PtrTy, B.getInt64(NPRAlloc), "vm.pregs");  break;
			}
		}
	}

	// Zero-initialize register files (shuffled order when hardened)
	auto zeroFill = [&](AllocaInst* A, Type* ElemTy, unsigned Count) {
		if (Count == 0) return;
		for (unsigned i = 0; i < Count; ++i)
			B.CreateStore(Constant::getNullValue(ElemTy),
				B.CreateGEP(ElemTy, A, B.getInt64(i)));
		};


	{
		unsigned FillOrd[] = { 0, 1, 2, 3 };
		fyShuffle(FillOrd, 4);
		for (unsigned idx : FillOrd) {
			switch (idx) {
			case 0: zeroFill(WRegs, I32Ty, NVRAlloc);   break;
			case 1: zeroFill(WRegs64, I64Ty, NVR64Alloc); break;
			case 2: zeroFill(WFregs, DoubleTy, NFRAlloc);   break;
			case 3: zeroFill(WPregs, PtrTy, NPRAlloc);   break;
			}
		}
	}


	// allocate + fill per-slot XOR key arrays ————————————————
	// Keys are compile-time constants from RegKeys[]/Reg64Keys[]/FRegKeys[].
	// Engine handlers will XOR with these keys on every register read/write.
	AllocaInst* WRegKeys = nullptr;
	AllocaInst* WReg64Keys = nullptr;
	AllocaInst* WFRegKeys = nullptr;
	const bool DoRegEncrypt = RegEncrypt && !RegKeys.empty();

	if (DoRegEncrypt) {
		WRegKeys = B.CreateAlloca(I32Ty, B.getInt64(NVRAlloc), "vm.regkeys");
		WReg64Keys = B.CreateAlloca(I64Ty, B.getInt64(NVR64Alloc), "vm.reg64keys");
		WFRegKeys = B.CreateAlloca(I64Ty, B.getInt64(NFRAlloc), "vm.fregkeys");
		for (unsigned i = 0; i < NVRAlloc; ++i)
			B.CreateStore(blindI32(RegKeys[i]),
				B.CreateGEP(I32Ty, WRegKeys, B.getInt64(i)));
		for (unsigned i = 0; i < NVR64Alloc; ++i)
			B.CreateStore(blindI64(Reg64Keys[i]),
				B.CreateGEP(I64Ty, WReg64Keys, B.getInt64(i)));
		for (unsigned i = 0; i < NFRAlloc; ++i)
			B.CreateStore(blindI64(FRegKeys[i]),
				B.CreateGEP(I64Ty, WFRegKeys, B.getInt64(i)));
	}


	// pre-load in shuffled category order (hardened) 
	// 8 independent load categories: each writes to distinct register
	// file slots, so execution order is arbitrary.  Shuffling breaks
	// structural pattern matching between different wrapper functions.

	auto emitIntArgs = [&]() {
		for (Argument& A : F.args()) {
			Type* AT = A.getType();
			if (!AT->isIntegerTy()) continue;
			if (AT->isIntegerTy(64)) {
				Value* Idx = B.getInt32(E.VR64.lookup(&A));
				Value* V = &A;
				if (V->getType() != I64Ty) V = B.CreateZExtOrTrunc(V, I64Ty, "vm.w64");
				if (DoRegEncrypt) {
					uint8_t Slot = E.VR64.lookup(&A);
					V = B.CreateXor(V, blindI64(Reg64Keys[Slot]), "vm.w64.enc");
				}
				B.CreateStore(V, B.CreateGEP(I64Ty, WRegs64, Idx));
				continue;
			}
			Value* Idx = B.getInt32(E.VR.lookup(&A));
			Value* V = (AT == I32Ty) ? (Value*)&A : B.CreateZExt(&A, I32Ty, "vm.wax");






			if (DoRegEncrypt) {
				uint8_t Slot = E.VR.lookup(&A);
				V = B.CreateXor(V, blindI32(RegKeys[Slot]), "vm.wax.enc");
			}
			B.CreateStore(V, B.CreateGEP(I32Ty, WRegs, Idx));
			continue;
		}


		};
	auto emitPtrArgs = [&]() {
		for (Argument& A : F.args()) {
			if (!A.getType()->isPointerTy()) continue;
			Value* Idx = B.getInt32(E.PR.lookup(&A));
			B.CreateStore(&A, B.CreateGEP(PtrTy, WPregs, Idx));
		}







		};
	auto emitAllocaArgs = [&]() {
		for (unsigned I = 0, N = (unsigned)E.PHIAllocas.size(); I != N; ++I) {
			Value* Idx = B.getInt32(E.PHIAllocas[I].Slot);
			B.CreateStore(Reallocas[I], B.CreateGEP(PtrTy, WPregs, Idx));




		}


		};
	auto emitIntConsts = [&]() {
		for (auto& [S, CI] : E.ImmLoads) {
			Value* V = (CI->getType() == I32Ty)
				? (Value*)CI
				: B.CreateZExt(CI, I32Ty, "vm.wcx");
			if (DoRegEncrypt) {
				if (auto* CIV = dyn_cast<ConstantInt>(V))
					V = blindI32((uint32_t)(CIV->getZExtValue() ^ RegKeys[S]));
				else
					V = B.CreateXor(V, blindI32(RegKeys[S]), "vm.wcx.enc");
			}
			B.CreateStore(V, B.CreateGEP(I32Ty, WRegs, B.getInt32(S)));


		}



		};
	auto emitI64Consts = [&]() {
		for (auto& [S, CI] : E.ImmLoads64) {
			Value* V = (CI->getType() == I64Ty)
				? (Value*)CI
				: B.CreateZExtOrTrunc(CI, I64Ty, "vm.wc64x");
			if (DoRegEncrypt) {
				if (auto* CIV = dyn_cast<ConstantInt>(V))
					V = blindI64(CIV->getZExtValue() ^ Reg64Keys[S]);
				else
					V = B.CreateXor(V, blindI64(Reg64Keys[S]), "vm.wc64x.enc");
			}
			B.CreateStore(V, B.CreateGEP(I64Ty, WRegs64, B.getInt32(S)));

		}



		};
	auto emitPtrConsts = [&]() {
		for (auto& [S, PV] : E.PtrLoads)
			B.CreateStore(cast<Constant>(PV), B.CreateGEP(PtrTy, WPregs, B.getInt32(S)));
		};
	auto emitFloatArgs = [&]() {
		for (Argument& A : F.args()) {
			Type* AT = A.getType();
			if (!AT->isFloatTy() && !AT->isDoubleTy()) continue;
			uint8_t Slot = E.FR.lookup(&A);
			Value* V = AT->isDoubleTy() ? (Value*)&A
				: B.CreateFPExt(&A, DoubleTy, "vm.wfa");
			if (DoRegEncrypt) {
				Value* Bits = B.CreateBitCast(V, I64Ty, "vm.wfa.bits");
				Bits = B.CreateXor(Bits, blindI64(FRegKeys[Slot]), "vm.wfa.enc");
				V = B.CreateBitCast(Bits, DoubleTy, "vm.wfa.eval");
			}
			B.CreateStore(V, B.CreateGEP(DoubleTy, WFregs, B.getInt32(Slot)));
		}
		};
	auto emitFloatConsts = [&]() {
		for (auto& [Slot, CF] : E.ImmLoadsF)
		{
			double DV = CF->getType()->isDoubleTy()
				? CF->getValueAPF().convertToDouble()
				: (double)CF->getValueAPF().convertToFloat();
			if (DoRegEncrypt)
			{
				uint64_t RawBits;
				std::memcpy(&RawBits, &DV, sizeof(uint64_t));
				RawBits ^= FRegKeys[Slot];
				if (Blind) {
					Value* BlindBits = blindI64(RawBits);
					Value* FVal = B.CreateBitCast(BlindBits, DoubleTy, "vm.wcf.blind");
					B.CreateStore(FVal, B.CreateGEP(DoubleTy, WFregs, B.getInt32(Slot)));
				}
				else {
					double EncDV;
					std::memcpy(&EncDV, &RawBits, sizeof(double));
					B.CreateStore(ConstantFP::get(DoubleTy, APFloat(EncDV)),
						B.CreateGEP(DoubleTy, WFregs, B.getInt32(Slot)));
				}







			}
			else
			{
				B.CreateStore(ConstantFP::get(DoubleTy, DV),
					B.CreateGEP(DoubleTy, WFregs, B.getInt32(Slot)));
			}
		}
		};

	// Dispatch in shuffled order (8 categories, Fisher-Yates)
	{
		using LoadFn = std::function<void()>;
		LoadFn Cats[] = {
			emitIntArgs, emitPtrArgs, emitAllocaArgs, emitIntConsts,
			emitI64Consts, emitPtrConsts, emitFloatArgs, emitFloatConsts,
		};
		unsigned CatOrd[] = { 0, 1, 2, 3, 4, 5, 6, 7 };
		fyShuffle(CatOrd, 8);
		for (unsigned idx : CatOrd) Cats[idx]();
	}


	// Lazy AES fetch: build the per-call context (unmasked round key + nonce +
	// keystream-block cache) that the shared engine's loadBC/loadBCDyn use.
	// Gated on SS->LazyMode (fixed by whichever function founded the shared
	// engine), not this function's own LazyDecrypt: the wrapper's argument
	// list must match the already-built engine signature regardless.
	auto* SS = VMEngine::getSharedState(M, EngineId);
	const bool LazyActive = SS->LazyMode;
	Value* LazyCtxArg = nullptr;
	if (LazyActive) {
		// buildWrapper() runs before buildEncryptCtor(); when lazy, create
		// the masked key-schedule/nonce/mask globals here so both this
		// wrapper and the later ctor (which reuses them instead of
		// re-emitting) can reference them.
		if (!GVAESExpandedKey) {
			SmallVector<Constant*, 176> MaskedRK;
			for (int i = 0; i < 176; i++)
				MaskedRK.push_back(ConstantInt::get(I8Ty, AESExpandedKey[i] ^ AESRKMask[i]));
			auto* RKTy = ArrayType::get(I8Ty, 176);
			// Writable when bindAntiDebug (mirrors buildEncryptCtor's creation
			// of this same global — only one site actually runs per function).
			GVAESExpandedKey = new GlobalVariable(
				M, RKTy, /*isConst=*/!BindAntiDebug, GlobalValue::PrivateLinkage,
				ConstantArray::get(RKTy, MaskedRK),
				(F.getName() + ".vm.aes.rk").str());
			GVAESExpandedKey->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
			GVAESExpandedKey->setAlignment(Align(16));

			SmallVector<Constant*, 8> NonceBytes;
			for (int i = 0; i < 8; i++)
				NonceBytes.push_back(ConstantInt::get(I8Ty, (AESNonce >> (8 * i)) & 0xFF));
			auto* NonceTy = ArrayType::get(I8Ty, 8);
			GVAESNonce = new GlobalVariable(
				M, NonceTy, /*isConst=*/true, GlobalValue::PrivateLinkage,
				ConstantArray::get(NonceTy, NonceBytes),
				(F.getName() + ".vm.aes.nonce").str());
			GVAESNonce->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

			SmallVector<Constant*, 176> MaskConsts;
			for (int i = 0; i < 176; i++)
				MaskConsts.push_back(ConstantInt::get(I8Ty, AESRKMask[i]));
			GVAESRKMask = new GlobalVariable(
				M, RKTy, /*isConst=*/true, GlobalValue::PrivateLinkage,
				ConstantArray::get(RKTy, MaskConsts),
				(F.getName() + ".vm.aes.rkmask").str());
			GVAESRKMask->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
		}

		auto* CtxTy = ArrayType::get(I8Ty, VMEngine::kLazyCtxSize);
		AllocaInst* LazyCtx = B.CreateAlloca(CtxTy, nullptr, "vm.lazy.ctx");
		LazyCtx->setAlignment(Align(16));

		// Unmask rk into ctx[0..175] (mirrors buildEncryptCtor's stack-unmask).
		B.CreateMemCpy(LazyCtx, Align(16), GVAESExpandedKey, Align(16), B.getInt64(176));
		for (unsigned i = 0; i < 176; i++) {
			Value* Ptr = B.CreateGEP(I8Ty, LazyCtx, B.getInt64(i), "vm.lazy.rk.p");
			Value* Byte = B.CreateLoad(I8Ty, Ptr, "vm.lazy.rk.b");
			Value* MkPtr = B.CreateGEP(I8Ty, GVAESRKMask, B.getInt64(i), "vm.lazy.mk.p");
			Value* Mk = B.CreateLoad(I8Ty, MkPtr, "vm.lazy.mk.b");
			B.CreateStore(B.CreateXor(Byte, Mk), Ptr);
		}

		// Copy nonce into ctx[176..183].
		Value* NonceDst = B.CreateGEP(I8Ty, LazyCtx,
			B.getInt64(VMEngine::kLazyCtxNonceOff), "vm.lazy.nonce.p");
		B.CreateMemCpy(NonceDst, Align(1), GVAESNonce, Align(1), B.getInt64(8));

		// cachedBlk = 0xFFFFFFFF: no block cached yet, forces a fetch on first use.
		Value* CachedBlkPtr = B.CreateGEP(I8Ty, LazyCtx,
			B.getInt64(VMEngine::kLazyCtxCachedBlkOff), "vm.lazy.cb.p");
		B.CreateStore(B.getInt32(0xFFFFFFFFu), CachedBlkPtr);

		LazyCtxArg = LazyCtx;
	}

	// Call vm_engine (indirect via handler table)
	// the engine pointer is stored in GVHandlers[OP_COUNT*K] (M1: base table
	// holds K variant slots per opcode -- see VMImpl::buildHandlerTable()).
	// We load it and make an indirect call.  This eliminates every direct
	// call-site xref from wrappers to @__vm_engine, breaking static
	// cross-reference analysis in IDA/Ghidra.

	// Bytecode base: use runtime copy if encryption is enabled
	Value* BCBase = (EncBytecode && GVBytecodeRT) ? (Value*)GVBytecodeRT : (Value*)GVBytecode;

	SmallVector<Value*, VMEngine::kNumParams + 1> Args = {
		BCBase,                                                          // bc
		blindI32((uint32_t)E.BC.size()),                                 // bc_len
		WRegs,                                                           // regs
		WRegs64,                                                         // regs64
		WFregs,                                                          // fregs
		WPregs,                                                          // pregs
		GVCallees ? (Value*)GVCallees                                    // callees
			: ConstantPointerNull::get(cast<PointerType>(PtrTy)),
		blindI32(SaltConst),                                             // salt
		blindI32(NVRAlloc > 0 ? NVRAlloc - 1 : 0),                       // regMask
		blindI32(NVR64Alloc > 0 ? NVR64Alloc - 1 : 0),                   // reg64Mask
		blindI32(NFRAlloc > 0 ? NFRAlloc - 1 : 0),                       // fregMask
		blindI32(NPRAlloc > 0 ? NPRAlloc - 1 : 0),                       // pregMask
		GVHandlers,                                                      // handlers
		GVFTyIndices ? (Value*)GVFTyIndices                              // fty_indices
			: ConstantPointerNull::get(cast<PointerType>(PtrTy)),
		// per-slot XOR key arrays for register encryption
		DoRegEncrypt ? (Value*)WRegKeys                                  // regkeys
			: ConstantPointerNull::get(cast<PointerType>(PtrTy)),
		DoRegEncrypt ? (Value*)WReg64Keys                                // reg64keys
			: ConstantPointerNull::get(cast<PointerType>(PtrTy)),
		DoRegEncrypt ? (Value*)WFRegKeys                                 // fregkeys
			: ConstantPointerNull::get(cast<PointerType>(PtrTy)),
		// per-function callee XOR mask (0 when unhardened)
		Cfg.hardened ? blindI64(CalleeMask) : B.getInt64(0),       // callee_mask
	};
	if (LazyActive) Args.push_back(LazyCtxArg);              // lazyctx

	// Load engine function pointer from handler table slot [OP_COUNT*K]
	// (M1: base table now holds K variant slots per opcode -- see
	// VMImpl::buildHandlerTable(). K is the shared engine's variant count,
	// not this function's own NumVariants member, which only reflects the
	// founding function's build.)
	Value* EngSlot = B.CreateGEP(PtrTy, GVHandlers,
		blindI32(OP_COUNT * SS->NumVariants), "vm.eng.slot");
	Value* EngPtr = B.CreateLoad(PtrTy, EngSlot, "vm.eng.ptr");

	FunctionType* EngFTy = VMEngine::getVMEngineFunctionType(Ctx, LazyActive);
	B.CreateCall(EngFTy, EngPtr, Args);

	// Extract return value and return
	Type* RT = F.getReturnType();
	if (RT->isVoidTy()) {
		B.CreateRetVoid();
	}
	else if (WrapRetSlot >= 0) {
		Value* SlotIdx = B.getInt32(WrapRetSlot);
		switch (WrapRetKind) {
		case VMEngine::RK2_I32: {
			Value* V = B.CreateLoad(I32Ty, B.CreateGEP(I32Ty, WRegs, SlotIdx), "vm.ret.v");
			if (DoRegEncrypt) {
				if (RollingRegKey)
					V = B.CreateXor(V, B.CreateLoad(I32Ty,
						B.CreateGEP(I32Ty, WRegKeys, SlotIdx), "vm.ret.rk"), "vm.ret.dec");
				else
					V = B.CreateXor(V, blindI32(RegKeys[WrapRetSlot]), "vm.ret.dec");
			}
			if (RT != I32Ty && RT->isIntegerTy())
				V = B.CreateTrunc(V, RT, "vm.ret.tr");
			B.CreateRet(V);
			break;
		}
		case VMEngine::RK2_I64: {
			Value* V = B.CreateLoad(I64Ty, B.CreateGEP(I64Ty, WRegs64, SlotIdx), "vm.ret.v64");
			if (DoRegEncrypt) {
				if (RollingRegKey)
					V = B.CreateXor(V, B.CreateLoad(I64Ty,
						B.CreateGEP(I64Ty, WReg64Keys, SlotIdx), "vm.ret.rk64"), "vm.ret.dec64");
				else
					V = B.CreateXor(V, blindI64(Reg64Keys[WrapRetSlot]), "vm.ret.dec64");
			}
			B.CreateRet(V);
			break;
		}
		case VMEngine::RK2_PTR: {
			Value* V = B.CreateLoad(PtrTy, B.CreateGEP(PtrTy, WPregs, SlotIdx), "vm.ret.vp");
			B.CreateRet(V);
			break;
		}
		case VMEngine::RK2_F64: {
			Value* V = B.CreateLoad(DoubleTy, B.CreateGEP(DoubleTy, WFregs, SlotIdx), "vm.ret.vf");
			if (DoRegEncrypt) {
				Value* Bits = B.CreateBitCast(V, I64Ty, "vm.ret.fbits");
				if (RollingRegKey)
					Bits = B.CreateXor(Bits, B.CreateLoad(I64Ty,
						B.CreateGEP(I64Ty, WFRegKeys, SlotIdx), "vm.ret.rkf"), "vm.ret.fdec");
				else
					Bits = B.CreateXor(Bits, blindI64(FRegKeys[WrapRetSlot]), "vm.ret.fdec");
				V = B.CreateBitCast(Bits, DoubleTy, "vm.ret.fval");
			}
			if (RT->isFloatTy())
				V = B.CreateFPTrunc(V, RT, "vm.ret.ftr");
			B.CreateRet(V);
			break;
		}
		default:
			B.CreateUnreachable();
			break;
		}
	}
	else {
		// RetSlot unknown — should not happen for non-void functions
		B.CreateUnreachable();
	}

	LLVM_DEBUG(dbgs() << "[vm] built thin wrapper for '" << F.getName()
		<< "' [retKind=" << (int)WrapRetKind
		<< " retSlot=" << WrapRetSlot
		<< " engMask=0x" << Twine::utohexstr(EngineMask) << "]\n");
}





void VMImpl::hardenWrapper() {
	if (!Cfg.hardened) return;

	auto HRng = R.fork("vm.wrap.split");
	llvm::obf::OpaqueUtils HOpaque(M, HRng, "vm.wrap.split.i32");
	BasicBlock* EntryBB = &F.getEntryBlock();
	if (!EntryBB || EntryBB->empty()) return;

	// Find the last alloca — everything before it stays in entry
	Instruction* LastAlloca = nullptr;
	for (auto& I : *EntryBB)
		if (isa<AllocaInst>(&I)) LastAlloca = &I;
	if (!LastAlloca) return;

	// Collect split-candidate instructions (after last alloca, pre-terminator)
	SmallVector<Instruction*, 128> Candidates;
	bool Past = false;
	for (auto& I : *EntryBB) {
		if (&I == LastAlloca) { Past = true; continue; }
		if (Past && !I.isTerminator())
			Candidates.push_back(&I);
	}
	if (Candidates.size() < 8) return; // too few instructions to split

	// Choose 3-5 evenly-spaced split points 
	unsigned NSplits = 3 + HRng.range(3); // 3..5
	if (NSplits >= Candidates.size()) NSplits = 2;
	unsigned ChunkSize = (unsigned)Candidates.size() / (NSplits + 1);
	if (ChunkSize < 2) ChunkSize = 2;

	SmallVector<Instruction*, 8> SplitPoints;
	for (unsigned i = 1; i <= NSplits; ++i) {
		unsigned Idx = i * ChunkSize;
		if (Idx < Candidates.size())
			SplitPoints.push_back(Candidates[Idx]);
	}
	if (SplitPoints.empty()) return;

	// Always split right after the last alloca (Phase 0 = allocas) 
	Instruction* FirstPostAlloca = LastAlloca->getNextNode();
	if (FirstPostAlloca && !FirstPostAlloca->isTerminator()) {
		// Insert at front only if not already present
		if (SplitPoints.empty() || SplitPoints.front() != FirstPostAlloca)
			SplitPoints.insert(SplitPoints.begin(), FirstPostAlloca);
	}

	// Split in reverse order to preserve instruction pointers 
	SmallVector<BasicBlock*, 8> PhaseBBs;
	for (int i = (int)SplitPoints.size() - 1; i >= 0; --i) {
		BasicBlock* NewBB = EntryBB->splitBasicBlock(
			SplitPoints[i], "vm.w.p" + Twine(i));
		PhaseBBs.push_back(NewBB);
	}
	std::reverse(PhaseBBs.begin(), PhaseBBs.end());
	// Now: EntryBB(allocas) → PhaseBBs[0] → PhaseBBs[1] → ... → PhaseBBs[N-1](ret)
	// Each edge is an unconditional branch inserted by splitBasicBlock.

	// Create dead blocks with junk arithmetic 
	unsigned NDeadBlocks = 3 + HRng.range(3); // 3..5
	SmallVector<BasicBlock*, 8> DeadBBs;
	for (unsigned i = 0; i < NDeadBlocks; ++i) {
		auto* DBB = BasicBlock::Create(Ctx, "vm.w.dead." + Twine(i), &F);
		IRBuilder<> DB(DBB);

		// Junk: opaque constants + arithmetic (2-4 operations)
		Value* J1 = HOpaque.opaqueI32Const(DB, HRng.u32());
		Value* J2 = HOpaque.opaqueI32Const(DB, HRng.u32());
		Value* R1 = DB.CreateXor(J1, J2, "vm.w.d.xor");
		Value* R2 = DB.CreateMul(R1, J1, "vm.w.d.mul");
		Value* R3 = DB.CreateAdd(R2, J2, "vm.w.d.add");
		(void)R3;

		// Branch to a random phase block (makes CFG look connected)
		unsigned Tgt = HRng.range((unsigned)PhaseBBs.size());
		DB.CreateBr(PhaseBBs[Tgt]);
		DeadBBs.push_back(DBB);
	}

	//  Replace unconditional branches with opaque-predicate branches 
	auto replaceEdge = [&](BasicBlock* From) {
		auto* Term = From->getTerminator();
		if (!Term || !isa<BranchInst>(Term)) return;
		auto* BI = cast<BranchInst>(Term);
		if (!BI->isUnconditional()) return;

		BasicBlock* RealSucc = BI->getSuccessor(0);
		BasicBlock* FakeDst = DeadBBs[HRng.range((unsigned)DeadBBs.size())];

		IRBuilder<> OB(Term);
		Value* Cond = HOpaque.hardTrue(OB);
		OB.CreateCondBr(Cond, RealSucc, FakeDst);
		Term->eraseFromParent();
		};

	// Entry → PhaseBBs[0]
	replaceEdge(EntryBB);
	// PhaseBBs[i] → PhaseBBs[i+1]  (last phase has the ret, no branch to replace)
	for (unsigned i = 0; i + 1 < PhaseBBs.size(); ++i)
		replaceEdge(PhaseBBs[i]);

	LLVM_DEBUG(dbgs() << "[vm] hardened wrapper for '"
		<< F.getName() << "' [phases=" << (PhaseBBs.size() + 1)
		<< " dead=" << NDeadBlocks << "]\n");
}



// switch-dispatch flattening of the wrapper ─
// Converts the multi-block wrapper CFG (produced by hardenWrapper) into
// a while-true / switch(state) dispatcher.  Each original basic block
// becomes a switch case.  Inter-block branches are replaced with
// state-variable assignments that jump back to the dispatcher.
//
// State encoding: each block gets a random i32 tag.  Transitions store
// the XOR delta between the current and next tag, so the decompiler
// sees: state ^= <opaque_delta>;  This prevents trivial state recovery.
//
// Blocks that terminate with ret/unreachable are left as function exits.
// Gated by Cfg.hardened — no-op when hardened=0.

void VMImpl::flattenWrapper() {
	if (!Cfg.hardened) return;

	auto FRng = R.fork("vm.wrap.flat");
	llvm::obf::OpaqueUtils FOpaque(M, FRng, "vm.wrap.flat.i32");

	BasicBlock* EntryBB = &F.getEntryBlock();

	// Collect all non-entry blocks that should become switch cases.
	SmallVector<BasicBlock*, 16> Blocks;
	for (BasicBlock& BB : F) {
		if (&BB == EntryBB) continue;
		Blocks.push_back(&BB);
	}
	if (Blocks.size() < 3) return; // too few blocks to flatten

	// Assign random state tags to each block.
	DenseMap<BasicBlock*, uint32_t> StateMap;
	for (auto* BB : Blocks) {
		uint32_t Tag;
		do { Tag = FRng.u32(); } while (Tag == 0); // avoid 0 (used as init)
		StateMap[BB] = Tag;
	}

	//  Create state variable in entry block 
	// Insert alloca before the entry block's terminator.
	IRBuilder<> EntryB(EntryBB->getTerminator());
	AllocaInst* StateVar = EntryB.CreateAlloca(I32Ty, nullptr, "vm.w.flat.st");

	// Initial state = tag of the first successor of entry.
	BasicBlock* FirstSucc = nullptr;
	if (auto* BI = dyn_cast<BranchInst>(EntryBB->getTerminator())) {
		FirstSucc = BI->getSuccessor(0);
	}
	if (!FirstSucc || !StateMap.count(FirstSucc)) return;
	uint32_t InitState = StateMap[FirstSucc];
	EntryB.CreateStore(FOpaque.opaqueI32Const(EntryB, InitState), StateVar);

	//  Create dispatcher block 
	BasicBlock* DispBB = BasicBlock::Create(Ctx, "vm.w.flat.disp", &F);
	IRBuilder<> DB(DispBB);
	LoadInst* StateLoad = DB.CreateLoad(I32Ty, StateVar, "vm.w.flat.ld");
	StateLoad->setVolatile(true);

	// Default case goes to the first block (fallback).
	SwitchInst* SW = DB.CreateSwitch(StateLoad, Blocks[0], (unsigned)Blocks.size());
	for (auto* BB : Blocks) {
		SW->addCase(ConstantInt::get(cast<IntegerType>(I32Ty), StateMap[BB]), BB);
	}

	//  Redirect entry block terminator to dispatcher ─
	EntryBB->getTerminator()->eraseFromParent();
	IRBuilder<> EB(EntryBB);
	EB.CreateBr(DispBB);

	//  Rewrite terminators of flattened blocks ─
	// Replace branches with: state ^= delta; br dispatcher
	for (auto* BB : Blocks) {
		auto* Term = BB->getTerminator();
		if (!Term) continue;

		// ret / unreachable — leave as function exit
		if (isa<ReturnInst>(Term) || isa<UnreachableInst>(Term))
			continue;

		if (auto* BI = dyn_cast<BranchInst>(Term)) {
			IRBuilder<> TB(Term);
			uint32_t CurTag = StateMap[BB];

			if (BI->isUnconditional()) {
				BasicBlock* Succ = BI->getSuccessor(0);
				if (StateMap.count(Succ)) {
					uint32_t NextTag = StateMap[Succ];
					uint32_t Delta = CurTag ^ NextTag;
					Value* Old = TB.CreateLoad(I32Ty, StateVar, "vm.w.flat.old");
					cast<LoadInst>(Old)->setVolatile(true);
					Value* New = TB.CreateXor(Old,
						FOpaque.opaqueI32Const(TB, Delta), "vm.w.flat.xor");
					TB.CreateStore(New, StateVar)->setVolatile(true);
					TB.CreateBr(DispBB);
					Term->eraseFromParent();
				}
			}
			else {
				// Conditional branch (opaque predicates from 06b.3)
				BasicBlock* TSucc = BI->getSuccessor(0);
				BasicBlock* FSucc = BI->getSuccessor(1);
				Value* Cond = BI->getCondition();

				if (StateMap.count(TSucc) && StateMap.count(FSucc)) {
					uint32_t TDelta = CurTag ^ StateMap[TSucc];
					uint32_t FDelta = CurTag ^ StateMap[FSucc];
					Value* SelDelta = TB.CreateSelect(Cond,
						FOpaque.opaqueI32Const(TB, TDelta),
						FOpaque.opaqueI32Const(TB, FDelta), "vm.w.flat.sel");
					Value* Old = TB.CreateLoad(I32Ty, StateVar, "vm.w.flat.old");
					cast<LoadInst>(Old)->setVolatile(true);
					Value* New = TB.CreateXor(Old, SelDelta, "vm.w.flat.xor");
					TB.CreateStore(New, StateVar)->setVolatile(true);
					TB.CreateBr(DispBB);
					Term->eraseFromParent();
				}
			}
		}
	}

	LLVM_DEBUG(dbgs() << "[vm] flattened wrapper for '"
		<< F.getName() << "' [blocks=" << Blocks.size()
		<< " states=" << StateMap.size() << "]\n");
}



// MBA substitutions on wrapper arithmetic ─
// After buildWrapper + hardenWrapper, the wrapper contains XOR, ADD, OR
// etc. for argument encryption, return decryption, opaque predicates,
// and junk arithmetic.  This pass replaces every eligible integer
// BinaryOperator with an MBA equivalent, making the decompiler output
// a multi-node expression tree for each operation.
//
// Operates on all basic blocks of the wrapper function (including the
// phase blocks and dead blocks created by hardenWrapper).
// Gated by Cfg.hardened — no-op when hardened=0.

void VMImpl::mbaHardenWrapper() {
	if (!Cfg.hardened) return;

	auto MRng = R.fork("vm.wrap.mba");
	llvm::obf::MbaUtils    WMBA(M, MRng, "vm.wrap.mba.noise.i32");
	llvm::obf::OpaqueUtils WOpq(M, MRng, "vm.wrap.mba.salt.i32");

	// Collect candidates (can't modify while iterating).
	SmallVector<BinaryOperator*, 64> Candidates;
	for (BasicBlock& BB : F) {
		for (Instruction& I : BB) {
			auto* BO = dyn_cast<BinaryOperator>(&I);
			if (!BO || !BO->getType()->isIntegerTy()) continue;
			if (!llvm::obf::MbaUtils::isTargetOpcode(BO->getOpcode())) continue;
			Candidates.push_back(BO);
		}
	}

	unsigned Sites = 0;
	for (BinaryOperator* BO : Candidates) {
		if (!BO->getParent()) continue; // erased by prior iteration

		IRBuilder<> B(BO);
		Value* A = BO->getOperand(0);
		Value* V = BO->getOperand(1);
		Value* Rep = nullptr;

		switch (BO->getOpcode()) {
		case Instruction::Add: {
			switch (MRng.range(3)) {
			case 0:  Rep = WMBA.addAlt(B, A, V);  break;
			case 1:  Rep = WMBA.add(B, A, V);     break;
			default: Rep = WMBA.addAlt2(B, A, V); break;
			}
			break;
		}
		case Instruction::Sub: Rep = WMBA.subAlt2(B, A, V); break;
		case Instruction::Xor: {
			Rep = (MRng.range(2) == 0)
				? WMBA.bitwiseXor(B, A, V)
				: WMBA.bitwiseXorAlt(B, A, V);
			break;
		}
		case Instruction::And: Rep = WMBA.bitwiseAndAlt(B, A, V); break;
		case Instruction::Or:  Rep = WMBA.bitwiseOrAlt2(B, A, V); break;
		default: break;
		}

		if (!Rep) continue;

		// ~25% chance: XOR result with opaque zero for extra noise.
		if (MRng.range(100) < 25) {
			Value* Zero = WOpq.opaqueZero32(B);
			Type* RT = Rep->getType();
			if (RT != Zero->getType()) {
				if (RT->getIntegerBitWidth() > 32)
					Zero = B.CreateZExt(Zero, RT, "vm.w.mba.z.ext");
				else
					Zero = B.CreateTrunc(Zero, RT, "vm.w.mba.z.tr");
			}
			Rep = B.CreateXor(Rep, Zero, "vm.w.mba.noise");
		}

		BO->replaceAllUsesWith(Rep);
		BO->eraseFromParent();
		++Sites;
	}

	LLVM_DEBUG(dbgs() << "[vm] MBA-hardened wrapper for '"
		<< F.getName() << "' [sites=" << Sites << "]\n");
}
