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
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"

#include <functional>
using namespace llvm;

#define DEBUG_TYPE "vm"


// wrapper phase-splitting + junk interleaving ─
// After buildWrapper() finishes, the wrapper function has a single basic
// block.  hardenWrapper() splits it into multiple phases connected by
// opaque-predicate-guarded branches and inserts dead blocks with junk
// arithmetic.  The decompiler sees a conditional CFG instead of a flat stub.
//
// Split strategy:
//   - allocas MUST stay in the entry block (mem2reg requirement)
//   - everything after the last alloca is split into 4-6 chunks
//   - each edge gets: if (hardTrue) goto RealPhase else goto JunkBlock
//   - 3-5 fully dead blocks with junk stores and opaque constants
//
// Gated by Cfg.hardened — no-op when hardened=0.


//salt corruption primitive
// Emits IR to silently poison the salt value.  After this executes,
// every subsequent loadBC() returns garbage because the per-byte XOR
// key (salt ^ idx) is now wrong.  The program continues running but
// produces incorrect output — no crash, no signal.

void VMImpl::emitSaltCorruption(IRBuilder<>& B, Value* SaltPtr, uint32_t PoisonKey) {
	auto* Old = B.CreateLoad(I32Ty, SaltPtr, "vm.ad.salt");
	cast<LoadInst>(Old)->setVolatile(true);
	auto* Poisoned = B.CreateXor(Old, B.getInt32(PoisonKey), "vm.ad.poison");
	B.CreateStore(Poisoned, SaltPtr)->setVolatile(true);
}



// .init_array bytecode integrity hash 
// Builds a constructor that computes FNV-1a over the on-disk encrypted
// GVBytecode global and compares against an embedded compile-time hash.
// On mismatch (binary patching detected): GVBytecodeRT[0] ^= 0xFF,
// silently corrupting the first opcode dispatch.
//
// Runs with priority 65535 (same as the AES/LCG decrypt ctor) but is
// appended after it in run(), so LLVM emits it second — the decrypted
// GVBytecodeRT is already populated when the hash check corrupts [0].
//
// Gated by hardened=1 && antiDebug=1.

void VMImpl::buildIntegrityHashCtor() {
	if (!Cfg.hardened || !Cfg.antiDebug) return;
	if (!GVBytecode || E.BC.empty()) return;

	unsigned BCLen = (unsigned)E.BC.size();

	//  Compile-time: compute FNV-1a over GVBytecode's initializer 
	uint32_t ExpectedHash = 2166136261u;
	if (auto* Init = GVBytecode->getInitializer()) {
		if (auto* CDA = dyn_cast<ConstantDataArray>(Init)) {
			for (unsigned i = 0; i < CDA->getNumElements(); ++i)
				ExpectedHash = (ExpectedHash ^ (uint8_t)CDA->getElementAsInteger(i))
				* 16777619u;
		}
		else if (auto* CA = dyn_cast<ConstantArray>(Init)) {
			for (unsigned i = 0; i < CA->getNumOperands(); ++i) {
				if (auto* CI = dyn_cast<ConstantInt>(CA->getOperand(i)))
					ExpectedHash = (ExpectedHash ^ (uint8_t)CI->getZExtValue())
					* 16777619u;
			}
		}
	}

	//  Build the constructor function 
	std::string FnName = (F.getName() + ".vm.hash.ctor").str();
	auto* FTy = FunctionType::get(Type::getVoidTy(Ctx), false);
	auto* Fn = Function::Create(FTy, GlobalValue::InternalLinkage, FnName, M);
	Fn->addFnAttr(Attribute::NoUnwind);

	BasicBlock* EntBB = BasicBlock::Create(Ctx, "vm.hash.entry", Fn);
	BasicBlock* LoopBB = BasicBlock::Create(Ctx, "vm.hash.loop", Fn);
	BasicBlock* BodyBB = BasicBlock::Create(Ctx, "vm.hash.body", Fn);
	BasicBlock* CheckBB = BasicBlock::Create(Ctx, "vm.hash.check", Fn);
	BasicBlock* FailBB = BasicBlock::Create(Ctx, "vm.hash.fail", Fn);
	BasicBlock* ExitBB = BasicBlock::Create(Ctx, "vm.hash.exit", Fn);

	// Entry: alloca hash accumulator + index, initialise
	AllocaInst* HashA;
	AllocaInst* IdxA;
	{
		IRBuilder<> B(EntBB);
		HashA = B.CreateAlloca(I32Ty, nullptr, "vm.hash.h");
		IdxA = B.CreateAlloca(I32Ty, nullptr, "vm.hash.i");
		B.CreateStore(B.getInt32(2166136261u), HashA);  // FNV offset basis
		B.CreateStore(B.getInt32(0), IdxA);
		B.CreateBr(LoopBB);
	}

	// Loop header: idx < BCLen ? body : check
	{
		IRBuilder<> B(LoopBB);
		Value* Idx = B.CreateLoad(I32Ty, IdxA, "vm.hash.idx");
		B.CreateCondBr(
			B.CreateICmpULT(Idx, B.getInt32(BCLen), "vm.hash.cmp"),
			BodyBB, CheckBB);
	}

	// Body: h = (h ^ byte) * 16777619
	{
		IRBuilder<> B(BodyBB);
		Value* Idx = B.CreateLoad(I32Ty, IdxA, "vm.hash.idx2");
		Value* H = B.CreateLoad(I32Ty, HashA, "vm.hash.hv");

		// Load byte from GVBytecode (const global, not the runtime copy)
		Value* Ptr = B.CreateGEP(I8Ty, GVBytecode,
			B.CreateSExt(Idx, I64Ty, "vm.hash.idx64"), "vm.hash.ptr");
		Value* Byte = B.CreateLoad(I8Ty, Ptr, "vm.hash.byte");
		Value* ByteW = B.CreateZExt(Byte, I32Ty, "vm.hash.bw");

		// FNV-1a h = (h ^ byte) * prime
		Value* HX = B.CreateXor(H, ByteW, "vm.hash.xor");
		Value* HM = B.CreateMul(HX, B.getInt32(16777619u), "vm.hash.mul");
		B.CreateStore(HM, HashA);

		// idx++
		B.CreateStore(B.CreateAdd(Idx, B.getInt32(1), "vm.hash.inc"), IdxA);
		B.CreateBr(LoopBB);
	}

	// Check: compare computed hash against expected
	{
		IRBuilder<> B(CheckBB);
		Value* H = B.CreateLoad(I32Ty, HashA, "vm.hash.final");
		Value* Match = B.CreateICmpEQ(H, B.getInt32(ExpectedHash), "vm.hash.ok");
		B.CreateCondBr(Match, ExitBB, FailBB);
	}

	// Fail: silently corrupt GVBytecodeRT[0] (or GVBytecode[0] if no RT)
	{
		IRBuilder<> B(FailBB);
		GlobalVariable* Target = GVBytecodeRT ? GVBytecodeRT : GVBytecode;
		Value* Ptr = B.CreateGEP(I8Ty, Target, B.getInt64(0), "vm.hash.tgt");
		Value* Old = B.CreateLoad(I8Ty, Ptr, "vm.hash.old");
		Value* Corrupted = B.CreateXor(Old, B.getInt8((uint8_t)0xFF), "vm.hash.bad");
		B.CreateStore(Corrupted, Ptr);
		B.CreateBr(ExitBB);
	}

	// Exit
	IRBuilder<>(ExitBB).CreateRetVoid();

	// Register as .init_array constructor (same priority as decrypt ctor)
	appendToGlobalCtors(M, Fn, 65535, nullptr);

	LLVM_DEBUG(dbgs() << "[vm] integrity hash ctor for '"
		<< F.getName() << "' [hash=0x"
		<< Twine::utohexstr(ExpectedHash) << " len=" << BCLen << "]\n");
}



// .init_array callee XOR masking constructor ─
// Builds a constructor that XOR-masks each entry in GVCallees with
// CalleeMask.  Runs at startup AFTER the linker resolves relocations
// (raw function addresses are in memory) but BEFORE main().
//
// After this ctor: GVCallees[i] = inttoptr(ptrtoint(original) ^ mask)
// The CALL handler  reverses this with the same XOR.
//
// For small callee counts (typical: 1-10), the loop is fully unrolled.
// Gated by hardened=1 and non-empty callee table.

void VMImpl::buildCalleeXorCtor() {
	if (!Cfg.hardened || !GVCallees || E.CalleeTab.empty()) return;
	if (CalleeMask == 0) return;

	unsigned NCallees = (unsigned)E.CalleeTab.size();

	std::string FnName = (F.getName() + ".vm.callee.ctor").str();
	auto* FTy = FunctionType::get(Type::getVoidTy(Ctx), false);
	auto* Fn = Function::Create(FTy, GlobalValue::InternalLinkage, FnName, M);
	Fn->addFnAttr(Attribute::NoUnwind);

	auto* BB = BasicBlock::Create(Ctx, "vm.cm.entry", Fn);
	IRBuilder<> B(BB);

	// Unrolled: for each slot, load → ptrtoint → xor → inttoptr → store
	for (unsigned i = 0; i < NCallees; ++i) {
		Value* SlotPtr = B.CreateGEP(PtrTy, GVCallees,
			B.getInt64(i), "vm.cm.slot" + Twine(i));
		Value* Raw = B.CreateLoad(PtrTy, SlotPtr, "vm.cm.raw" + Twine(i));
		Value* RawInt = B.CreatePtrToInt(Raw, I64Ty, "vm.cm.ri" + Twine(i));
		Value* Masked = B.CreateXor(RawInt,
			B.getInt64(CalleeMask), "vm.cm.xor" + Twine(i));
		Value* MaskedPtr = B.CreateIntToPtr(Masked, PtrTy, "vm.cm.mp" + Twine(i));
		B.CreateStore(MaskedPtr, SlotPtr);
	}

	B.CreateRetVoid();
	appendToGlobalCtors(M, Fn, 65535, nullptr);

	LLVM_DEBUG(dbgs() << "[vm] callee XOR ctor for '"
		<< F.getName() << "' [" << NCallees << " entries, mask=0x"
		<< Twine::utohexstr(CalleeMask) << "]\n");
}



// vm.dispatch anti-debug timing + debugger-API gate 
// Inserts a counter-gated check between vm.dispatch and vm.fetch inside
// the shared __vm_engine.  Every 64 fetch iterations the gate fires and:
//   (a) reads the cycle counter twice with a small computation between,
//       if delta > threshold → salt corruption (catches single-stepping)
//   (b) on Windows, calls IsDebuggerPresent(), CheckRemoteDebuggerPresent(),
//       and NtQueryInformationProcess(ProcessDebugPort) → salt corruption
//
// On detection: emitSaltCorruption() XORs the salt, making all subsequent
// bytecode decryptions produce garbage.  Execution continues — no crash.
//
// When no debugger is attached, the counter check is a single AND+CMP
// that the branch predictor learns is almost-always-false (~1 cycle).

void VMImpl::buildAntiDebugGate(VMEngine::SharedState* SS) {
	if (!Cfg.hardened || !Cfg.antiDebug) return;
	// Stays active under bindAntiDebug too (redundant with the ctor-time
	// key-mask fold, but harmless): an early return here was tried and
	// dropped -- on the i64_ops shape it left __vm_engine's dispatch block
	// with an unmodified false-successor (no CountBB/GateBB between
	// vm.dispatch and vm.fetch), a structural shape this codebase has never
	// exercised before (every existing hardened+antiDebug test has this gate
	// active), and it reproducibly segfaulted at -O2 on that shape even
	// though the gate's own detection was never involved (Detected was always
	// false). Keeping this gate unconditional avoids that untested shape.
	// threadedDispatch has no central vm.dispatch/vm.fetch pair to insert
	// this gate between (SS->Dispatch is null there too, so the next check
	// would already no-op this -- explicit for clarity). The handler-level
	// spot-check timing traps in hardenVMEngine() still fire independently.
	if (ThreadedDispatch) return;
	if (!SS || !SS->EngineFn || !SS->Dispatch || !SS->EngineSalt) return;

	Function* EF = SS->EngineFn;

	//  Find FetchBB: it's the false-successor of vm.dispatch ─
	auto* DispTerm = dyn_cast<BranchInst>(SS->Dispatch->getTerminator());
	if (!DispTerm || !DispTerm->isConditional()) return;
	BasicBlock* FetchBB = DispTerm->getSuccessor(1); // false = !OOB = fetch

	//  Create counter alloca in vm.entry (before its terminator) ─
	IRBuilder<> EntB(SS->Entry->getTerminator());
	AllocaInst* CtrA = EntB.CreateAlloca(I32Ty, nullptr, "vm.ad.ctr");
	EntB.CreateStore(EntB.getInt32(0), CtrA)->setVolatile(true);

	//  Create new basic blocks 
	BasicBlock* CountBB = BasicBlock::Create(Ctx, "vm.ad.count", EF);
	BasicBlock* GateBB = BasicBlock::Create(Ctx, "vm.ad.gate", EF);
	BasicBlock* CorruptBB = BasicBlock::Create(Ctx, "vm.ad.corrupt", EF);

	//  Redirect Dispatch → FetchBB  to  Dispatch → CountBB 
	DispTerm->setSuccessor(1, CountBB);

	//  vm.ad.count: increment counter, check every N iterations ─
	{
		IRBuilder<> B(CountBB);
		auto* Ctr = B.CreateLoad(I32Ty, CtrA, "vm.ad.c");
		cast<LoadInst>(Ctr)->setVolatile(true);
		auto* NCtr = B.CreateAdd(Ctr, B.getInt32(1), "vm.ad.cn");
		B.CreateStore(NCtr, CtrA)->setVolatile(true);
		// interval from config (rounded to power-of-2 for AND mask)
		unsigned Interval = Cfg.adDispatchInterval;
		if (Interval == 0) Interval = 64;
		unsigned Mask = 1;
		while (Mask < Interval) Mask <<= 1;
		Mask -= 1; // e.g. 64 → 63
		auto* Masked = B.CreateAnd(NCtr, B.getInt32(Mask), "vm.ad.mask");
		auto* DoCheck = B.CreateICmpEQ(Masked, B.getInt32(0), "vm.ad.fire");
		B.CreateCondBr(DoCheck, GateBB, FetchBB);
	}

	//  vm.ad.gate: platform-specific detection ─
	{
		IRBuilder<> B(GateBB);
		Value* Detected = ConstantInt::getFalse(Ctx);


		// CI-only escape hatch (off by default: no kill-switch string shipped)
		if (ObfVMAllowAntiDebugBypass) {
			FunctionCallee GetEnv = M.getOrInsertFunction("getenv",
				FunctionType::get(PtrTy, { PtrTy }, false));
			Value* EnvName = B.CreateGlobalStringPtr(
				"__OBF_DISABLE_ANTIDEBUG", "vm.ad.envname");
			Value* EnvVal = B.CreateCall(GetEnv, { EnvName }, "vm.ad.env");
			Value* EnvSet = B.CreateICmpNE(EnvVal,
				ConstantPointerNull::get(cast<PointerType>(PtrTy)), "vm.ad.envset");
			// If env var is set, jump straight to FetchBB (skip all checks)
			BasicBlock* RealGateBB = BasicBlock::Create(Ctx, "vm.ad.gate.real", EF);
			B.CreateCondBr(EnvSet, FetchBB, RealGateBB);
			B.SetInsertPoint(RealGateBB);
			Detected = ConstantInt::getFalse(Ctx);
		}

		//  Timing gate: readcyclecounter (x86_64 + AArch64) 
		bool HasCycleCounter = TI.IsX86_64 || TI.IsAArch64;
		if (HasCycleCounter) {
			Function* RCC = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::readcyclecounter);
			auto* T1 = B.CreateCall(RCC, {}, "vm.ad.t1");

			// Small computation between reads (prevents the two reads from
			// being coalesced and gives a realistic baseline delta)
			auto* Dummy = B.CreateLoad(I32Ty, CtrA, "vm.ad.dummy");
			cast<LoadInst>(Dummy)->setVolatile(true);
			auto* Sink = B.CreateAdd(Dummy, B.getInt32(1), "vm.ad.sink");
			B.CreateStore(Sink, CtrA)->setVolatile(true);

			auto* T2 = B.CreateCall(RCC, {}, "vm.ad.t2");
			auto* Delta = B.CreateSub(T2, T1, "vm.ad.delta");
			// threshold from config
			auto* Slow = B.CreateICmpUGT(Delta,
				B.getInt64((uint64_t)Cfg.adDispatchThreshold), "vm.ad.slow");
			Detected = B.CreateOr(Detected, Slow, "vm.ad.det.time");
		}

		//  Windows: IsDebuggerPresent()
		if (TI.IsWindows) {
			auto* IDPTy = FunctionType::get(I32Ty, false);
			FunctionCallee IDP = M.getOrInsertFunction("IsDebuggerPresent", IDPTy);
			if (auto* IDPFn = dyn_cast<Function>(IDP.getCallee()))
				IDPFn->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
			auto* Dbg = B.CreateCall(IDP, {}, "vm.ad.idb");
			auto* IsDbg = B.CreateICmpNE(Dbg, B.getInt32(0), "vm.ad.win");
			Detected = B.CreateOr(Detected, IsDbg, "vm.ad.det.win");

			// Shared pseudo-handle for the process-query checks.
			FunctionCallee GCP = M.getOrInsertFunction(
				"GetCurrentProcess", FunctionType::get(PtrTy, false));
			if (auto* F2 = dyn_cast<Function>(GCP.getCallee()))
				F2->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
			Value* HProc = B.CreateCall(GCP, {}, "vm.ad.hproc");

			// Output buffers live in the engine entry (avoid dynamic allocas in the gate).
			IRBuilder<> EntB(SS->Entry->getTerminator());

			// (1) CheckRemoteDebuggerPresent(HANDLE, PBOOL) — kernel32. Sets *pbFlag
			//     to nonzero when a (possibly remote/kernel) debugger is attached.
			{
				AllocaInst* Flag = EntB.CreateAlloca(I32Ty, nullptr, "vm.ad.crdp");
				EntB.CreateStore(EntB.getInt32(0), Flag)->setVolatile(true);
				FunctionCallee CRDP = M.getOrInsertFunction(
					"CheckRemoteDebuggerPresent",
					FunctionType::get(I32Ty, { PtrTy, PtrTy }, false));
				if (auto* F3 = dyn_cast<Function>(CRDP.getCallee()))
					F3->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
				B.CreateCall(CRDP, { HProc, Flag });
				auto* FV = B.CreateLoad(I32Ty, Flag, "vm.ad.crdp.v");
				cast<LoadInst>(FV)->setVolatile(true);
				Value* IsRDbg = B.CreateICmpNE(FV, B.getInt32(0), "vm.ad.crdp.d");
				Detected = B.CreateOr(Detected, IsRDbg, "vm.ad.det.crdp");
			}

			// (2) NtQueryInformationProcess(HANDLE, ProcessDebugPort=7, &port, 8, NULL)
			//     resolved at RUNTIME via GetProcAddress so no static ntdll import
			//     is needed (a static __imp_NtQueryInformationProcess breaks linking
			//     — ntdll is not in a default import lib). A nonzero debug port means
			//     a debugger is attached. The call is branch-guarded so a failed
			//     resolve (null proc) is never called.
			{
				// port buffer in engine entry, default 0 (stays 0 if unresolved).
				AllocaInst* Port = EntB.CreateAlloca(I64Ty, nullptr, "vm.ad.dport");
				EntB.CreateStore(EntB.getInt64(0), Port)->setVolatile(true);

				// HMODULE ntdll = GetModuleHandleA("ntdll.dll");
				FunctionCallee GMH = M.getOrInsertFunction(
					"GetModuleHandleA", FunctionType::get(PtrTy, { PtrTy }, false));
				if (auto* Fh = dyn_cast<Function>(GMH.getCallee()))
					Fh->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
				Value* DllName = B.CreateGlobalString("ntdll.dll", "vm.ad.ntdll");
				Value* HMod = B.CreateCall(GMH, { DllName }, "vm.ad.hntdll");

				// FARPROC p = GetProcAddress(HMODULE, "NtQueryInformationProcess");
				FunctionCallee GPA = M.getOrInsertFunction(
					"GetProcAddress", FunctionType::get(PtrTy, { PtrTy, PtrTy }, false));
				if (auto* Fp = dyn_cast<Function>(GPA.getCallee()))
					Fp->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
				Value* ProcName = B.CreateGlobalString(
					"NtQueryInformationProcess", "vm.ad.ntqname");
				Value* Proc = B.CreateCall(GPA, { HMod, ProcName }, "vm.ad.ntqaddr");
				Value* HasProc = B.CreateICmpNE(
					Proc, ConstantPointerNull::get(cast<PointerType>(PtrTy)),
					"vm.ad.ntq.ok");

				// Guard: call through Proc only when resolved (never call null).
				BasicBlock* NtqCallBB = BasicBlock::Create(Ctx, "vm.ad.ntq.call", EF);
				BasicBlock* NtqAfterBB = BasicBlock::Create(Ctx, "vm.ad.ntq.after", EF);
				B.CreateCondBr(HasProc, NtqCallBB, NtqAfterBB);

				// NtqCallBB: indirect call sets *Port.
				{
					IRBuilder<> CB(NtqCallBB);
					FunctionType* NtqFTy = FunctionType::get(
						I32Ty, { PtrTy, I32Ty, PtrTy, I32Ty, PtrTy }, false);
					CB.CreateCall(NtqFTy, Proc,
						{ HProc, CB.getInt32(7), Port, CB.getInt32(8),
						  ConstantPointerNull::get(cast<PointerType>(PtrTy)) });
					CB.CreateBr(NtqAfterBB);
				}

				// Continue in NtqAfterBB (preds: gate block [unresolved] + NtqCallBB).
				// Detected is defined in the gate block which dominates NtqAfterBB,
				// so it is available here without a PHI; Port defaults 0 on the
				// unresolved path.
				B.SetInsertPoint(NtqAfterBB);
				auto* PV = B.CreateLoad(I64Ty, Port, "vm.ad.dport.v");
				cast<LoadInst>(PV)->setVolatile(true);
				Value* HasPort = B.CreateICmpNE(PV, B.getInt64(0), "vm.ad.dport.d");
				Detected = B.CreateOr(Detected, HasPort, "vm.ad.det.dport");
			}
		}

		B.CreateCondBr(Detected, CorruptBB, FetchBB);
	}

	//  vm.ad.corrupt: silently poison salt, then continue 
	{
		IRBuilder<> B(CorruptBB);
		emitSaltCorruption(B, SS->EngineSalt, ADPoisonKey);
		B.CreateBr(FetchBB);
	}

	LLVM_DEBUG(dbgs() << "[vm] anti-debug gate in vm_engine"
		<< " [timing=" << (TI.IsX86_64 || TI.IsAArch64)
		<< " winAPI=" << TI.IsWindows << "]\n");
}



// .init_array anti-debug key-mask fold ─
// Builds a per-function constructor that runs BEFORE the AES bytecode-decrypt
// ctor (priority 100 vs 65535 -- see buildEncryptCtor) and folds the
// debugger-detection result directly into the masked AES round-key global
// (@fn.vm.aes.rk / GVAESExpandedKey) instead of poisoning a salt value that
// a patched detection call can simply avoid triggering.
//
// Detection mirrors the Windows checks in buildAntiDebugGate: IsDebuggerPresent,
// CheckRemoteDebuggerPresent, and NtQueryInformationProcess(ProcessDebugPort)
// resolved at runtime via GetProcAddress (no static ntdll import). The three
// results OR together into a single 0/1 bit ("combined").
//
// combined == 0 (no debugger): global untouched, AES ctor unmasks the correct
// key, bytecode decodes correctly.
// combined == 1 (debugger present): the first 16 bytes of the masked-key
// global are each XORed with a byte of ADPoisonKey, so the AES ctor's later
// unmask (rk[i] ^= mask[i], mask itself unchanged) produces a wrong key --
// bytecode decodes to garbage instead of running under a poisoned salt.
//
// Gated by BindAntiDebug; only emitted when GVAESExpandedKey exists (it's
// created by buildWrapper() when lazyDecrypt=1, otherwise by buildEncryptCtor()
// -- either way this runs after both in VMImpl::run()).

void VMImpl::buildAntiDebugKeyBindCtor() {
	if (!BindAntiDebug) return;
	if (!GVAESExpandedKey) return;

	std::string FnName = (F.getName() + ".vm.adbind.ctor").str();
	auto* FTy = FunctionType::get(Type::getVoidTy(Ctx), false);
	auto* Fn = Function::Create(FTy, GlobalValue::InternalLinkage, FnName, M);
	Fn->addFnAttr(Attribute::NoUnwind);

	BasicBlock* EntBB = BasicBlock::Create(Ctx, "vm.adbind.entry", Fn);
	BasicBlock* CombineBB = BasicBlock::Create(Ctx, "vm.adbind.combine", Fn);

	IRBuilder<> B(EntBB);
	Value* Detected = ConstantInt::getFalse(Ctx);
	Value* HProc = nullptr;
	Value* Proc = nullptr;
	AllocaInst* Port = nullptr;

	if (TI.IsWindows) {
		// IsDebuggerPresent()
		auto* IDPTy = FunctionType::get(I32Ty, false);
		FunctionCallee IDP = M.getOrInsertFunction("IsDebuggerPresent", IDPTy);
		if (auto* IDPFn = dyn_cast<Function>(IDP.getCallee()))
			IDPFn->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
		auto* Dbg = B.CreateCall(IDP, {}, "vm.adbind.idp");
		Value* IsDbg = B.CreateICmpNE(Dbg, B.getInt32(0), "vm.adbind.idp.d");
		Detected = B.CreateOr(Detected, IsDbg, "vm.adbind.det.idp");

		// GetCurrentProcess() — shared pseudo-handle for the queries below.
		FunctionCallee GCP = M.getOrInsertFunction(
			"GetCurrentProcess", FunctionType::get(PtrTy, false));
		if (auto* F2 = dyn_cast<Function>(GCP.getCallee()))
			F2->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
		HProc = B.CreateCall(GCP, {}, "vm.adbind.hproc");

		// CheckRemoteDebuggerPresent(HANDLE, PBOOL)
		AllocaInst* CrdpFlag = B.CreateAlloca(I32Ty, nullptr, "vm.adbind.crdp");
		B.CreateStore(B.getInt32(0), CrdpFlag);
		FunctionCallee CRDP = M.getOrInsertFunction(
			"CheckRemoteDebuggerPresent",
			FunctionType::get(I32Ty, { PtrTy, PtrTy }, false));
		if (auto* F3 = dyn_cast<Function>(CRDP.getCallee()))
			F3->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
		B.CreateCall(CRDP, { HProc, CrdpFlag });
		auto* CrdpV = B.CreateLoad(I32Ty, CrdpFlag, "vm.adbind.crdp.v");
		Value* IsRDbg = B.CreateICmpNE(CrdpV, B.getInt32(0), "vm.adbind.crdp.d");
		Detected = B.CreateOr(Detected, IsRDbg, "vm.adbind.det.crdp");

		// NtQueryInformationProcess(HANDLE, ProcessDebugPort=7, &port, 8, NULL)
		// resolved via GetProcAddress -- a static __imp_NtQueryInformationProcess
		// breaks linking (ntdll is not in a default import lib).
		Port = B.CreateAlloca(I64Ty, nullptr, "vm.adbind.dport");
		B.CreateStore(B.getInt64(0), Port);

		FunctionCallee GMH = M.getOrInsertFunction(
			"GetModuleHandleA", FunctionType::get(PtrTy, { PtrTy }, false));
		if (auto* Fh = dyn_cast<Function>(GMH.getCallee()))
			Fh->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
		Value* DllName = B.CreateGlobalString("ntdll.dll", "vm.adbind.ntdll");
		Value* HMod = B.CreateCall(GMH, { DllName }, "vm.adbind.hntdll");

		FunctionCallee GPA = M.getOrInsertFunction(
			"GetProcAddress", FunctionType::get(PtrTy, { PtrTy, PtrTy }, false));
		if (auto* Fp = dyn_cast<Function>(GPA.getCallee()))
			Fp->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
		Value* ProcName = B.CreateGlobalString(
			"NtQueryInformationProcess", "vm.adbind.ntqname");
		Proc = B.CreateCall(GPA, { HMod, ProcName }, "vm.adbind.ntqaddr");
		Value* HasProc = B.CreateICmpNE(
			Proc, ConstantPointerNull::get(cast<PointerType>(PtrTy)),
			"vm.adbind.ntq.ok");

		// Guard: call through Proc only when resolved (never call null).
		BasicBlock* NtqCallBB = BasicBlock::Create(Ctx, "vm.adbind.ntq.call", Fn);
		B.CreateCondBr(HasProc, NtqCallBB, CombineBB);

		IRBuilder<> CB(NtqCallBB);
		FunctionType* NtqFTy = FunctionType::get(
			I32Ty, { PtrTy, I32Ty, PtrTy, I32Ty, PtrTy }, false);
		CB.CreateCall(NtqFTy, Proc,
			{ HProc, CB.getInt32(7), Port, CB.getInt32(8),
			  ConstantPointerNull::get(cast<PointerType>(PtrTy)) });
		CB.CreateBr(CombineBB);
	} else {
		B.CreateBr(CombineBB);
	}

	// vm.adbind.combine: fold the debug port result in (Detected is defined
	// in EntBB, which dominates CombineBB on every path -- no PHI needed,
	// same reasoning as buildAntiDebugGate's NtqAfterBB), then fold the
	// combined 0/1 bit into the first 16 bytes of the masked-key global.
	IRBuilder<> CB2(CombineBB);
	Value* CombinedDet = Detected;
	if (TI.IsWindows) {
		auto* PV = CB2.CreateLoad(I64Ty, Port, "vm.adbind.dport.v");
		Value* HasPort = CB2.CreateICmpNE(PV, CB2.getInt64(0), "vm.adbind.dport.d");
		CombinedDet = CB2.CreateOr(CombinedDet, HasPort, "vm.adbind.det.dport");
	}
	// combined = (idp | crdp | ntq) & 1 -- zext of an i1 is already 0/1.
	Value* Combined32 = CB2.CreateZExt(CombinedDet, I32Ty, "vm.adbind.c32");
	Value* Combined8 = CB2.CreateTrunc(Combined32, I8Ty, "vm.adbind.c8");

	for (unsigned i = 0; i < 16; ++i) {
		uint8_t Amt = (uint8_t)((ADPoisonKey >> ((i % 4) * 8)) & 0xFFu);
		Value* Ptr = CB2.CreateGEP(I8Ty, GVAESExpandedKey,
			CB2.getInt64(i), "vm.adbind.p" + Twine(i));
		Value* Old = CB2.CreateLoad(I8Ty, Ptr, "vm.adbind.o" + Twine(i));
		// Branchless: corruption is 0 (no-op XOR) unless combined==1.
		Value* Corr = CB2.CreateMul(Combined8, CB2.getInt8(Amt), "vm.adbind.corr" + Twine(i));
		Value* NewV = CB2.CreateXor(Old, Corr, "vm.adbind.n" + Twine(i));
		CB2.CreateStore(NewV, Ptr);
	}
	CB2.CreateRetVoid();

	// Priority 100: strictly before buildEncryptCtor's AES ctor (65535), so
	// the round-key global is corrupted (or not) before it gets unmasked.
	appendToGlobalCtors(M, Fn, 100, nullptr);

	LLVM_DEBUG(dbgs() << "[vm] anti-debug key-bind ctor for '"
		<< F.getName() << "' [winAPI=" << TI.IsWindows << "]\n");
}
