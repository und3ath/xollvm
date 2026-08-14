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
#include "llvm/Transforms/Obfuscator/Rng.h"

#include <functional>
using namespace llvm;

#define DEBUG_TYPE "vm"



void VMImpl::buildHandlerTable() {
	// table is [OP_COUNT*K + 1 x ptr] (+ OP_COUNT more when encDispatch is
	// on).  Slots [P*K .. P*K+K-1] hold the K variant BlockAddress entries
	// for physical opcode P (M1: intra-function handler-variant dispatch --
	// all K variant bodies are reachable per opcode; vm.fetch selects one at
	// runtime from (ip, salt)).  Slot [OP_COUNT*K] holds the engine function
	// pointer — the wrapper loads it and makes an indirect call, breaking
	// static call-site xref analysis.
	//
	// NOTE: The pointer is stored unmasked here because LLVM 21 does not
	// support xor(ptrtoint) in constant-expression global initialisers.
	// The handler table already contains many blockaddress(@__vm_engine,...)
	// entries so one more raw ptr adds no new information for the analyst.
	// (constant blinding) will obfuscate the wrapper's runtime
	// load path so the connection is not trivially visible in the wrapper.
	// In shared engine mode, OpcBB[] lives in vm_engine.
	VMEngine::SharedState* SS =
		SharedEngineMode ? VMEngine::getSharedState(M, EngineId) : nullptr;
	Function* BAFn = SharedEngineMode ? SS->EngineFn : &F;
	unsigned K = SharedEngineMode ? SS->NumVariants : NumVariants;
	bool ED = SharedEngineMode ? SS->EncDispatch : EncDispatch;
	// M3: decoy slot count for this engine (0 = off / nestedVM, mirrors K).
	unsigned Nd = SharedEngineMode ? SS->NumDecoys : NumDecoys;

	// P2: table size grows to hold the encrypted dispatch map (dmap) when
	// encDispatch is on. M1: base size grows from OP_COUNT+1 to OP_COUNT*K+1.
	// M3: Nd more slots appended past the dmap (or past the engine-ptr slot
	// when encDispatch is off) for decoy blockaddresses. At K==1, Nd==0 this
	// is byte-identical to pre-M1 (TableSize == OP_COUNT+1).
	unsigned TableSize = OP_COUNT * K + 1u + (ED ? OP_COUNT : 0u) + Nd;
	SmallVector<Constant*, 128> Es;
	Es.resize(TableSize, nullptr);

	// P2: secondary Fisher-Yates permutation of handler table slots (P-space).
	// Identity when encDispatch is off (dormant, no RNG consumption).
	uint8_t DispPerm[OP_COUNT];
	for (unsigned i = 0; i < OP_COUNT; ++i) DispPerm[i] = (uint8_t)i;
	if (ED) {
		auto DR = R.fork("vm.disp.perm");
		for (unsigned i = OP_COUNT - 1; i > 0; --i) {
			unsigned j = DR.range(i + 1);
			uint8_t t = DispPerm[i]; DispPerm[i] = DispPerm[j]; DispPerm[j] = t;
		}
	}

	for (unsigned L = 0; L < OP_COUNT; ++L) {
		unsigned P = (unsigned)OpMap.encode((VMOp)L);
		assert(P < OP_COUNT && "opcode map out of range");
		unsigned PermP = DispPerm[P];               // identity when ED off
		// CALL handlers wire the module-shared SS->CallSW[RK] switch, which
		// keeps only the LAST-built variant's switch; ensureCallFTyCases()
		// extends only that one as later functions register new FunctionTypes.
		// Routing to any earlier CALL variant would hit a switch that never
		// received those cases -> default (vm.cl.ur, unreachable) -> UB.
		// Pin ALL K slots for CALL opcodes to the last variant (K-1) so
		// runtime vsel can never select an unwired CALL variant; all other
		// opcodes keep full intra-function variant diversity.
		bool IsCall = (L == OP_CALL_VOID || L == OP_CALL_INT || L == OP_CALL_PTR ||
					   L == OP_CALL_INT64 || L == OP_CALL_F);
		for (unsigned v = 0; v < K; ++v) {
			unsigned VB = (K > 1 && IsCall) ? (K - 1) : v;
			BasicBlock* HB = SharedEngineMode ? SS->OpcBB[L][VB]
											   : OpcBB[L][VB];
			assert(HB && "missing opcode handler variant");
			Es[PermP * K + v] = BlockAddress::get(BAFn, HB);
		}
	}
	for (unsigned i = 0; i < OP_COUNT * K; ++i)
		assert(Es[i] && "unfilled handler table slot");

	// engine pointer in slot [OP_COUNT*K]
	{
		Function* EngFn = M.getFunction(VMEngine::vmEngineName(EngineId));
		assert(EngFn && "vm_engine must exist before building handler table");
		Es[OP_COUNT * K] = EngFn;
	}

	// P2: encrypted dispatch map (dmap) occupies slots
	// [OP_COUNT*K+1 .. OP_COUNT*K+OP_COUNT]. dmap[P] = DispPerm[P] XOR
	// SaltConst (semantics UNCHANGED from pre-M1 -- still indexed per-P;
	// vm.fetch multiplies the decoded value by K after decrypt), stored as
	// an inttoptr constant expr (LLVM allows ConstantExpr::getIntToPtr in
	// global initializers; ptrtoint recovers the integer at runtime).
	if (ED) {
		for (unsigned P = 0; P < OP_COUNT; ++P) {
			uint64_t enc = (uint64_t)((uint32_t)DispPerm[P] ^ SaltConst);
			Es[OP_COUNT * K + 1 + P] =
				ConstantExpr::getIntToPtr(ConstantInt::get(I64Ty, enc), PtrTy);
		}
	}

	// M3: decoy blockaddresses occupy the tail Nd slots, past the dmap (or
	// past the engine-ptr slot when encDispatch is off). Never referenced by
	// vm.fetch/emitThreadedTail (P is clamped mod OP_COUNT before indexing),
	// so these slots exist purely for a static lifter to trip over.
	{
		unsigned DecoyBase = OP_COUNT * K + 1u + (ED ? OP_COUNT : 0u);
		BasicBlock* const* DBB = SharedEngineMode ? SS->DecoyBB.data() : DecoyBB.data();
		for (unsigned i = 0; i < Nd; ++i) {
			assert(DBB[i] && "missing decoy handler block");
			Es[DecoyBase + i] = BlockAddress::get(BAFn, DBB[i]);
		}
	}

	for (unsigned i = 0; i < TableSize; ++i)
		assert(Es[i] && "unfilled handler table slot (incl. dmap/decoys)");

	auto* ATy = ArrayType::get(PtrTy, TableSize);
	GVHandlers = new GlobalVariable(M, ATy, true, GlobalValue::PrivateLinkage,
		ConstantArray::get(ATy, Es), (F.getName() + ".vm.ophandlers").str());
	GVHandlers->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
}


// buildDispatch 
// vm.dispatch: bounds-check IP  vm.fetch: fetch opcode  decrypt  indirectbr

void VMImpl::buildDispatch() {
	if (ThreadedDispatch) {
		// No central vm.dispatch/vm.fetch pair: ExitBB and every OpcBB
		// placeholder were already created before buildOpcodeHandlers() ran
		// (see populateVMEngine), so every handler's own inlined tail
		// (nextInsn -> emitThreadedTail) could reference the full successor
		// set as it was built. All that remains is wiring vm.entry to fetch
		// the first instruction, same as any other handler's back-edge.
		if (Entry && !Entry->getTerminator()) {
			IRBuilder<> EB(Entry);
			nextInsn(EB);
		}
		return;
	}

	// ExitBB is new; Dispatch is the shell already created in run()
	ExitBB = BasicBlock::Create(Ctx, "vm.exit", HFn);
	auto* FetchBB = BasicBlock::Create(Ctx, "vm.fetch", HFn);

	new UnreachableInst(Ctx, ExitBB);

	//  vm.dispatch: bounds check 
	{
		IRBuilder<> B(Dispatch);
		auto* IP = B.CreateLoad(I32Ty, VMIP, "vm.ip.d"); IP->setVolatile(true);
		Value* BCLen = EffBCLen ? EffBCLen
			: (Value*)B.getInt32((uint32_t)E.BC.size());
		Value* OOB = B.CreateICmpUGE(IP, BCLen, "vm.oob");
		B.CreateCondBr(OOB, ExitBB, FetchBB);
	}

	//  vm.fetch: load opcode, decrypt, dispatch 
	{
		IRBuilder<> B(FetchBB);
		auto* IP = B.CreateLoad(I32Ty, VMIP, "vm.ip.f"); IP->setVolatile(true);
		Value* Raw = loadBC(B, IP, 0, "vm.raw");

		// loadBC() already decrypts when EncBytecode=1
		Value* OpB = Raw;

		// keyedDispatch: un-XOR the per-IP opcode key applied by
		// BytecodeEmitter::bop() at write time, before mapping the byte to a
		// permuted opcode index.
		if (KeyedDispatch) {
			auto* SaltL = B.CreateLoad(I32Ty, EffSalt, "vm.opk.salt"); SaltL->setVolatile(true);
			OpB = B.CreateXor(OpB, opKeyByteIR(B, SaltL, IP, "vm.opk"), "vm.opd");
		}

		// Advance IP past opcode byte
		B.CreateStore(B.CreateAdd(IP, B.getInt32(1), "vm.ip1"), VMIP)->setVolatile(true);

		// Clamp opcode index (prevents out-of-bounds GEP on corrupted bytecode)
		Value* OIdx = B.CreateZExt(OpB, I32Ty, "vm.oidx");
		Value* P = B.CreateURem(OIdx, B.getInt32(OP_COUNT), "vm.safe");

		// P2: route through the encrypted dispatch map (dmap) when encDispatch
		// is on. dmap lives at handlers[OP_COUNT*K+1 + P] (M1: base table grew
		// to OP_COUNT*K slots); decrypt with the runtime salt to recover the
		// permuted P-space slot (semantics unchanged -- runtime multiplies by
		// NumVariants below, after decode).
		Value* FinalSlot;
		if (EncDispatch) {
			Value* DmIdx  = B.CreateAdd(P,
				B.getInt32(OP_COUNT * NumVariants + 1), "vm.dm.i");
			Value* DmPtr  = B.CreateGEP(PtrTy, EffHandlers, DmIdx, "vm.dm.p");
			Value* DmRaw  = B.CreateLoad(PtrTy, DmPtr, "vm.dm.raw");
			Value* DmInt  = B.CreateTrunc(
								B.CreatePtrToInt(DmRaw, I64Ty, "vm.dm.i64"),
								I32Ty, "vm.dm.i32");
			auto*  SaltL  = B.CreateLoad(I32Ty, EffSalt, "vm.dm.salt");
			SaltL->setVolatile(true);
			Value* Dec    = B.CreateXor(DmInt, SaltL, "vm.dm.dec");
			FinalSlot     = B.CreateURem(Dec, B.getInt32(OP_COUNT), "vm.dm.slot");
		} else {
			FinalSlot = P;
		}

		// M1: intra-function handler-variant dispatch. Table is now laid
		// out [P*K + v] per opcode; select v at runtime from (ip, salt) so
		// different dispatches of the same opcode can reach different
		// variant bodies. Guarded on NumVariants > 1 -- emits no new IR and
		// leaves the GEP consuming FinalSlot verbatim when K==1 (identity,
		// byte-identical to pre-M1).
		//
		// Uses the raw incoming "salt" ARGUMENT (HFn->getArg(kParamSalt)),
		// not a load from EffSalt/SS->EngineSalt: hardenVMEngine()'s RDTSC
		// handler-timing traps XOR-poison that alloca on a suspected debugger
		// (a documented, load-sensitive false-positive risk). Pre-M1, nothing
		// in this code path read that alloca unless keyedDispatch/encDispatch
		// (opt-in, off by default) were on, so a false trip was control-flow
		// inert here. Reading it for vsel would make EVERY default VM build
		// (handlerVariants=3) newly control-flow-sensitive to that flake.
		// The argument SSA value is immutable and dominates the whole
		// function, so it is never affected by the poison store.
		Value* TableSlot = FinalSlot;
		if (NumVariants > 1) {
			Value* SaltL = HFn->getArg(VMEngine::kParamSalt);
			Value* Mix = B.CreateXor(
				B.CreateMul(IP, B.getInt32(0x9E3779B1u), "vm.vs.mul"),
				B.CreateLShr(SaltL, B.getInt32(3), "vm.vs.shr"),
				"vm.vs.mix");
			Value* VSel = B.CreateURem(Mix, B.getInt32(NumVariants), "vm.vs.sel");
			TableSlot = B.CreateAdd(
				B.CreateMul(FinalSlot, B.getInt32(NumVariants), "vm.vs.base"),
				VSel, "vm.vs.slot");
		}

		// GEP into handler table[table_slot]
		Value* Slot = B.CreateGEP(PtrTy, EffHandlers, TableSlot, "vm.ohsl");
		Value* Hndl = B.CreateLoad(PtrTy, Slot, "vm.hndl");

		// indirectbr with all opcode blocks (all variants) declared as successors
		IndirectBrInst* IBR = B.CreateIndirectBr(Hndl, OP_COUNT * NumVariants + 1);
		for (unsigned i = 0; i < OP_COUNT; ++i)
			for (unsigned v = 0; v < NumVariants; ++v)
				IBR->addDestination(OpcBB[i][v]);
		IBR->addDestination(ExitBB);
	}

	// Terminate vm.entry with branch to vm.dispatch
	if (Entry && !Entry->getTerminator()) {
		IRBuilder<> EB(Entry);
		nextInsn(EB);
	}
}


// emitThreadedTail / nextInsn
// threadedDispatch: inline the fetch/decode/indirectbr sequence into every
// handler's own back-edge instead of routing through one shared vm.dispatch/
// vm.fetch pair. Mirrors buildDispatch()'s central logic exactly, just
// emitted per call-site: a bounds check in the caller's current block,
// followed by a private continuation block holding the fetch/decode/
// indirectbr. Requires ExitBB and every OpcBB[i][v] to already exist (see
// populateVMEngine's pre-creation pass) since the first handler built may
// dispatch to the last one.

void VMImpl::emitThreadedTail(IRBuilder<>& B) {
	auto* IP = B.CreateLoad(I32Ty, VMIP, "vm.ip.d"); IP->setVolatile(true);
	Value* BCLen = EffBCLen ? EffBCLen
		: (Value*)B.getInt32((uint32_t)E.BC.size());
	Value* OOB = B.CreateICmpUGE(IP, BCLen, "vm.oob");

	BasicBlock* ContBB = BasicBlock::Create(Ctx, "vm.next", HFn);
	B.CreateCondBr(OOB, ExitBB, ContBB);

	IRBuilder<> FB(ContBB);
	auto* IP2 = FB.CreateLoad(I32Ty, VMIP, "vm.ip.f"); IP2->setVolatile(true);
	Value* Raw = loadBC(FB, IP2, 0, "vm.raw");

	// loadBC() already decrypts when EncBytecode=1
	Value* OpB = Raw;

	// keyedDispatch: un-XOR the per-IP opcode key applied by
	// BytecodeEmitter::bop() at write time, before mapping the byte to a
	// permuted opcode index. Mirrors buildDispatch()'s vm.fetch logic exactly.
	if (KeyedDispatch) {
		auto* SaltL = FB.CreateLoad(I32Ty, EffSalt, "vm.opk.salt"); SaltL->setVolatile(true);
		OpB = FB.CreateXor(OpB, opKeyByteIR(FB, SaltL, IP2, "vm.opk"), "vm.opd");
	}

	// Advance IP past opcode byte
	FB.CreateStore(FB.CreateAdd(IP2, FB.getInt32(1), "vm.ip1"), VMIP)->setVolatile(true);

	// Clamp opcode index (prevents out-of-bounds GEP on corrupted bytecode)
	Value* OIdx = FB.CreateZExt(OpB, I32Ty, "vm.oidx");
	Value* P = FB.CreateURem(OIdx, FB.getInt32(OP_COUNT), "vm.safe");

	// P2: route through the encrypted dispatch map (dmap) when encDispatch
	// is on -- mirrors buildDispatch()'s vm.fetch logic exactly.
	Value* FinalSlot;
	if (EncDispatch) {
		Value* DmIdx = FB.CreateAdd(P,
			FB.getInt32(OP_COUNT * NumVariants + 1), "vm.dm.i");
		Value* DmPtr = FB.CreateGEP(PtrTy, EffHandlers, DmIdx, "vm.dm.p");
		Value* DmRaw = FB.CreateLoad(PtrTy, DmPtr, "vm.dm.raw");
		Value* DmInt = FB.CreateTrunc(
							FB.CreatePtrToInt(DmRaw, I64Ty, "vm.dm.i64"),
							I32Ty, "vm.dm.i32");
		auto*  SaltL = FB.CreateLoad(I32Ty, EffSalt, "vm.dm.salt");
		SaltL->setVolatile(true);
		Value* Dec   = FB.CreateXor(DmInt, SaltL, "vm.dm.dec");
		FinalSlot    = FB.CreateURem(Dec, FB.getInt32(OP_COUNT), "vm.dm.slot");
	} else {
		FinalSlot = P;
	}

	// M1: intra-function handler-variant dispatch -- mirrors buildDispatch()'s
	// vm.fetch logic exactly. Guarded on NumVariants > 1; identity (no new
	// IR, GEP consumes FinalSlot verbatim) when K==1. Uses the raw incoming
	// "salt" ARGUMENT, not a load from EffSalt/SS->EngineSalt -- see the
	// comment in buildDispatch()'s vm.fetch for why (RDTSC handler-trap
	// false-positive poisoning of that alloca).
	Value* TableSlot = FinalSlot;
	if (NumVariants > 1) {
		Value* SaltL = HFn->getArg(VMEngine::kParamSalt);
		Value* Mix = FB.CreateXor(
			FB.CreateMul(IP2, FB.getInt32(0x9E3779B1u), "vm.vs.mul"),
			FB.CreateLShr(SaltL, FB.getInt32(3), "vm.vs.shr"),
			"vm.vs.mix");
		Value* VSel = FB.CreateURem(Mix, FB.getInt32(NumVariants), "vm.vs.sel");
		TableSlot = FB.CreateAdd(
			FB.CreateMul(FinalSlot, FB.getInt32(NumVariants), "vm.vs.base"),
			VSel, "vm.vs.slot");
	}

	// GEP into handler table[table_slot]
	Value* Slot = FB.CreateGEP(PtrTy, EffHandlers, TableSlot, "vm.ohsl");
	Value* Hndl = FB.CreateLoad(PtrTy, Slot, "vm.hndl");

	// indirectbr with all opcode blocks (all variants) declared as successors
	IndirectBrInst* IBR = FB.CreateIndirectBr(Hndl, OP_COUNT * NumVariants + 1);
	for (unsigned i = 0; i < OP_COUNT; ++i)
		for (unsigned v = 0; v < NumVariants; ++v)
			IBR->addDestination(OpcBB[i][v]);
	IBR->addDestination(ExitBB);
}


void VMImpl::nextInsn(IRBuilder<>& B) {
	if (ThreadedDispatch) emitThreadedTail(B);
	else B.CreateBr(Dispatch);
}




// ============================================================================
// SharedState management + vm_engine shell + engine population
// ============================================================================

#include <mutex>

namespace {
	static std::mutex SharedStateMu;
	// Keyed by (Module*, EngineId): EngineId 0 = plain engine, 1 = nesting
	// engine. Each key gets its own independent SharedState, so the two
	// engines' "first function populates" guards can never cross-contaminate.
	static DenseMap<std::pair<Module*, unsigned>, std::unique_ptr<VMEngine::SharedState>> SharedStateMap;
}


namespace llvm {
	namespace VMEngine {

		static const char* const kParamNames[kNumParams] = {
			"bc", "bc_len", "regs", "regs64", "fregs", "pregs",
			"callees", "salt", "regMask", "reg64Mask", "fregMask", "pregMask",
			"handlers", "fty_indices",
			"regkeys", "reg64keys", "fregkeys",
			"callee_mask",

		};
		static constexpr const char* kPopulatedMDKey = "obf.vm.engine.populated";

		Function* getOrBuildVMEngine(Module& M, unsigned EngineId) {
			// Lookup only — returns null if not yet created.
			// populateVMEngine() handles atomic creation + population.
			if (Function* Existing = M.getFunction(vmEngineName(EngineId))) {
				assert((Existing->arg_size() == kNumParams ||
					Existing->arg_size() == kNumParams + 1) &&
					"vm_engine parameter count mismatch");
				return Existing;
			}
			return nullptr;
		}

		bool isEnginePopulated(Function* VMEngineFunc) {
			if (!VMEngineFunc) return false;
			MDNode* MD = VMEngineFunc->getMetadata(kPopulatedMDKey);
			if (!MD || MD->getNumOperands() == 0) return false;
			auto* CAM = dyn_cast<ConstantAsMetadata>(MD->getOperand(0));
			if (!CAM) return false;
			auto* CI = dyn_cast<ConstantInt>(CAM->getValue());
			return CI && CI->isOne();
		}

		void markEnginePopulated(Function* VMEngineFunc) {
			if (!VMEngineFunc) return;
			LLVMContext& C = VMEngineFunc->getContext();
			MDNode* TrueMD = MDNode::get(C, {
				ConstantAsMetadata::get(ConstantInt::getTrue(C))
				});
			VMEngineFunc->setMetadata(kPopulatedMDKey, TrueMD);
		}

		SharedState* getSharedState(Module& M, unsigned EngineId) {
			std::lock_guard<std::mutex> LK(SharedStateMu);
			auto& Ptr = SharedStateMap[{&M, EngineId}];
			if (!Ptr) Ptr = std::make_unique<SharedState>();
			return Ptr.get();
		}

		void releaseSharedState(Module& M) {
			std::lock_guard<std::mutex> LK(SharedStateMu);
			SmallVector<std::pair<Module*, unsigned>, 4> ToErase;
			for (auto& KV : SharedStateMap)
				if (KV.first.first == &M) ToErase.push_back(KV.first);
			for (auto& K : ToErase) SharedStateMap.erase(K);
		}

	} // namespace VMEngine
} // namespace llvm


// setupEffLocal: point Eff* at per-function allocas/globals

void VMImpl::setupEffLocal() {
	HFn = &F;
	EffBC = (EncBytecode && GVBytecodeRT) ? (Value*)GVBytecodeRT : (Value*)GVBytecode;
	EffBCLen = nullptr;
	EffSalt = VMSalt;
	EffRegs = VMRegs;
	EffRegs64 = VMRegs64;
	EffFregs = VMFregs;
	EffPregs = VMPRegs;
	EffCallees = GVCallees;
	EffFTyIndices = GVFTyIndices;
	EffHandlers = GVHandlers;
	MaskVR = ConstantInt::get(I32Ty, NVRAlloc > 0 ? NVRAlloc - 1 : 0);
	MaskVR64 = ConstantInt::get(I32Ty, NVR64Alloc > 0 ? NVR64Alloc - 1 : 0);
	MaskFR = ConstantInt::get(I32Ty, NFRAlloc > 0 ? NFRAlloc - 1 : 0);
	MaskPR = ConstantInt::get(I32Ty, NPRAlloc > 0 ? NPRAlloc - 1 : 0);
	// local mode never encrypts registers (no engine params)
	EffRegKeys = nullptr;
	EffReg64Keys = nullptr;
	EffFRegKeys = nullptr;
	EffCalleeMask = nullptr;  // no callee masking in local mode
	EffLazyCtx = nullptr;    // local mode never uses lazy AES fetch
	SharedEngineMode = false;
}


// populateVMEngine: build all handlers inside shared vm_engine 

void VMImpl::populateVMEngine() {
	auto* SS = VMEngine::getSharedState(M, EngineId);
	if (SS->Populated) return;

	// Create __vm_engine AND populate it atomically 
	// The function must never be visible to LLVM infrastructure as an
	// empty declaration — MSVC debug ilist sentinel assertions fire when
	// anything iterates an empty basic block list.  We create the function
	// and immediately start adding blocks in the same C++ scope.

	FunctionType* FTy = VMEngine::getVMEngineFunctionType(Ctx, LazyDecrypt);
	Function* EF = Function::Create(FTy, GlobalValue::InternalLinkage,
		VMEngine::vmEngineName(EngineId), &M);

	// CRITICAL: Create the entry block IMMEDIATELY after Function::Create.
	// The function must never be observable with an empty block list —
	// MSVC debug builds assert on ilist sentinel dereference if anything
	// (pass manager, analysis invalidation) iterates an empty function.
	BasicBlock* EngEntry = BasicBlock::Create(Ctx, "vm.entry", EF);

	{
		unsigned PIdx = 0;
		static const char* const PNames[] = {
			"bc", "bc_len", "regs", "regs64", "fregs", "pregs",
			"callees", "salt", "regMask", "reg64Mask", "fregMask", "pregMask",
			"handlers", "fty_indices",
			"regkeys", "reg64keys", "fregkeys",
			"callee_mask",
			"lazyctx",
		};
		for (Argument& A : EF->args()) A.setName(PNames[PIdx++]);
	}
	EF->addFnAttr(Attribute::NoUnwind);
	EF->addFnAttr(Attribute::NoInline);
	EF->addFnAttr(Attribute::OptimizeNone);
	EF->setUnnamedAddr(GlobalValue::UnnamedAddr::None);
	SS->EngineFn = EF;



	// Set up Eff* to point at vm_engine parameters
	HFn = EF;
	SharedEngineMode = true;

	EffBC = EF->getArg(VMEngine::kParamBC);
	EffBCLen = EF->getArg(VMEngine::kParamBCLen);
	EffRegs = EF->getArg(VMEngine::kParamRegs);
	EffRegs64 = EF->getArg(VMEngine::kParamRegs64);
	EffFregs = EF->getArg(VMEngine::kParamFregs);
	EffPregs = EF->getArg(VMEngine::kParamPregs);
	EffCallees = EF->getArg(VMEngine::kParamCallees);
	EffHandlers = EF->getArg(VMEngine::kParamHandlers);
	EffFTyIndices = EF->getArg(VMEngine::kParamFTyIndices);
	MaskVR = EF->getArg(VMEngine::kParamRegMask);
	MaskVR64 = EF->getArg(VMEngine::kParamReg64Mask);
	MaskFR = EF->getArg(VMEngine::kParamFregMask);
	MaskPR = EF->getArg(VMEngine::kParamPregMask);
	// key array pointers (null when regEncrypt is off)
	EffRegKeys = EF->getArg(VMEngine::kParamRegKeys);
	EffReg64Keys = EF->getArg(VMEngine::kParamReg64Keys);
	EffFRegKeys = EF->getArg(VMEngine::kParamFRegKeys);
	EffCalleeMask = EF->getArg(VMEngine::kParamCalleeMask);
	EffLazyCtx = LazyDecrypt ? EF->getArg(VMEngine::kParamLazyCtx) : nullptr;

	// lazyDecrypt: forward-declare the runtime keystream helper so the fetch
	// path (loadBC/loadBCDyn, built below) can call it. buildEncryptCtor()
	// links the AES stub bitcode (which defines this symbol) later, for the
	// founding function's own ctor — the linker resolves this declaration
	// against that definition.
	if (LazyDecrypt) {
		KeystreamFn = M.getFunction("__obf_aes_ctr_keystream_block");
		if (!KeystreamFn) {
			FunctionType* KSFTy = FunctionType::get(Type::getVoidTy(Ctx),
				{ PtrTy, PtrTy, I32Ty, PtrTy }, /*isVarArg=*/false);
			KeystreamFn = Function::Create(KSFTy, GlobalValue::ExternalLinkage,
				"__obf_aes_ctr_keystream_block", &M);
		}
	}

	// Build vm.entry with VMIP + salt alloca
	Entry = EngEntry;  // already created above
	IRBuilder<> EB(Entry);
	VMIP = EB.CreateAlloca(I32Ty, nullptr, "vm.ip");
	AllocaInst* SaltAlloca = EB.CreateAlloca(I32Ty, nullptr, "vm.salt");
	EB.CreateStore(EF->getArg(VMEngine::kParamSalt), SaltAlloca)->setVolatile(true);
	EffSalt = SaltAlloca;
	EB.CreateStore(EB.getInt32(0), VMIP)->setVolatile(true);

	SS->EngineVMIP = VMIP;
	SS->EngineSalt = SaltAlloca;
	SS->Entry = Entry;

	// Create Dispatch shell (central-dispatch builds only; threadedDispatch
	// has no shared vm.dispatch/vm.fetch pair -- see buildDispatch()).
	if (!ThreadedDispatch) {
		Dispatch = BasicBlock::Create(Ctx, "vm.dispatch", EF);
		SS->Dispatch = Dispatch;
	}

	// Build all 51 opcode handlers
	NumVariants = Cfg.handlerVariants;
	if (NumVariants < 1) NumVariants = 1;
	if (NumVariants > kMaxHandlerVariants) NumVariants = kMaxHandlerVariants;
	EncDispatch = Cfg.encDispatch;

	// threadedDispatch: every handler inlines its own fetch/decode/indirectbr
	// tail (see emitThreadedTail()), which needs the FULL successor set --
	// every opcode/variant block plus ExitBB -- before any handler body is
	// built (the first handler emitted may branch to the last one). Pre-create
	// empty placeholder blocks for all of them up front; mkOpc() fills each in
	// (renaming, not reallocating) as buildOpcodeHandlers() reaches it.
	if (ThreadedDispatch) {
		ExitBB = BasicBlock::Create(Ctx, "vm.exit", EF);
		new UnreachableInst(Ctx, ExitBB);
		for (unsigned i = 0; i < OP_COUNT; ++i)
			for (unsigned v = 0; v < NumVariants; ++v) {
				BasicBlock* BB = BasicBlock::Create(Ctx, "vm.opc.pending", EF);
				OpcBB[i][v] = BB;
				VariantOf[BB] = (uint8_t)v;
			}
	}

	buildOpcodeHandlers();

	// Make the K structurally-identical variants distinct (per-variant MBA).
	diversifyHandlerVariants(EF);

	// Make this pool clone's handler bodies distinct from the other engines'
	// (per-clone MBA, seeded by EngineId). No-op unless metamorphicEngines is on.
	metamorphRewriteEngine(EF);

	// M3: static decoy handlers. computeNumDecoys() returns 0 when
	// handlerDecoys==0 or nestedVM==1 -- buildDecoyHandlers() is then a
	// no-op that touches no IR (byte-identical to pre-M3 output).
	NumDecoys = computeNumDecoys();
	buildDecoyHandlers();
	SS->NumDecoys = NumDecoys;
	SS->EngineJunk = EngineJunk;
	SS->DecoyBB.clear();
	for (unsigned i = 0; i < NumDecoys; ++i)
		SS->DecoyBB.push_back(DecoyBB[i]);

	SS->NumVariants = NumVariants;
	SS->EncDispatch = EncDispatch;
	SS->LazyMode = LazyDecrypt;
	for (unsigned i = 0; i < OP_COUNT; ++i)
		for (unsigned v = 0; v < NumVariants; ++v)
			SS->OpcBB[i][v] = OpcBB[i][v];

	// Build dispatch loop
	buildDispatch();
	SS->ExitBB = ExitBB;

	// insert anti-debug timing gate between dispatch and fetch
	buildAntiDebugGate(SS);

	SS->Populated = true;
	SS->FTyCountAtLastBuild = (unsigned)SS->SharedFTys.size();
	VMEngine::markEnginePopulated(EF);

	if (Cfg.hardened)
		hardenVMEngine(EF, SS);

	LLVM_DEBUG(dbgs() << "[vm] populated vm_engine with "
		<< OP_COUNT << " handler blocks\n");
	if (ObfVerbose)
		errs() << "[vm] vm_engine populated: " << OP_COUNT << " handlers\n";

	// Restore per-function state
	SharedEngineMode = false;
	HFn = &F;
}




// ensureCallFTyCases: extend CALL switches for new FunctionTypes
//
// Called after buildCalleeGlobal() in each function's run().  If this
// function introduced FunctionTypes not seen when the engine was first
// populated, adds new case blocks to the existing CALL handler switches
// inside __vm_engine.

void VMImpl::ensureCallFTyCases() {
	auto* SS = VMEngine::getSharedState(M, EngineId);
	if (!SS->Populated) return;
	unsigned OldCount = SS->FTyCountAtLastBuild;
	unsigned NewCount = (unsigned)SS->SharedFTys.size();
	if (NewCount <= OldCount) return;

	Function* EF = SS->EngineFn;
	if (!EF) return;

	LLVM_DEBUG(dbgs() << "[vm] extending CALL switches: " << OldCount
		<< " -> " << NewCount << " FunctionTypes\n");

	// For each CALL opcode (indexed by RetKind2 0..4):
	for (unsigned RKIdx = 0; RKIdx < 5; ++RKIdx) {
		auto& CSW = SS->CallSW[RKIdx];
		if (!CSW.SW) continue;  // this CALL opcode wasn't built

		VMEngine::RetKind2 RK = CSW.RK;
		bool IsVoid = (RK == VMEngine::RK2_VOID);
		Type* RetTy = (RK == VMEngine::RK2_PTR) ? (Type*)PtrTy
			: (RK == VMEngine::RK2_I64) ? (Type*)I64Ty
			: (RK == VMEngine::RK2_F64) ? (Type*)DoubleTy
			: (RK == VMEngine::RK2_I32) ? (Type*)I32Ty
			: (Type*)Type::getVoidTy(Ctx);

		for (unsigned TIdx = OldCount; TIdx < NewCount; ++TIdx) {
			FunctionType* SrcFTy = SS->SharedFTys[TIdx];
			unsigned N = SrcFTy->getNumParams();
			bool isVA = SrcFTy->isVarArg();

			auto* CaseBB = BasicBlock::Create(Ctx,
				"vm.cl.fty" + Twine(TIdx), EF);
			CSW.SW->addCase(
				cast<ConstantInt>(ConstantInt::get(I32Ty, TIdx)), CaseBB);
			IRBuilder<> CB(CaseBB);

			SmallVector<Type*, VMEngine::MaxArgs> ATys;
			SmallVector<Value*, VMEngine::MaxArgs> CA;
			for (unsigned i = 0; i < N && i < VMEngine::MaxArgs; ++i) {
				Type* PT = SrcFTy->getParamType(i);
				if (PT->isFloatTy() || PT->isDoubleTy()) {
					ATys.push_back(DoubleTy);
					CA.push_back(CSW.FregVals[i]);
				}
				else {
					ATys.push_back(PtrTy);
					if (PT->isPointerTy())
						CA.push_back(CSW.PVals[i]);
					else if (PT->isIntegerTy(64))
						CA.push_back(CSW.I64Vs[i]);
					else
						CA.push_back(CSW.IVals[i]);
				}
			}

			auto* CallFTy = FunctionType::get(RetTy, ATys, isVA);
			auto* CI = CB.CreateCall(CallFTy, CSW.Callee, CA,
				IsVoid ? "" : "vm.cl.rv");
			if (!IsVoid && CSW.RetPHI)
				CSW.RetPHI->addIncoming(CI, CB.GetInsertBlock());
			CB.CreateBr(CSW.MergeBB);
		}
	}

	SS->FTyCountAtLastBuild = NewCount;
	if (ObfVerbose && NewCount > OldCount)
		errs() << "[vm] extended CALL handlers: +"
		<< (NewCount - OldCount) << " FunctionTypes\n";
}
