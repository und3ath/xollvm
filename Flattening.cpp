#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/LowerSwitch.h"

#include "llvm/Transforms/Obfuscator/PassCtx.h"
#include "llvm/Transforms/Obfuscator/FunctionObfContextAnalysis.h"
#include "llvm/Transforms/Obfuscator/Flattening.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/Utils.h"
#include "llvm/Transforms/Obfuscator/OpaqueUtils.h"
#include "llvm/Transforms/Obfuscator/EHUtils.h"



#include <set>

using namespace llvm;

#define DEBUG_TYPE "flattening"

STATISTIC(Flattened, "Functions flattened");


namespace {


	struct FlaCtx;

	struct FlaImpl final {
		// --------------------------------------------------------------------------
		// Config
		// --------------------------------------------------------------------------
		static FlatteningConfig getFlatteningConfig(Function& F, FunctionAnalysisManager& AM);
		static constexpr llvm::StringRef kFlaOpaqueSlot = "fla.opaque.salt.i32";

		// --------------------------------------------------------------------------
		// Small bit-mix utilities
		// --------------------------------------------------------------------------
		static inline uint32_t rotl32c(uint32_t x, unsigned r) {
			r &= 31u;
			return (r == 0) ? x : (x << r) | (x >> (32u - r));
		}
		static Value* rotl32ir(IRBuilder<>& B, Value* V, unsigned r);

		// --------------------------------------------------------------------------
		// Domain-per-dispatcher encoding
		// --------------------------------------------------------------------------
		static void initPerDispatcherDomains(FlaCtx& PCtx, FunctionObfContext& Ctx);
		static uint32_t dispatcherDomainConst(uint32_t Enc, unsigned DispIdx, const FunctionObfContext& Ctx);
		static Value* dispatcherDomainIR(IRBuilder<>& B, Value* Enc, unsigned DispIdx, const FunctionObfContext& Ctx);



		// --------------------------------------------------------------------------
		// State pointer obfuscation layer
		// --------------------------------------------------------------------------
		static void ensureStatePtrObfSlots(FlaCtx& PCtx, FunctionObfContext& Ctx);
		static Value* getStateI32Ptr(IRBuilder<>& B, FlaCtx& PCtx, FunctionObfContext& Ctx);
		static Value* loadState(IRBuilder<>& B, FlaCtx& PCtx, FunctionObfContext& Ctx);
		static void storeState(IRBuilder<>& B, FlaCtx& PCtx, FunctionObfContext& Ctx, Value* V);
		static Instruction* getAllocaIP(Function& F);

		// --------------------------------------------------------------------------
		// State encoding / router mixing
		// --------------------------------------------------------------------------
		static uint32_t encodeStateConst(uint32_t Raw, const FunctionObfContext& Ctx);
		static uint32_t routerMixConst(uint32_t Enc, const FunctionObfContext& Ctx);
		static Value* routerMixIR(IRBuilder<>& B, Value* Enc, FunctionObfContext& Ctx);

		// --------------------------------------------------------------------------
		// Fake transitions
		// --------------------------------------------------------------------------
		static uint32_t pickFakeEncodedState(FlaCtx& PCtx, FunctionObfContext& Ctx,
			std::initializer_list<uint32_t> AvoidEnc);
		static Value* applyFakeTransition(IRBuilder<>& B, FlaCtx& PCtx, FunctionObfContext& Ctx,
			Value* RealNext, std::initializer_list<uint32_t> AvoidEnc);

		// --------------------------------------------------------------------------
		// Stack/dominance repair
		// --------------------------------------------------------------------------
		static bool valueEscapes(const Instruction& Inst);
		static void fixStack(Function& F);

		// --------------------------------------------------------------------------
		// Eligibility / preparation
		// --------------------------------------------------------------------------
		static bool isFlattenEligible(const Function& F, const FunctionObfContext& Ctx,
			const FlatteningConfig& Cfg, raw_ostream* Reason = nullptr);
		static unsigned computeNumDispatchers(const FunctionObfContext& Ctx);
		static AllocaInst* createStateVariable(Function& F);
		static void createDispatchers(Function& F, FunctionObfContext& Ctx);
		static void assignBlockIDs(FlaCtx& PCtx);
		static void assignDispatcherGroupsFromEncodedState(FunctionObfContext& Ctx);
		static void createRouter(Function& F, FunctionObfContext& Ctx);
		static BasicBlock* getOrCreateExitTrampline(Function& F);

		// --------------------------------------------------------------------------
		// Core construction
		// --------------------------------------------------------------------------
		static bool prepareFlattening(FlaCtx& PCtx);
		static void buildRouter(Function& F, FunctionObfContext& Ctx, FlaCtx& PCtx);
		static void buildDispatcherSwitchesEncoded(Function& F, FunctionObfContext& Ctx, FlaCtx& PCtx);
		static void rewriteEntryBlockRouter(Function& F, FunctionObfContext& Ctx, FlaCtx& PCtx);
		static void rewriteFlattenedBlocksRouter(Function& F, FunctionObfContext& Ctx, FlaCtx& PCtx);
		static bool flattenFunction(FlaCtx& PCtx);

#ifndef NDEBUG
		// --------------------------------------------------------------------------
		// Debug instrumentation / verification
		// --------------------------------------------------------------------------
		static void insertDispatcherLogging(Function& F, FlaCtx& PCtx, FunctionObfContext& Ctx);
		static void insertStateValidation(Function& F, FlaCtx& PCtx, FunctionObfContext& Ctx);
		static void dumpStateTransitions(Function& F, FunctionObfContext& Ctx, raw_ostream& OS);
		static void verifyDispatcherCoverage(Function& F, FlaCtx& PCtx, FunctionObfContext& Ctx, raw_ostream& OS);
		static bool verifyFlatteningIR(Function& F, FunctionObfContext& Ctx, raw_ostream& OS);
#endif
	};





	struct FlaCtx : llvm::obf::FuncPassCtx {
		llvm::FlatteningConfig Cfg;
		llvm::FunctionObfContext& FOC;

		llvm::obf::Rng KeysRng;   // state/router keys
		llvm::obf::Rng IdRng;     // block IDs + shuffle
		llvm::obf::Rng OpaqueRng; // opaque state material
		llvm::obf::Rng FakeRng;   // fake edges/cases selection
		llvm::obf::Rng DomainRng;
		llvm::obf::Rng PtrRng;

		llvm::obf::OpaqueUtils Opaque;

		static llvm::obf::OpaqueUtils::Options makeOpaqueOpts(const FlatteningConfig& Cfg) {
			const bool WantOpaqueConsts = Cfg.OpaqueState;
			const bool WantHardPreds = Cfg.OpaqueAliasStatePtr || Cfg.FakeTransitions; // or Cfg.OpaqueState
			const bool WantVolLoads = Cfg.OpaqueState || Cfg.FakeTransitions || Cfg.ObfuscateStatePtr;

			llvm::obf::OpaqueUtils::Options O;
			O.EnableOpaqueConsts = WantOpaqueConsts;
			O.EnableOpaqueBools = true;
			O.EnableHardPreds = WantHardPreds;
			O.VolatileLoads = WantVolLoads;

			// Strength heuristic: flattening can afford heavier constant predicates when
			// fake transitions / opaque state ptr logic is enabled.
			O.PredStrength = (Cfg.FakeTransitions || Cfg.OpaqueAliasStatePtr) ? 3u :
				(Cfg.OpaqueState || Cfg.ObfuscateStatePtr) ? 2u : 1u;

			return O;
		}




		FlaCtx(Function& F, FunctionAnalysisManager& AM)
			: FuncPassCtx(F, AM, "flattening"),
			Cfg(FlaImpl::getFlatteningConfig(F, AM)),
			FOC(*AM.getResult<llvm::FunctionObfContextAnalysis>(F)),
			KeysRng(R.fork("keys")),
			OpaqueRng(R.fork("opaque")),
			FakeRng(R.fork("fake")),
			IdRng(R.fork("ids")),
			DomainRng(R.fork("domain")),
			PtrRng(R.fork("ptr")),
			Opaque(M, OpaqueRng, FlaImpl::kFlaOpaqueSlot, makeOpaqueOpts(Cfg)) {
		}
	};



	// ============================================================================
	// Helper Functions
	// ============================================================================

	Instruction* FlaImpl::getAllocaIP(Function& F) {
		return llvm::obf::getAllocaIP(F);
	}


	Value* FlaImpl::rotl32ir(IRBuilder<>& B, Value* V, unsigned r) {
		r &= 31u;
		if (r == 0) return V;
		Type* I32 = Type::getInt32Ty(B.getContext());
		Value* Shl = B.CreateShl(V, ConstantInt::get(I32, r), "fla.rotl.shl");
		Value* Shr = B.CreateLShr(V, ConstantInt::get(I32, 32u - r), "fla.rotl.shr");
		return B.CreateOr(Shl, Shr, "fla.rotl");
	}

	// Ensure per-dispatcher domain keys exist
	void FlaImpl::initPerDispatcherDomains(FlaCtx& PCtx, FunctionObfContext& Ctx) {
		if (!PCtx.Cfg.PerDispatcherDomain)
			return;

		unsigned N = (unsigned)Ctx.Dispatchers.size();
		if (N == 0) return;

		if (!Ctx.DomXor1.empty() && Ctx.DomXor1.size() == N)
			return;

		Ctx.DomXor1.assign(N, 0);
		Ctx.DomMul.assign(N, 0);
		Ctx.DomAdd.assign(N, 0);
		Ctx.DomXor2.assign(N, 0);
		Ctx.DomRot.assign(N, 0);

		for (unsigned i = 0; i < N; ++i) {
			Ctx.DomXor1[i] = PCtx.DomainRng.u32();
			Ctx.DomMul[i] = (PCtx.DomainRng.u32() | 1u);      // odd
			Ctx.DomAdd[i] = PCtx.DomainRng.u32();
			Ctx.DomXor2[i] = PCtx.DomainRng.u32();
			Ctx.DomRot[i] = (uint8_t)(1 + PCtx.DomainRng.range(31)); // 1..31
		}
	}

	uint32_t FlaImpl::dispatcherDomainConst(uint32_t Enc, unsigned DispIdx,
		const FunctionObfContext& Ctx) {
		uint32_t x = Enc ^ Ctx.DomXor1[DispIdx];
		x = x * Ctx.DomMul[DispIdx] + Ctx.DomAdd[DispIdx];
		x = rotl32c(x, Ctx.DomRot[DispIdx]);
		x ^= Ctx.DomXor2[DispIdx];
		return x;
	}

	Value* FlaImpl::dispatcherDomainIR(IRBuilder<>& B, Value* Enc, unsigned DispIdx,
		const FunctionObfContext& Ctx) {
		Type* I32 = Type::getInt32Ty(B.getContext());
		Value* x = B.CreateXor(Enc, ConstantInt::get(I32, Ctx.DomXor1[DispIdx]), "fla.dom.x1");
		x = B.CreateMul(x, ConstantInt::get(I32, Ctx.DomMul[DispIdx]), "fla.dom.mul");
		x = B.CreateAdd(x, ConstantInt::get(I32, Ctx.DomAdd[DispIdx]), "fla.dom.add");
		x = rotl32ir(B, x, Ctx.DomRot[DispIdx]);
		x = B.CreateXor(x, ConstantInt::get(I32, Ctx.DomXor2[DispIdx]), "fla.dom.x2");
		return B.CreateFreeze(x, "fla.dom.fr");
	}

	// --- State pointer obfuscation ---

	void FlaImpl::ensureStatePtrObfSlots(FlaCtx& PCtx, FunctionObfContext& Ctx) {
		if (!PCtx.Cfg.ObfuscateStatePtr)
			return;
		if (Ctx.StatePtrSlot)
			return;

		Function& F = *Ctx.StatVar->getFunction();
		LLVMContext& C = F.getContext();
		Type* I32 = Type::getInt32Ty(C);

		// Opaque pointer type: "ptr" in addrspace(0)
		Type* PtrTy = PointerType::get(C, 0);

		IRBuilder<> EB(getAllocaIP(F));

		// Fake alias location (never used at runtime, but poisons AA/MemorySSA)
		Ctx.AliasStateSlot = EB.CreateAlloca(I32, nullptr, "fla.state.alias.i32");
		auto* AliasInit = EB.CreateStore(ConstantInt::get(I32, PCtx.PtrRng.u32()), Ctx.AliasStateSlot);
		AliasInit->setVolatile(true);

		// Pointer slots store opaque ptr values
		Ctx.StatePtrSlot = EB.CreateAlloca(PtrTy, nullptr, "fla.state.ptr");
		Ctx.StatePtrSlotFake = EB.CreateAlloca(PtrTy, nullptr, "fla.state.ptr.fake");

		// In opaque-ptr LLVM, allocas return "ptr" already.
		Value* RealBase = Ctx.StatVar;        // ptr
		Value* FakeBase = Ctx.AliasStateSlot; // ptr

		auto* St0 = EB.CreateStore(RealBase, Ctx.StatePtrSlot);
		auto* St1 = EB.CreateStore(FakeBase, Ctx.StatePtrSlotFake);

		// Volatile keeps pointer materialization and makes AA/MemorySSA conservative.
		St0->setVolatile(true);
		St1->setVolatile(true);
	}

	/*Value* FlaImpl::loadFlaOpaqueSalt(IRBuilder<>& B, FlaCtx& PCtx) {
		AllocaInst* Slot = getOrCreateFlaOpaqueSalt(PCtx);
		Type* I32 = Type::getInt32Ty(B.getContext());
		auto* L = B.CreateLoad(I32, Slot, "fla.salt");
		L->setVolatile(true);
		return B.CreateFreeze(L, "fla.salt.fr");
	}*/

	/*Value* FlaImpl::opaqueZero64(IRBuilder<>& B, FlaCtx& PCtx) {
		// Requires your earlier helper: loadFlaOpaqueSalt(B, PCtx)
		// If you named it differently, adjust here.
		Type* I32 = Type::getInt32Ty(B.getContext());
		Type* I64 = Type::getInt64Ty(B.getContext());
		Value* A = loadFlaOpaqueSalt(B, PCtx);           // volatile anchored i32
		Value* Z = B.CreateXor(A, A, "fla.z");           // 0, but keeps the volatile load alive
		Z = B.CreateFreeze(Z, "fla.z.fr");
		return B.CreateZExt(Z, I64, "fla.z64");
	}*/

	Value* FlaImpl::getStateI32Ptr(IRBuilder<>& B, FlaCtx& PCtx, FunctionObfContext& Ctx) {
		if (!PCtx.Cfg.ObfuscateStatePtr)
			return Ctx.StatVar; // plain ptr (alloca of i32)

		ensureStatePtrObfSlots(PCtx, Ctx);

		LLVMContext& C = B.getContext();
		Type* PtrTy = PointerType::get(C, 0);              // opaque ptr
		Type* I8 = Type::getInt8Ty(C);

		// Load base pointers (opaque ptr)
		auto* L0 = B.CreateLoad(PtrTy, Ctx.StatePtrSlot, "fla.base");
		auto* L1 = B.CreateLoad(PtrTy, Ctx.StatePtrSlotFake, "fla.base.fake");
		L0->setVolatile(true);
		L1->setVolatile(true);

		Value* RealBase = B.CreateFreeze(L0, "fla.base.fr");
		Value* FakeBase = B.CreateFreeze(L1, "fla.base.fake.fr");

		Value* Base = RealBase;
		if (PCtx.Cfg.OpaqueAliasStatePtr) {
			Value* HF = PCtx.Opaque.hardFalse(B);
			Base = B.CreateSelect(HF, FakeBase, RealBase, "fla.base.sel");
		}

		// Offset is always 0 at runtime, but not provably constant due to volatile.
		// Use non-inbounds GEP to avoid UB assumptions.
		Value* Off = PCtx.Opaque.opaqueZero64(B); // i64 0 (opaque)
		Value* P = B.CreateGEP(I8, Base, Off, "fla.p");  // still opaque ptr

		// Return opaque ptr. Loads/stores specify I32 type explicitly.
		return P;
	}


	Value* FlaImpl::loadState(IRBuilder<>& B, FlaCtx& PCtx, FunctionObfContext& Ctx) {
		Type* I32 = Type::getInt32Ty(B.getContext());
		Value* P = getStateI32Ptr(B, PCtx, Ctx);
		auto* L = B.CreateLoad(I32, P, "fla.state");
		if (PCtx.Cfg.OpaqueState || PCtx.Cfg.FakeTransitions || PCtx.Cfg.ObfuscateStatePtr)
			L->setVolatile(true);
		return B.CreateFreeze(L, "fla.state.fr");
	}

	void FlaImpl::storeState(IRBuilder<>& B, FlaCtx& PCtx, FunctionObfContext& Ctx, Value* V) {
		Value* P = getStateI32Ptr(B, PCtx, Ctx);
		auto* S = B.CreateStore(V, P);
		if (PCtx.Cfg.OpaqueState || PCtx.Cfg.FakeTransitions || PCtx.Cfg.ObfuscateStatePtr)
			S->setVolatile(true);
	}


	uint32_t FlaImpl::encodeStateConst(uint32_t Raw, const FunctionObfContext& Ctx) {
		// 32-bit wrap is intended
		return (Raw ^ Ctx.StateXorKey) + Ctx.StateAddKey;
	}

	unsigned FlaImpl::computeNumDispatchers(const FunctionObfContext& Ctx) {
		if (Ctx.NumBlocks < 6)
			return 1;

		if (Ctx.NumBlocks < 15)
			return 2;

		return 3;
	}

	bool FlaImpl::valueEscapes(const Instruction& Inst) {
		if (!Inst.getType()->isSized())
			return false;

		const BasicBlock* BB = Inst.getParent();
		for (const User* U : Inst.users()) {
			const Instruction* UI = dyn_cast<Instruction>(U);
			if (!UI) continue;
			if (UI->getParent() != BB || isa<PHINode>(UI))
				return true;
		}
		return false;
	}


	void FlaImpl::fixStack(Function& F) {
		std::vector<PHINode*> tmpPhi;
		std::vector<Instruction*> tmpReg;
		BasicBlock* bbEntry = &F.getEntryBlock();

		Instruction* AllocaIP = getAllocaIP(F); // <--- key change

		do {
			tmpPhi.clear();
			tmpReg.clear();

			for (BasicBlock& BB : F) {
				for (Instruction& I : BB) {
					if (PHINode* phi = dyn_cast<PHINode>(&I)) {
						tmpPhi.push_back(phi);
						continue;
					}
					// Token / label / metadata types are unsized — DemoteRegToStack
					// will assert when creating an AllocaInst for them.  Skip early.
					if (!I.getType()->isSized())
						continue;
					if (!(isa<AllocaInst>(I) && I.getParent() == bbEntry) &&
						(valueEscapes(I) || I.isUsedOutsideOfBlock(&BB))) {
						tmpReg.push_back(&I);
					}
				}
			}

			for (Instruction* I : tmpReg) {
				DemoteRegToStack(*I, AllocaIP); // <--- was entry terminator
			}

			for (PHINode* phi : tmpPhi) {
				// Keep your current call if your LLVM wants std::optional here.
				// If your LLVM has an overload taking Instruction* insertion point, prefer that.
				DemotePHIToStack(phi, std::nullopt);
			}

		} while (!tmpReg.empty() || !tmpPhi.empty());
	}



	void FlaImpl::assignBlockIDs(FlaCtx& PCtx) {
		auto& Ctx = PCtx.FOC;

		Ctx.BlockIDs.clear();
		std::vector<uint32_t> IDs;

		// generate unique-ish IDs: random 32-bit values
		for (size_t i = 0; i < Ctx.FlattenedBlocks.size(); ++i) {
			uint32_t v = PCtx.IdRng.u32();
			// avoid 0 if you want (optional)
			if (v == 0) v = 1;
			IDs.push_back(v);
		}

		// shuffle mapping so IDs don't correlate to block order
		PCtx.IdRng.shuffle<uint32_t>(llvm::MutableArrayRef<uint32_t>(IDs));

		for (size_t i = 0; i < Ctx.FlattenedBlocks.size(); ++i) {
			Ctx.BlockIDs[Ctx.FlattenedBlocks[i]] = IDs[i];
		}
	}

	bool FlaImpl::isFlattenEligible(const Function& F, const FunctionObfContext& Ctx,
		const FlatteningConfig& Cfg,
		raw_ostream* Reason) {
		if (F.isDeclaration()) {
			if (Reason)
				*Reason << "declaration";
			return false;
		}

		if (Ctx.NumBlocks < Cfg.MinBlocks) {
			if (Reason)
				*Reason << "too few blocks";
			return false;
		}

		if (Ctx.NumBlocks > Cfg.MaxBlocks) {
			if (Reason)
				*Reason << "too many blocks";
			return false;
		}


		// ── Reject funclet-based EH (Windows SEH / WinEH) ────────────
		// The Windows OS unwinder relies on .xdata/.pdata tables that map
		// PC ranges to catch handlers.  Flattening scrambles the CFG and
		// makes those tables stale, causing stack corruption at runtime.
		// Itanium-style EH (landingpad) is handled via the trampoline
		// mechanism in rewriteFlattenedBlocksRouter and is still allowed.
		if (Ctx.HasCatchSwitch || Ctx.HasCatchPad || Ctx.HasCleanupPad) {
			if (Reason)
				*Reason << "funclet-based EH (WinEH) — incompatible with flattening";
			return false;
		}


		if (Ctx.HasInvoke) {
			// Phase 1.2: Instead of rejecting outright, allow if there are
			// enough non-EH blocks to make flattening worthwhile.
			unsigned NormalBlocks = 0;
			for (const BasicBlock& BB : F) {
				if (!BB.isEHPad() && !llvm::obf::isInEHRegion(&BB))
					++NormalBlocks;

			}
			if (NormalBlocks < Cfg.MinBlocks) {
				if (Reason)
					*Reason << "invoke present, too few non-EH blocks ("
					<< NormalBlocks << ")";
				return false;

			}
			// Allowed: flattening will use EHUtils to only flatten
			// normal blocks, leaving EH pads untouched.
		}

		if (Ctx.HasIndirectBr) {
			if (Reason)
				*Reason << "indirectbr present";
			return false;
		}

		if (Ctx.HasMustTail) {
			if (Reason)
				*Reason << "musttail call";
			return false;
		}


		if (Ctx.HasCallBr) {
			if (Reason)
				*Reason << "callbr present";
			return false;

		}

		if (Ctx.HasConvergentCalls) {
			if (Reason)
				*Reason << "convergent call present";
			return false;

		}

		if (Ctx.HasNaked) {
			if (Reason)
				*Reason << "naked function";
			return false;

		}

		if (!Cfg.AllowIndirect && Ctx.HasIndirectCalls) {
			if (Reason)
				*Reason << "indirect calls";
			return false;
		}

		if (Ctx.NumExits == 0) {
			if (Reason)
				*Reason << "no exit blocks";
			return false;
		}

		return true;
	}



	AllocaInst* FlaImpl::createStateVariable(Function& F) {
		IRBuilder<> B(getAllocaIP(F));
		return B.CreateAlloca(Type::getInt32Ty(F.getContext()), nullptr, "fla.state");
	}

	void FlaImpl::createDispatchers(Function& F, FunctionObfContext& Ctx) {
		LLVMContext& LC = F.getContext();

		Ctx.Dispatchers.clear();

		for (unsigned i = 0; i < Ctx.NumDispatchers; ++i) {
			auto* DB = BasicBlock::Create(LC, "fla.dispatch." + Twine(i), &F);
			Ctx.Dispatchers.push_back(DB);
		}

		Ctx.Dispatcher = Ctx.Dispatchers.front(); // compatibility
	}


	BasicBlock* FlaImpl::getOrCreateExitTrampline(Function& F) {
		for (BasicBlock& BB : F) {
			if (BB.getName() == "fla.exit.trampoline")
				return &BB;
		}

		LLVMContext& LC = F.getContext();
		BasicBlock* Exit = BasicBlock::Create(LC, "fla.exit.trampoline", &F);
		IRBuilder<> B(Exit);

		// DEBUGGING VERSION (use during development):
#ifndef NDEBUG
  // Print which state caused the problem
		Function* TrapFn =
			Intrinsic::getOrInsertDeclaration(F.getParent(), Intrinsic::trap);
		B.CreateCall(TrapFn);
#endif

		// PRODUCTION VERSION:
		B.CreateUnreachable();

		return Exit;
	}



#ifndef NDEBUG
	void FlaImpl::insertDispatcherLogging(Function& F, FlaCtx& PCtx, FunctionObfContext& Ctx) {

		LLVMContext& LC = F.getContext();
		Type* I32Ty = Type::getInt32Ty(LC);
		Module* M = F.getParent();

		ArrayType* HistoryType = ArrayType::get(I32Ty, 100);
		GlobalVariable* StateHistory = M->getGlobalVariable("fla.state_history");
		if (!StateHistory) {
			StateHistory = new GlobalVariable(
				*M, HistoryType, false, GlobalValue::InternalLinkage,
				ConstantAggregateZero::get(HistoryType), "fla.state_history");
		}

		GlobalVariable* HistoryIndex = M->getGlobalVariable("fla.history_index");
		if (!HistoryIndex) {
			HistoryIndex = new GlobalVariable(
				*M, I32Ty, false, GlobalValue::InternalLinkage,
				ConstantInt::get(I32Ty, 0), "fla.history_index");
		}

		for (unsigned i = 0; i < Ctx.Dispatchers.size(); ++i) {
			BasicBlock* Disp = Ctx.Dispatchers[i];
			Instruction* FirstInst = &*Disp->getFirstInsertionPt();
			IRBuilder<> B(FirstInst);

			// Load current encoded state through pointer-obfuscation layer
			Value* CurrentState = loadState(B, PCtx, Ctx);

			Value* Index = B.CreateLoad(I32Ty, HistoryIndex, "history.index");
			Value* WrappedIndex = B.CreateURem(Index, ConstantInt::get(I32Ty, 100), "history.index.mod");

			Value* Indices[] = { ConstantInt::get(I32Ty, 0), WrappedIndex };
			Value* HistoryPtr = B.CreateInBoundsGEP(HistoryType, StateHistory, Indices, "history.ptr");

			// Store current state to history (volatile)
			auto* St = B.CreateStore(CurrentState, HistoryPtr);
			St->setVolatile(true);

			Value* NextIndex = B.CreateAdd(Index, ConstantInt::get(I32Ty, 1), "history.index.next");
			B.CreateStore(NextIndex, HistoryIndex);
		}

		errs() << "[validation] Instrumented " << Ctx.Dispatchers.size()
			<< " dispatchers with state logging\n";

	}

	void FlaImpl::insertStateValidation(Function& F, FlaCtx& PCtx, FunctionObfContext& Ctx)
	{

		LLVMContext& LC = F.getContext();
		Type* I32Ty = Type::getInt32Ty(LC);
		Module* M = F.getParent();

		GlobalVariable* InvalidCounter = M->getGlobalVariable("fla.invalid_states");
		if (!InvalidCounter) {
			InvalidCounter = new GlobalVariable(
				*M, I32Ty, false, GlobalValue::InternalLinkage,
				ConstantInt::get(I32Ty, 0), "fla.invalid_states");
		}

		BasicBlock* ExitTramp = getOrCreateExitTrampline(F);

		Instruction* TrapInst = nullptr;
		for (Instruction& I : *ExitTramp) {
			if (isa<CallInst>(&I) || isa<UnreachableInst>(&I)) {
				TrapInst = &I;
				break;
			}
		}

		if (TrapInst) {
			IRBuilder<> B(TrapInst);

			Value* Counter = B.CreateLoad(I32Ty, InvalidCounter, "invalid.count");
			Value* Incremented = B.CreateAdd(Counter, ConstantInt::get(I32Ty, 1), "invalid.count.inc");
			B.CreateStore(Incremented, InvalidCounter);

			// Load bad encoded state through pointer-obfuscation layer
			Value* BadState = loadState(B, PCtx, Ctx);

			GlobalVariable* LastBadState = M->getGlobalVariable("fla.last_bad_state");
			if (!LastBadState) {
				LastBadState = new GlobalVariable(
					*M, I32Ty, false, GlobalValue::InternalLinkage,
					ConstantInt::get(I32Ty, 0), "fla.last_bad_state");
			}
			auto* St = B.CreateStore(BadState, LastBadState);
			St->setVolatile(true);
		}

		errs() << "[validation] Instrumented exit trampoline for function "
			<< F.getName() << "\n";

	}


	void FlaImpl::dumpStateTransitions(Function& F, FunctionObfContext& Ctx,
		raw_ostream& OS) {
		OS << "\n=== State Transition Map ===\n";
		OS << "Function: " << F.getName() << "\n";
		OS << "Num Dispatchers: " << Ctx.Dispatchers.size() << "\n";
		OS << "State XOR Key: " << Ctx.StateXorKey << "\n";
		OS << "State ADD Key: " << Ctx.StateAddKey << "\n\n";

		for (BasicBlock* BB : Ctx.FlattenedBlocks) {
			uint32_t ID = Ctx.BlockIDs.lookup(BB);
			unsigned Grp = Ctx.DispatcherGroups.lookup(BB);
			BasicBlock* Disp = Ctx.BlockToDispatcher.lookup(BB);

			OS << "Block: " << BB->getName() << "\n";
			OS << "  State ID: " << ID << " (0x" << format("%08X", ID) << ")\n";
			OS << "  Encoded: " << ((ID ^ Ctx.StateXorKey) + Ctx.StateAddKey) << " (0x"
				<< format("%08X", (ID ^ Ctx.StateXorKey) + Ctx.StateAddKey) << ")\n";
			OS << "  Group: " << Grp << "\n";
			OS << "  Dispatcher: " << (Disp ? Disp->getName() : "NULL") << "\n";

			Instruction* TI = BB->getTerminator();
			OS << "  Successors: ";
			for (unsigned i = 0; i < TI->getNumSuccessors(); ++i) {
				BasicBlock* Succ = TI->getSuccessor(i);
				OS << Succ->getName();
				if (Ctx.BlockIDs.count(Succ)) {
					OS << " (ID=" << Ctx.BlockIDs.lookup(Succ) << ")";
				}
				if (i + 1 < TI->getNumSuccessors())
					OS << ", ";
			}
			OS << "\n\n";
		}
	}


	void FlaImpl::verifyDispatcherCoverage(Function& F, FlaCtx& PCtx, FunctionObfContext& Ctx,
		raw_ostream& OS) {

		OS << "\n=== Dispatcher Switch Coverage (encoded keys) ===\n";
		OS << "Function: " << F.getName() << "\n";
		OS << "Dispatchers: " << Ctx.Dispatchers.size() << "\n";
		OS << "PerDispatcherDomain: " << (PCtx.Cfg.PerDispatcherDomain ? "ON" : "OFF") << "\n";
		OS << "FakeTransitions: " << (PCtx.Cfg.FakeTransitions ? "ON" : "OFF")
			<< " (FakeCases=" << PCtx.Cfg.FakeCases << ")\n";
		OS << "StateXorKey=0x" << format("%08X", Ctx.StateXorKey)
			<< " StateAddKey=0x" << format("%08X", Ctx.StateAddKey) << "\n";
		OS << "RouterXorKey=0x" << format("%08X", Ctx.RouterXorKey)
			<< " RouterMulKey=0x" << format("%08X", Ctx.RouterMulKey)
			<< " RouterAddKey=0x" << format("%08X", Ctx.RouterAddKey) << "\n";

		const unsigned N = (unsigned)Ctx.Dispatchers.size();
		if (N == 0) {
			OS << "ERROR: no dispatchers\n";
			return;
		}

		BasicBlock* ExitTrampoline = getOrCreateExitTrampline(F);

		struct ExpectedCase {
			BasicBlock* BB = nullptr;
			uint32_t Raw = 0;
			uint32_t Enc = 0;
			uint32_t Key = 0;
			unsigned RouterGrp = 0;
		};

		auto expectedKeyFor = [&](BasicBlock* BB, unsigned DispIdx) -> ExpectedCase {
			ExpectedCase E;
			E.BB = BB;
			E.Raw = Ctx.BlockIDs.lookup(BB);
			E.Enc = encodeStateConst(E.Raw, Ctx);
			E.RouterGrp = (unsigned)(routerMixConst(E.Enc, Ctx) % N);
			E.Key = PCtx.Cfg.PerDispatcherDomain ? dispatcherDomainConst(E.Enc, DispIdx, Ctx) : E.Enc;
			return E;
			};

		auto findExpectedByKey = [&](const std::vector<ExpectedCase>& V, uint32_t Key) -> const ExpectedCase* {
			for (const auto& E : V)
				if (E.Key == Key)
					return &E;
			return nullptr;
			};

		for (unsigned i = 0; i < N; ++i) {
			BasicBlock* Disp = Ctx.Dispatchers[i];
			OS << "\n--- Dispatcher " << i << " (" << Disp->getName() << ") ---\n";

			auto* Sw = dyn_cast_or_null<SwitchInst>(Disp->getTerminator());
			if (!Sw) {
				OS << "ERROR: dispatcher has no switch terminator\n";
				continue;
			}

			OS << "Default: " << Sw->getDefaultDest()->getName();
			if (Sw->getDefaultDest() != ExitTrampoline)
				OS << "  [WARN expected default=" << ExitTrampoline->getName() << "]";
			OS << "\n";
			OS << "NumCases: " << Sw->getNumCases() << "\n";

			if (PCtx.Cfg.PerDispatcherDomain) {
				// print domain parameters for this dispatcher
				OS << "Domain keys: x1=0x" << format("%08X", Ctx.DomXor1[i])
					<< " mul=0x" << format("%08X", Ctx.DomMul[i])
					<< " add=0x" << format("%08X", Ctx.DomAdd[i])
					<< " rot=" << (unsigned)Ctx.DomRot[i]
					<< " x2=0x" << format("%08X", Ctx.DomXor2[i]) << "\n";
			}

			// Build expected REAL cases for this dispatcher group
			std::vector<ExpectedCase> Expected;
			std::set<uint32_t> ExpectedKeys;
			unsigned GroupCount = 0;

			for (BasicBlock* BB : Ctx.FlattenedBlocks) {
				if (Ctx.DispatcherGroups.lookup(BB) != i)
					continue;
				++GroupCount;

				ExpectedCase E = expectedKeyFor(BB, i);

				// sanity: your stored group should match router group computed from Enc
				if (E.RouterGrp != i) {
					OS << "  [WARN] group mismatch for " << BB->getName()
						<< ": DispatcherGroups=" << i << " but router(Enc)->" << E.RouterGrp
						<< " (raw=0x" << format("%08X", E.Raw)
						<< " enc=0x" << format("%08X", E.Enc) << ")\n";
				}

				if (!ExpectedKeys.insert(E.Key).second) {
					OS << "  [WARN] key collision inside group " << i
						<< ": key=0x" << format("%08X", E.Key)
						<< " for block " << BB->getName() << "\n";
				}

				Expected.push_back(E);
			}

			// Sort expected by key to make reading easier
			llvm::sort(Expected, [](const ExpectedCase& A, const ExpectedCase& B) {
				return A.Key < B.Key;
				});

			OS << "Expected real blocks in group: " << GroupCount << "\n";
			OS << "Expected real case-keys: " << Expected.size() << "\n";

			// Print expected (real) table
			for (const auto& E : Expected) {
				OS << "  expect key=0x" << format("%08X", E.Key)
					<< " -> " << E.BB->getName()
					<< " (raw=0x" << format("%08X", E.Raw)
					<< " enc=0x" << format("%08X", E.Enc) << ")\n";
			}

			// Scan actual switch cases
			std::set<uint32_t> SeenKeys;
			unsigned RealHits = 0;
			unsigned FakeHits = 0;
			unsigned WrongSucc = 0;

			OS << "Cases:\n";
			for (auto Case : Sw->cases()) {
				uint32_t K = (uint32_t)Case.getCaseValue()->getZExtValue();
				BasicBlock* Tgt = Case.getCaseSuccessor();

				const ExpectedCase* Match = findExpectedByKey(Expected, K);

				OS << "  case key=0x" << format("%08X", K)
					<< " -> " << Tgt->getName();

				if (Match) {
					++RealHits;
					if (Tgt != Match->BB) {
						++WrongSucc;
						OS << "  [REAL KEY BUT WRONG SUCC: expected " << Match->BB->getName() << "]";
					}
					else {
						OS << "  [real]";
					}
					OS << " (raw=0x" << format("%08X", Match->Raw)
						<< " enc=0x" << format("%08X", Match->Enc) << ")";
				}
				else {
					++FakeHits;
					OS << "  [fake/unknown]";
				}

				if (!SeenKeys.insert(K).second) {
					OS << "  [WARN duplicate case value in switch]";
				}
				OS << "\n";
			}

			// Missing expected cases?
			unsigned Missing = 0;
			for (const auto& E : Expected) {
				if (!SeenKeys.count(E.Key)) {
					++Missing;
					OS << "  [ERROR] missing REAL case for " << E.BB->getName()
						<< ": key=0x" << format("%08X", E.Key)
						<< " raw=0x" << format("%08X", E.Raw)
						<< " enc=0x" << format("%08X", E.Enc) << "\n";
				}
			}

			OS << "Summary: realPresent=" << RealHits << "/" << Expected.size()
				<< " missing=" << Missing
				<< " wrongSucc=" << WrongSucc
				<< " extraCases=" << (Sw->getNumCases() - RealHits) << "\n";
		}

		// Keep your cross-dispatcher transitions section, but make it key-aware
		OS << "\n=== Cross-Dispatcher Transitions (router group view) ===\n";
		for (BasicBlock* BB : Ctx.FlattenedBlocks) {
			Instruction* TI = BB->getTerminator();
			if (!TI || isa<ReturnInst>(TI) || isa<UnreachableInst>(TI))
				continue;

			unsigned BBGrp = Ctx.DispatcherGroups.lookup(BB);

			for (unsigned s = 0; s < TI->getNumSuccessors(); ++s) {
				BasicBlock* Succ = TI->getSuccessor(s);
				if (!Ctx.BlockIDs.count(Succ))
					continue;

				ExpectedCase ES = expectedKeyFor(Succ, /*DispIdx=*/Ctx.DispatcherGroups.lookup(Succ));
				unsigned SuccGrp = Ctx.DispatcherGroups.lookup(Succ);

				if (BBGrp != SuccGrp) {
					OS << BB->getName() << " (grp " << BBGrp << ") -> " << Succ->getName()
						<< " (grp " << SuccGrp << ")"
						<< " raw=0x" << format("%08X", ES.Raw)
						<< " enc=0x" << format("%08X", ES.Enc)
						<< " routerGrp=" << ES.RouterGrp
						<< "\n";
				}
			}
		}

	}



	bool FlaImpl::verifyFlatteningIR(Function& F, FunctionObfContext& Ctx,
		raw_ostream& OS) {

		bool Broken = false;

		OS << "[flattening] Verifying function: " << F.getName() << "\n";

		// ------------------------------------------------------------------
		// 1. LLVM IR verifier (dominance, SSA, CFG)
		// ------------------------------------------------------------------
		if (verifyFunction(F, &OS)) {
			OS << "[flattening] LLVM verifyFunction failed\n";
			Broken = true;
		}

		// ------------------------------------------------------------------
		// 2. Dispatcher sanity
		// ------------------------------------------------------------------
		if (Ctx.Dispatchers.empty()) {
			OS << "[flattening] No dispatchers created\n";
			return true;
		}

		for (BasicBlock* Disp : Ctx.Dispatchers) {
			if (!Disp) {
				OS << "[flattening] Null dispatcher pointer\n";
				Broken = true;
				continue;
			}

			if (!Disp->getTerminator()) {
				OS << "[flattening] Dispatcher has no terminator: " << Disp->getName()
					<< "\n";
				Broken = true;
				continue;
			}

			if (!isa<BranchInst>(Disp->getTerminator()) &&
				!isa<SwitchInst>(Disp->getTerminator())) {
				OS << "[flattening] Dispatcher terminator is not branch/switch: "
					<< Disp->getName() << "\n";
				Broken = true;
			}
		}

		// ------------------------------------------------------------------
		// 3. Flattened blocks checks
		// ------------------------------------------------------------------
		for (BasicBlock* BB : Ctx.FlattenedBlocks) {
			if (!BB) {
				OS << "[flattening] Null flattened block pointer\n";
				Broken = true;
				continue;
			}

			Instruction* TI = BB->getTerminator();
			if (!TI) {
				OS << "[flattening] Block has no terminator: " << BB->getName() << "\n";
				Broken = true;
				continue;
			}

			// No fallthrough allowed
			if (TI->getNumSuccessors() == 0 && !isa<ReturnInst>(TI) &&
				!isa<UnreachableInst>(TI)) {
				OS << "[flattening] Block ends without control transfer: "
					<< BB->getName() << "\n";
				Broken = true;
			}

			// Must not branch directly to another flattened block
			for (unsigned i = 0; i < TI->getNumSuccessors(); ++i) {
				BasicBlock* Succ = TI->getSuccessor(i);
				if (llvm::is_contained(Ctx.FlattenedBlocks, Succ)) {
					OS << "[flattening] Direct flattened->flattened edge: " << BB->getName()
						<< " -> " << Succ->getName() << "\n";
					Broken = true;
				}
			}
		}

		// ------------------------------------------------------------------
		// 4. Block ID coverage
		// ------------------------------------------------------------------
		for (BasicBlock* BB : Ctx.FlattenedBlocks) {
			if (!Ctx.BlockIDs.count(BB)) {
				OS << "[flattening] Missing BlockID for block: " << BB->getName() << "\n";
				Broken = true;
			}
		}

		// ------------------------------------------------------------------
		// 5. Dispatcher group consistency
		// ------------------------------------------------------------------
		for (BasicBlock* BB : Ctx.FlattenedBlocks) {
			if (!Ctx.DispatcherGroups.count(BB)) {
				OS << "[flattening] Missing dispatcher group for block: " << BB->getName()
					<< "\n";
				Broken = true;
				continue;
			}

			unsigned G = Ctx.DispatcherGroups.lookup(BB);
			if (G >= Ctx.Dispatchers.size()) {
				OS << "[flattening] Invalid dispatcher group index " << G << " for block "
					<< BB->getName() << "\n";
				Broken = true;
			}
		}

		// ------------------------------------------------------------------
		// 6. State variable sanity
		// ------------------------------------------------------------------
		if (!Ctx.StatVar) {
			OS << "[flattening] State variable not initialized\n";
			Broken = true;
		}
		else if (!Ctx.StatVar->getType()->isPointerTy()) {
			OS << "[flattening] State variable has invalid type\n";
			Broken = true;
		}

		if (Broken) {
			OS << "[flattening] Verification FAILED\n";
			return true;
		}

		OS << "[flattening] Verification OK\n";

		return false;
	}



#endif



	void FlaImpl::createRouter(Function& F, FunctionObfContext& Ctx) {
		LLVMContext& LC = F.getContext();
		Ctx.Router = BasicBlock::Create(LC, "fla.dispatch.router", &F);
	}

	// ============================================================================
	// Flattening Logic
	// ============================================================================

	bool FlaImpl::prepareFlattening(FlaCtx& PCtx) {

		Function& F = PCtx.F;
		FunctionObfContext& Ctx = PCtx.FOC;

		Ctx.StatVar = createStateVariable(F);
		Ctx.NumDispatchers = computeNumDispatchers(Ctx);
		// State encoding keys
		Ctx.StateXorKey = PCtx.KeysRng.u32();
		Ctx.StateAddKey = PCtx.KeysRng.u32();
		// Router hash keys (pick non-trivial values)
		Ctx.RouterXorKey = PCtx.KeysRng.u32();
		Ctx.RouterMulKey = (PCtx.KeysRng.u32() | 1u); // make it odd
		Ctx.RouterAddKey = PCtx.KeysRng.u32();
		createDispatchers(F, Ctx);
		// Collect flattened blocks (exclude entry, dispatchers, EH pads, EH regions)
		Ctx.FlattenedBlocks.clear();
		for (BasicBlock& BB : F) {
			if (&BB == &F.getEntryBlock())
				continue;
			if (llvm::is_contained(Ctx.Dispatchers, &BB))
				continue;
			// Exclude ALL EH pads (landingpad, catchswitch, catchpad, cleanuppad)
			// and blocks that are reachable only through EH pads (EH regions).
			// These blocks are left untouched; their edges into flattened blocks
			// work naturally since the flattened block will set state and jump
			// to the router at its end.
			if (BB.isEHPad() || llvm::obf::isInEHRegion(&BB))
				continue;
			Ctx.FlattenedBlocks.push_back(&BB);
		}
		// Create router AFTER collection so it won't be included
		createRouter(F, Ctx);

		return true;
	}



	uint32_t FlaImpl::pickFakeEncodedState(FlaCtx& PCtx, FunctionObfContext& Ctx,
		std::initializer_list<uint32_t> Avoid) {
		std::set<uint32_t> AvoidSet(Avoid.begin(), Avoid.end());
		if (Ctx.FlattenedBlocks.empty())
			return 0xA5A5A5A5u;

		for (unsigned t = 0; t < 16; ++t) {
			auto* BB = Ctx.FlattenedBlocks[PCtx.FakeRng.range((uint32_t)Ctx.FlattenedBlocks.size())];
			uint32_t Raw = Ctx.BlockIDs.lookup(BB);
			uint32_t Enc = encodeStateConst(Raw, Ctx);
			if (!AvoidSet.count(Enc))
				return Enc;
		}

		uint32_t Rnd = PCtx.FakeRng.u32();
		if (AvoidSet.count(Rnd)) Rnd ^= 0x3C3C3C3Cu;
		return Rnd;
	}

	Value* FlaImpl::applyFakeTransition(IRBuilder<>& B, FlaCtx& PCtx, FunctionObfContext& Ctx,
		Value* RealNext, std::initializer_list<uint32_t> AvoidEnc) {
		if (!PCtx.Cfg.FakeTransitions)
			return RealNext;

		uint32_t FakeEnc = pickFakeEncodedState(PCtx, Ctx, AvoidEnc);
		Value* FakeV = PCtx.Opaque.opaqueI32Const(B, FakeEnc);
		Value* HF = PCtx.Opaque.hardFalse(B);
		return B.CreateSelect(HF, FakeV, RealNext, "fla.next.fake");
	}



	uint32_t FlaImpl::routerMixConst(uint32_t Enc, const FunctionObfContext& Ctx) {
		uint32_t x = Enc ^ Ctx.RouterXorKey;
		x *= Ctx.RouterMulKey;
		x += Ctx.RouterAddKey;
		return x;
	}

	Value* FlaImpl::routerMixIR(IRBuilder<>& B, Value* Enc, FunctionObfContext& Ctx) {
		Type* I32Ty = Type::getInt32Ty(B.getContext());
		Value* X = B.CreateXor(Enc, ConstantInt::get(I32Ty, Ctx.RouterXorKey));
		X = B.CreateMul(X, ConstantInt::get(I32Ty, Ctx.RouterMulKey));
		X = B.CreateAdd(X, ConstantInt::get(I32Ty, Ctx.RouterAddKey));
		return X;
	}



	void FlaImpl::assignDispatcherGroupsFromEncodedState(FunctionObfContext& Ctx) {
		unsigned N = Ctx.Dispatchers.size();
		assert(N > 0);
		Ctx.DispatcherGroups.clear();
		Ctx.BlockToDispatcher.clear();
		Ctx.StateToDispatcher.clear(); // optional, but keeps your debug working
		for (BasicBlock* BB : Ctx.FlattenedBlocks) {
			uint32_t Raw = Ctx.BlockIDs.lookup(BB);
			uint32_t Enc = encodeStateConst(Raw, Ctx);
			unsigned grp = routerMixConst(Enc, Ctx) % N;
			Ctx.DispatcherGroups[BB] = grp;
			Ctx.BlockToDispatcher[BB] = Ctx.Dispatchers[grp];
			Ctx.StateToDispatcher[Raw] = Ctx.Dispatchers[grp]; // optional
		}
	}

	void FlaImpl::buildRouter(Function& F, FunctionObfContext& Ctx, FlaCtx& PCtx) {
		assert(Ctx.Router && "Router not created");
		LLVMContext& LC = F.getContext();
		Type* I32Ty = Type::getInt32Ty(LC);
		IRBuilder<> B(Ctx.Router);


		Value* EncState = loadState(B, PCtx, Ctx);

		Value* Mix = routerMixIR(B, EncState, Ctx);
		Value* Grp = nullptr;
		if (Ctx.Dispatchers.size() == 1) {
			Grp = ConstantInt::get(I32Ty, 0);
		}
		else {
			Grp = B.CreateURem(Mix,
				ConstantInt::get(I32Ty, (uint32_t)Ctx.Dispatchers.size()),
				"fla.grp");
		}

		BasicBlock* ExitTrampoline = getOrCreateExitTrampline(F);
		auto* Sw = B.CreateSwitch(Grp, ExitTrampoline, Ctx.Dispatchers.size());
		for (unsigned i = 0; i < Ctx.Dispatchers.size(); ++i)
			Sw->addCase(cast<ConstantInt>(ConstantInt::get(I32Ty, i)), Ctx.Dispatchers[i]);
	}


	void FlaImpl::buildDispatcherSwitchesEncoded(Function& F, FunctionObfContext& Ctx, FlaCtx& PCtx) {
		LLVMContext& LC = F.getContext();
		Type* I32 = Type::getInt32Ty(LC);
		BasicBlock* ExitTrampoline = getOrCreateExitTrampline(F);
		unsigned N = (unsigned)Ctx.Dispatchers.size();

		initPerDispatcherDomains(PCtx, Ctx);

		for (unsigned i = 0; i < Ctx.Dispatchers.size(); ++i) {
			BasicBlock* Disp = Ctx.Dispatchers[i];
			IRBuilder<> B(Disp);

			Value* EncState = loadState(B, PCtx, Ctx); // <<<<<< no direct load from StatVar

			Value* SwitchKey = EncState;
			if (PCtx.Cfg.PerDispatcherDomain) {
				SwitchKey = dispatcherDomainIR(B, EncState, i, Ctx);
			}

			// Count real cases for this dispatcher group
			unsigned RealCases = 0;
			std::vector<BasicBlock*> GroupBlocks;
			for (BasicBlock* BB : Ctx.FlattenedBlocks) {
				if (Ctx.DispatcherGroups.lookup(BB) == i) {
					++RealCases;
					GroupBlocks.push_back(BB);
				}
			}

			unsigned Extra = (PCtx.Cfg.FakeTransitions ? PCtx.Cfg.FakeCases : 0);
			auto* Sw = B.CreateSwitch(SwitchKey, ExitTrampoline, RealCases + Extra);

			std::set<uint32_t> UsedKeys;

			// Real cases
			for (BasicBlock* BB : Ctx.FlattenedBlocks) {
				if (Ctx.DispatcherGroups.lookup(BB) != i)
					continue;

				uint32_t Raw = Ctx.BlockIDs.lookup(BB);
				uint32_t Enc = encodeStateConst(Raw, Ctx);

				uint32_t Key = PCtx.Cfg.PerDispatcherDomain ? dispatcherDomainConst(Enc, i, Ctx) : Enc;
				UsedKeys.insert(Key);

				Sw->addCase(cast<ConstantInt>(ConstantInt::get(I32, Key)), BB);
			}

			// Fake cases: choose EncFake that routes to this dispatcher via routerMixConst, then domain-transform it
			if (Extra && !GroupBlocks.empty() && N) {
				for (unsigned k = 0; k < Extra; ++k) {
					uint32_t EncFake = 0;
					bool Found = false;

					for (unsigned tries = 0; tries < 512; ++tries) {
						uint32_t Cnd = PCtx.FakeRng.u32();
						if (Cnd == 0) Cnd = 1;
						if ((routerMixConst(Cnd, Ctx) % N) != i) continue; // router-reachable for dispatcher i
						uint32_t Key = PCtx.Cfg.PerDispatcherDomain ? dispatcherDomainConst(Cnd, i, Ctx) : Cnd;
						if (UsedKeys.count(Key)) continue;
						EncFake = Cnd;
						UsedKeys.insert(Key);
						Found = true;
						break;
					}

					if (!Found) continue;

					BasicBlock* Target = GroupBlocks[PCtx.FakeRng.range((uint32_t)GroupBlocks.size())];
					uint32_t KeyFake = PCtx.Cfg.PerDispatcherDomain ? dispatcherDomainConst(EncFake, i, Ctx) : EncFake;
					Sw->addCase(cast<ConstantInt>(ConstantInt::get(I32, KeyFake)), Target);
				}
			}
		}
	}


	void FlaImpl::rewriteEntryBlockRouter(Function& F, FunctionObfContext& Ctx, FlaCtx& PCtx) {
		BasicBlock& Entry = F.getEntryBlock();
		Instruction* TI = Entry.getTerminator();



		
		// ── Invoke handling (EH-aware flattening) ────────────────────
		// Same trampoline pattern used by rewriteFlattenedBlocksRouter:
		// redirect the invoke's normal dest through a trampoline that
		// sets the dispatch state and jumps to the router.  The unwind
		// edge is left completely intact.
		if (auto* II = dyn_cast<InvokeInst>(TI)) {
			BasicBlock* NormalDest = II->getNormalDest();
			if (!Ctx.BlockIDs.count(NormalDest))
				return;  // normal dest not flattened — leave invoke as-is

			LLVMContext& LC = F.getContext();
			uint32_t NormalID = Ctx.BlockIDs.lookup(NormalDest);
			uint32_t Enc = encodeStateConst(NormalID, Ctx);

			BasicBlock* Tramp = BasicBlock::Create(LC,
				"fla.entry.invoke.tramp", &F);
			IRBuilder<> TB(Tramp);
			Value* Next = PCtx.Opaque.opaqueI32Const(TB, Enc);
			Next = applyFakeTransition(TB, PCtx, Ctx, Next, { Enc });
			storeState(TB, PCtx, Ctx, Next);
			TB.CreateBr(Ctx.Router);

			II->setNormalDest(Tramp);
			return;  // invoke preserved, unwind edge untouched
		}

		auto* Br = dyn_cast<BranchInst>(TI);
		if (!Br) return;  // exotic terminator — skip gracefully

		IRBuilder<> B(TI);
		if (Br->isUnconditional()) {
			BasicBlock* Succ = Br->getSuccessor(0);
			uint32_t Raw = Ctx.BlockIDs.lookup(Succ);
			uint32_t Enc = encodeStateConst(Raw, Ctx);

			Value* Next = PCtx.Opaque.opaqueI32Const(B, Enc);
			Next = applyFakeTransition(B, PCtx, Ctx, Next, { Enc });

			storeState(B, PCtx, Ctx, Next);
		}
		else {
			Value* Cond = Br->getCondition();
			BasicBlock* T = Br->getSuccessor(0);
			BasicBlock* FBB = Br->getSuccessor(1);

			uint32_t EncT = encodeStateConst(Ctx.BlockIDs.lookup(T), Ctx);
			uint32_t EncF = encodeStateConst(Ctx.BlockIDs.lookup(FBB), Ctx);

			Value* VT = PCtx.Opaque.opaqueI32Const(B, EncT);
			Value* VF = PCtx.Opaque.opaqueI32Const(B, EncF);

			Value* Next = B.CreateSelect(Cond, VT, VF, "fla.next.enc");
			Next = applyFakeTransition(B, PCtx, Ctx, Next, { EncT, EncF });

			storeState(B, PCtx, Ctx, Next);
		}

		B.CreateBr(Ctx.Router);
		TI->eraseFromParent();
	}

	void FlaImpl::rewriteFlattenedBlocksRouter(Function& F, FunctionObfContext& Ctx, FlaCtx& PCtx) {
		LLVMContext& LC = F.getContext();
		for (BasicBlock* BB : Ctx.FlattenedBlocks) {
			Instruction* TI = BB->getTerminator();
			if (!TI)
				continue;
			if (isa<ReturnInst>(TI) || isa<UnreachableInst>(TI))
				continue;

			// ── Invoke handling (EH-aware flattening) ────────────────────
			// Create a trampoline block for the invoke's normal continuation.
			// The trampoline sets the dispatch state and jumps to the router.
			// The unwind edge (invoke → landing pad) is left completely intact.
			if (auto* II = dyn_cast<InvokeInst>(TI)) {
				BasicBlock* NormalDest = II->getNormalDest();

				// Only create trampoline if normal dest is a flattened block
				// (has a state ID in the dispatcher).  If it isn't (e.g. an
				// EH-region block filtered out of FlattenedBlocks), leave the
				// invoke completely untouched.
				if (!Ctx.BlockIDs.count(NormalDest))
					continue;

				uint32_t NormalID = Ctx.BlockIDs.lookup(NormalDest);
				uint32_t Enc = encodeStateConst(NormalID, Ctx);

				// Build the trampoline: store encoded state → br %router
				BasicBlock* Tramp = BasicBlock::Create(LC,
					"fla.invoke.tramp", &F);
				IRBuilder<> TB(Tramp);
				Value* Next = PCtx.Opaque.opaqueI32Const(TB, Enc);
				Next = applyFakeTransition(TB, PCtx, Ctx, Next, { Enc });
				storeState(TB, PCtx, Ctx, Next);
				TB.CreateBr(Ctx.Router);

				// Redirect the invoke's normal dest to the trampoline.
				// The invoke instruction itself and its unwind dest are preserved.
				II->setNormalDest(Tramp);
				// Do NOT erase the invoke.
				continue;
			}

			// ── Branch handling (existing logic) ─────────────────────────

			auto* Br = dyn_cast<BranchInst>(TI);
			if (!Br) {
				// Unexpected terminator (e.g. switch that wasn't lowered).
				// Leave as-is rather than asserting — a diagnostic will catch it.
				continue;
			}

			IRBuilder<> B(TI);
			if (Br->isUnconditional()) {
				BasicBlock* Succ = Br->getSuccessor(0);
				uint32_t Enc = encodeStateConst(Ctx.BlockIDs.lookup(Succ), Ctx);
				Value* Next = PCtx.Opaque.opaqueI32Const(B, Enc);
				Next = applyFakeTransition(B, PCtx, Ctx, Next, { Enc });

				storeState(B, PCtx, Ctx, Next);

				B.CreateBr(Ctx.Router);

			}
			else {
				Value* Cond = Br->getCondition();
				BasicBlock* T = Br->getSuccessor(0);
				BasicBlock* FBB = Br->getSuccessor(1);
				uint32_t EncT = encodeStateConst(Ctx.BlockIDs.lookup(T), Ctx);
				uint32_t EncF = encodeStateConst(Ctx.BlockIDs.lookup(FBB), Ctx);

				Value* VT = PCtx.Opaque.opaqueI32Const(B, EncT);
				Value* VF = PCtx.Opaque.opaqueI32Const(B, EncF);

				Value* Next = B.CreateSelect(Cond, VT, VF, "fla.next.enc");
				Next = applyFakeTransition(B, PCtx, Ctx, Next, { EncT, EncF });

				storeState(B, PCtx, Ctx, Next);

				B.CreateBr(Ctx.Router);

			}
			TI->eraseFromParent();
		}
		
	}

	bool FlaImpl::flattenFunction(FlaCtx& PCtx)
	{
		Function& F = PCtx.F;
		FunctionObfContext& Ctx = PCtx.FOC;

		// Strategy: local reg2mem for CFG safety, then mem2reg after flattening.
		llvm::SmallVector<llvm::AllocaInst*, 64> DemotedAllocas;
		llvm::obf::demoteForCFGChange(F, DemotedAllocas);

		if (!prepareFlattening(PCtx))
			return false;
		assignBlockIDs(PCtx);
		assignDispatcherGroupsFromEncodedState(Ctx);
		rewriteEntryBlockRouter(F, Ctx, PCtx);
		buildRouter(F, Ctx, PCtx);
		buildDispatcherSwitchesEncoded(F, Ctx, PCtx);
		rewriteFlattenedBlocksRouter(F, Ctx, PCtx);

		// Restore SSA to avoid leaving reg2mem artifacts and reduce detectability.
		llvm::obf::promoteDemotedAllocas(F, DemotedAllocas);

#ifndef NDEBUG
		insertStateValidation(F, PCtx, Ctx);
		insertDispatcherLogging(F, PCtx, Ctx);

		dumpStateTransitions(F, Ctx, errs());
		verifyDispatcherCoverage(F, PCtx, Ctx, errs());
		if (verifyFlatteningIR(F, Ctx, errs())) {
			F.dump();
			llvm_unreachable("Invalid IR produced by flattening");
		}
#endif
		return true;
	}



	// ============================================================================
	// Configuration
	// ============================================================================

	FlatteningConfig FlaImpl::getFlatteningConfig(Function& F, FunctionAnalysisManager& AM)
	{
		const ObfuscationConfig& obfConfig = getObfConfig(F, AM);
		auto passConfig = obfConfig.getPassConfig("flattening");


		if (!passConfig.has_value()) {
			FlatteningConfig cfg;
			cfg.enable = false;
			return cfg;
		}

		FlatteningConfig cfg = FlatteningConfig::fromPassConfig(*passConfig);

		if (!cfg.validate()) {
			if (ObfVerbose) {
				errs() << "Flattening: Invalid configuration for function " << F.getName()
					<< ", disabling pass\n";
			}
			cfg.enable = false;
		}

		return cfg;
	}

} // anonymous namespace

// ============================================================================
// Pass Implementation
// ============================================================================

PreservedAnalyses FlatteningPass::run(Function& F, FunctionAnalysisManager& AM) {
	if (F.isDeclaration())
		return PreservedAnalyses::all();

	FlaCtx Ctx(F, AM);

	if (!Ctx.Cfg.enable)
		return PreservedAnalyses::all();

	std::string Str;
	raw_string_ostream RejectReason(Str);
	if (!FlaImpl::isFlattenEligible(F, Ctx.FOC, Ctx.Cfg, &RejectReason)) {
		LLVM_DEBUG(dbgs() << "Flattening skipped: " << RejectReason.str() << "\n");
		llvm::obf::recordObfPassSkip(Ctx.FOC, "flattening",
			Str.empty() ? "ineligible" : Str);
		return PreservedAnalyses::all();
	}


	PreservedAnalyses LowerPA = PreservedAnalyses::all();
	bool NeedLower = llvm::any_of(F, [](BasicBlock& BB) {
		return isa<SwitchInst>(BB.getTerminator());
		});

	if (NeedLower) {
		LowerSwitchPass lowerSwitch;
		LowerPA = lowerSwitch.run(F, AM);
	}

	bool Success = FlaImpl::flattenFunction(Ctx);

	if (Success) {
		if (ObfVerbose)
			errs() << "Flattening Success on: " << F.getName() << "\n";
		++Flattened;
		return PreservedAnalyses::none();
	}

	llvm::obf::recordObfPassSkip(Ctx.FOC, "flattening", "flatten_failed");
	return LowerPA;
}
