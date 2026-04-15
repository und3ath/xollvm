#include "llvm/Transforms/Obfuscator/VirtualCall.h"

#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/MD5.h"

#include "llvm/Transforms/Obfuscator/PassCtx.h"
#include "llvm/Transforms/Obfuscator/Utils.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/FunctionObfContextAnalysis.h"

using namespace llvm;

#define DEBUG_TYPE "vcall"

STATISTIC(VirtualizedCalls, "Number of virtualized calls");

namespace {

	static constexpr unsigned kTableSize = 8;
	static_assert((kTableSize& (kTableSize - 1)) == 0, "kTableSize must be power of two");


	// ----------------------------------------------------------------------------
	// Hash-based naming helpers
	// ----------------------------------------------------------------------------
	static std::string md5Hex(StringRef S) {
		llvm::MD5 H;
		H.update(S);
		llvm::MD5::MD5Result R;
		H.final(R);
		SmallString<32> Out;
		llvm::MD5::stringifyResult(R, Out);
		return Out.str().str();
		
	}
	
	static std::string opaqueVTableName(Function * Callee, uint32_t Salt) {
		std::string Sig;
		raw_string_ostream OS(Sig);
		Callee->getFunctionType()->print(OS);
		OS << "|" << Callee->getName() << "|" << Salt;
		OS.flush();
		return (Twine(".vt.") + md5Hex(Sig)).str();
		
	}
	
	// ----------------------------------------------------------------------------
	// Optional merged-vtable mode (opt-in): one vtable per function type: [N x i8*]
	// ----------------------------------------------------------------------------
	struct MergedVTableInfo {
		GlobalVariable * GV = nullptr; // [N x i8*]
		unsigned Size = 0;
		// stable base offsets per callee
		DenseMap<Function*, unsigned> BaseByCallee;
		
	};
	




	struct VCallCtx;
	struct VCallImpl final {
		// ----------------------------------------------------------------------------
		// Config
		// ----------------------------------------------------------------------------
		static VirtualCallConfig getVCallConfig(Function& F, FunctionAnalysisManager& AM);

		// ----------------------------------------------------------------------------
		// Helpers: thunks + vtable
		// ----------------------------------------------------------------------------
		static bool canVirtualize(CallInst* CI);
		static Function* getOrCreateThunk(Module& M, Function* Callee, unsigned ThunkIdx);
		static Function* getOrCreateDecoyThunk(Module& M, Function* Callee, unsigned ThunkIdx);
		static uint32_t getOrCreateRealSlot(Module& M, Function* Callee, llvm::obf::Rng& TableRng);
		static GlobalVariable* getOrCreateVTable(Module& M, Function* Callee, llvm::obf::Rng& TableRng, uint32_t& RealSlotOut);

		// merged mode
		static MergedVTableInfo & getMergedInfo(Module & M);
		static GlobalVariable * getOrCreateMergedVTable(Module & M, Function * Callee, VCallCtx & Ctx, uint32_t & BaseOut, uint32_t & RealSlotOut);

		// ----------------------------------------------------------------------------
		// Index that always selects real slot at runtime, but doesn't fold
		// ----------------------------------------------------------------------------
		static Value* makeRuntimeZeroDelta(IRBuilder<>& B, AllocaInst* VolSlot, llvm::obf::Rng& IndexRng);
		static Value* obfuscateIndexPerCallsite(IRBuilder<>& B, Value* IdxI32, VCallCtx& Ctx);

		// ----------------------------------------------------------------------------
		// Virtualize one callsite
		// ----------------------------------------------------------------------------
		static void virtualizeCall(CallInst* CI, VCallCtx& Ctx);

		// ----------------------------------------------------------------------------
		// Main pass logic
		// ----------------------------------------------------------------------------
		static bool runVirtualCall(VCallCtx& Ctx, int Probability, unsigned MaxSites);
	};

	// ----------------------------------------------------------------------------
	// Config
	// ----------------------------------------------------------------------------
	VirtualCallConfig VCallImpl::getVCallConfig(Function& F, FunctionAnalysisManager& AM) {
		const ObfuscationConfig obfConfig = getObfConfig(F, AM);
		auto passConfig = obfConfig.getPassConfig("vcall");
		if (!passConfig.has_value()) {
			VirtualCallConfig cfg;
			cfg.enable = false;
			return cfg;
		}

		VirtualCallConfig cfg = VirtualCallConfig::fromPassConfig(*passConfig);
		if (!cfg.validate()) {
			if (ObfVerbose) {
				errs() << "VCall: Invalid configuration for function " << F.getName()
					<< ", disabling pass\n";
			}
			cfg.enable = false;
		}
		return cfg;
	}

	// ----------------------------------------------------------------------------
	// Context
	// ----------------------------------------------------------------------------
	struct VCallCtx : llvm::obf::FuncPassCtx {
		VirtualCallConfig Cfg;
		FunctionObfContext& FOC;

		llvm::obf::Rng SelectRng; // choose callsites
		llvm::obf::Rng PickRng;   // shuffle candidate order (stable)
		llvm::obf::Rng TableRng;  // vtable layout + real slot
		llvm::obf::Rng IndexRng;  // volatile-delta masking salt

		llvm::obf::Rng NameRng;   // vtable naming salt
		llvm::obf::Rng DecoyRng;  // decoy selection
		llvm::obf::Rng SiteRng;   // per callsite index shaping

		AllocaInst* VolSlot = nullptr; // used for volatile loads; cancels to 0

		VCallCtx(Function& F, FunctionAnalysisManager& AM)
			: FuncPassCtx(F, AM, "vcall"),
			Cfg(VCallImpl::getVCallConfig(F, AM)),
			FOC(*AM.getResult<FunctionObfContextAnalysis>(F)),
			SelectRng(R.fork("select")),
			PickRng(R.fork("pick")),
			TableRng(R.fork("table")),
			IndexRng(R.fork("index")),
			NameRng(R.fork("names")),
			DecoyRng(R.fork("decoys")),
			SiteRng(R.fork("site")) {

			// Create one volatile slot per function to generate "unknown but runtime-zero" deltas.
			LLVMContext& C = F.getContext();
			IRBuilder<> B(&*F.getEntryBlock().getFirstInsertionPt());

			VolSlot = B.CreateAlloca(Type::getInt32Ty(C), nullptr, "vcall.slot");

			VolSlot->setAlignment(Align(4));
			Type* I32 = Type::getInt32Ty(C);
			Type* I64 = Type::getInt64Ty(C);
			Value* P2I = B.CreatePtrToInt(VolSlot, I64, "vcall.slot.p2i");
			Value* P32 = B.CreateTrunc(P2I, I32, "vcall.slot.p2i32");
			uint32_t K = IndexRng.u32();
			Value* Init = B.CreateXor(P32, ConstantInt::get(I32, K), "vcall.slot.init");


			auto* St = B.CreateStore(Init, VolSlot);
			St->setVolatile(true);
		}
	};

	// ----------------------------------------------------------------------------
	// Helpers: thunks + vtable
	// ----------------------------------------------------------------------------
	bool VCallImpl::canVirtualize(CallInst* CI) {
		if (!CI)
			return false;

		Function* Callee = CI->getCalledFunction();
		if (!Callee)
			return false; // no bitcasts / no function pointers

		if (CI->isMustTailCall())
			return false;

		if (Callee->isDeclaration() || Callee->isIntrinsic())
			return false;

		if (Callee->getName().starts_with("llvm."))
			return false;

		// Don't virtualize our own helpers.
		if (Callee->getName().starts_with("__decrypt_string"))
			return false;

		// Safety: skip varargs (thunks would need to forward varargs carefully)
		if (Callee->isVarArg())
			return false;

		return true;
	}

	Function* VCallImpl::getOrCreateThunk(Module& M, Function* Callee, unsigned ThunkIdx) {
		// Name includes idx so each slot has distinct function pointer (even if same semantics).
		std::string Name =
			(Twine("__vcall_thunk.") + Callee->getName() + "." + Twine(ThunkIdx)).str();

		if (Function* Existing = M.getFunction(Name))
			return Existing;

		FunctionType* FTy = Callee->getFunctionType();
		Function* Thunk =
			Function::Create(FTy, GlobalValue::PrivateLinkage, Name, M);

		// Make it unattractive to inline/merge
		Thunk->addFnAttr(Attribute::NoInline);
		Thunk->addFnAttr(Attribute::Cold);
		Thunk->addFnAttr(Attribute::NoUnwind);

		// Match calling convention to avoid ABI surprises
		Thunk->setCallingConv(Callee->getCallingConv());

		// Build body: forward args to Callee
		LLVMContext& C = M.getContext();
		BasicBlock* Entry = BasicBlock::Create(C, "entry", Thunk);
		IRBuilder<> B(Entry);

		SmallVector<Value*, 8> Args;
		Args.reserve(Thunk->arg_size());
		for (Argument& A : Thunk->args())
			Args.push_back(&A);

		CallInst* Call = B.CreateCall(FTy, Callee, Args);
		Call->setCallingConv(Callee->getCallingConv());

		// Return appropriately
		if (FTy->getReturnType()->isVoidTy()) {
			B.CreateRetVoid();
		}
		else {
			B.CreateRet(Call);
		}

		return Thunk;
	}

	Function * VCallImpl::getOrCreateDecoyThunk(Module & M, Function * Callee, unsigned ThunkIdx) {
		// Distinct decoy name to discourage merging with normal thunks.
		std::string Name =
		(Twine("__vcall_decoy.") + Callee->getName() + "." + Twine(ThunkIdx)).str();
		
		if (Function* Existing = M.getFunction(Name))
			return Existing;
		
		FunctionType * FTy = Callee->getFunctionType();
		Function * Thunk = Function::Create(FTy, GlobalValue::PrivateLinkage, Name, M);
		
		Thunk->addFnAttr(Attribute::NoInline);
		Thunk->addFnAttr(Attribute::Cold);
		Thunk->addFnAttr(Attribute::NoUnwind);
		Thunk->setCallingConv(Callee->getCallingConv());
		
		LLVMContext & C = M.getContext();
		BasicBlock * Entry = BasicBlock::Create(C, "entry", Thunk);
		IRBuilder<> B(Entry);
		
		// Safe stub: return neutral value / do nothing.
		Type * RTy = FTy->getReturnType();
		if (RTy->isVoidTy()) {
			B.CreateRetVoid();
		}
		else if (RTy->isIntegerTy()) {
			B.CreateRet(ConstantInt::get(RTy, 0));
		}
		else if (RTy->isPointerTy()) {
			B.CreateRet(ConstantPointerNull::get(cast<PointerType>(RTy)));
		}
		else if (RTy->isFloatTy() || RTy->isDoubleTy()) {
			B.CreateRet(ConstantFP::get(RTy, 0.0));
		}
		else {
			B.CreateRet(UndefValue::get(RTy));
			
		}
		
		return Thunk;	
	}
	
	uint32_t VCallImpl::getOrCreateRealSlot(Module& M, Function* Callee, llvm::obf::Rng& TableRng) {
		std::string SlotName = (Twine(".vcall.slot.") + Callee->getName()).str();

		if (GlobalVariable* G = M.getGlobalVariable(SlotName, /*AllowInternal=*/true)) {
			if (auto* CI = dyn_cast<ConstantInt>(G->getInitializer()))
				return (uint32_t)CI->getZExtValue();
		}

		// Derive slot deterministically per-callee.
		// Forking by callee name makes it stable independent of callsite visitation order.
		llvm::obf::Rng Local = TableRng.fork(Callee->getName());
		uint32_t Slot = Local.range(kTableSize);

		LLVMContext& C = M.getContext();
		auto* I32 = Type::getInt32Ty(C);

		auto* SlotGV = new GlobalVariable(
			M, I32,
			/*isConstant=*/true,
			GlobalValue::PrivateLinkage,
			ConstantInt::get(I32, Slot),
			SlotName);

		SlotGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
		SlotGV->setAlignment(Align(4));

		return Slot;
	}

	GlobalVariable* VCallImpl::getOrCreateVTable(Module& M, Function* Callee,
		llvm::obf::Rng& TableRng,
		uint32_t& RealSlotOut) {
		// Opaque name if enabled (else keep old name for compatibility)
		std::string Name = (Twine(".vtable.") + Callee->getName()).str();

		// Always resolve real slot deterministically (even if vtable already exists).
		RealSlotOut = getOrCreateRealSlot(M, Callee, TableRng);

		if (GlobalVariable* Existing = M.getGlobalVariable(Name, /*AllowInternal=*/true))
			return Existing;

		auto* FuncPtrTy = cast<PointerType>(Callee->getType());
		auto* TableTy = ArrayType::get(FuncPtrTy, kTableSize);

		SmallVector<Constant*, kTableSize> Entries;
		Entries.reserve(kTableSize);

		for (unsigned i = 0; i < kTableSize; ++i) {
			if (i == RealSlotOut) {
				Entries.push_back(Callee);
			}
			else {
				
				// Enhanced: optionally create decoy entries for some slots.
				// (Never selected at runtime due to index construction.)
				Function * Thunk = nullptr;
				// NOTE: this function doesn't have Ctx; decoy selection is done by caller in merged mode.
				// In non-merged mode, keep stable behavior by using normal thunks here.
				Thunk = getOrCreateThunk(M, Callee, i);

				// Ensure type matches
				if (Thunk->getType() != Callee->getType()) {
					// Bitcast defensively if needed (rare)
					Entries.push_back(ConstantExpr::getBitCast(Thunk, Callee->getType()));
				}
				else {
					Entries.push_back(Thunk);
				}
			}
		}

		Constant* InitVal = ConstantArray::get(TableTy, Entries);

		auto* VTable = new GlobalVariable(
			M, TableTy,
			/*isConstant=*/true,
			GlobalValue::PrivateLinkage,
			InitVal,
			Name);

		VTable->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
		VTable->setAlignment(M.getDataLayout().getABITypeAlign(FuncPtrTy));

		return VTable;
	}


	// ----------------------------------------------------------------------------
	// merged mode helpers
	// ----------------------------------------------------------------------------
	static const char* kMergedMDKey = "obf.vcall.merged.info";

	MergedVTableInfo& VCallImpl::getMergedInfo(Module& M) {
		// Store in Module metadata via a static map keyed by Module* (simple & safe in-pass lifetime).
		// This pass runs per-function, but within one opt invocation this is stable.
		static DenseMap<Module*, MergedVTableInfo> Map;
		return Map[&M];
	}

	GlobalVariable* VCallImpl::getOrCreateMergedVTable(Module& M, Function* Callee, VCallCtx& Ctx,
		uint32_t& BaseOut, uint32_t& RealSlotOut) {

		LLVMContext& C = M.getContext();
		Type* PtrTy = PointerType::get(C, 0); // opaque ptr (AS0)
		FunctionType* FTy = Callee->getFunctionType();

		auto& Info = getMergedInfo(M);

		// Name per signature
		std::string Name;
		if (Ctx.Cfg.opaqueVTableNames) {
			uint32_t Salt = Ctx.NameRng.u32();
			Name = opaqueVTableName(Callee, Salt);
		}
		else {
			std::string Sig;
			raw_string_ostream OS(Sig);
			FTy->print(OS);
			OS.flush();
			Name = (Twine(".vtable.merged.") + md5Hex(Sig)).str();
		}

		// Create or reuse GV
		if (!Info.GV) {
			// IMPORTANT: start with kTableSize nulls so BaseOut remains aligned to kTableSize
			ArrayType* AT = ArrayType::get(PtrTy, kTableSize);

			SmallVector<Constant*, kTableSize> Z;
			Z.reserve(kTableSize);
			for (unsigned i = 0; i < kTableSize; ++i)
				Z.push_back(Constant::getNullValue(PtrTy));

			Constant* Init = ConstantArray::get(AT, Z);
			Info.GV = new GlobalVariable(M, AT, /*isConstant=*/true, GlobalValue::PrivateLinkage, Init, Name);
			Info.GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
			Info.GV->setAlignment(Align(8));
			Info.Size = kTableSize;
		}

		// If already placed, reuse base and real slot
		if (auto It = Info.BaseByCallee.find(Callee); It != Info.BaseByCallee.end()) {
			BaseOut = It->second;
			RealSlotOut = getOrCreateRealSlot(M, Callee, Ctx.TableRng);
			return Info.GV;
		}

		RealSlotOut = getOrCreateRealSlot(M, Callee, Ctx.TableRng);

		// Decide decoy count for this callee segment
		unsigned DecoyCount = 0;
		if (Ctx.Cfg.addDecoyEntries) {
			unsigned MaxD = std::min<unsigned>(kTableSize - 1, Ctx.Cfg.decoyMax);
			unsigned MinD = std::min<unsigned>(MaxD, Ctx.Cfg.decoyMin);
			if (MaxD > 0)
				DecoyCount = MinD + (unsigned)Ctx.DecoyRng.range((uint32_t)(MaxD - MinD + 1));
		}

		// Build segment of exactly kTableSize entries of ptr:
		SmallVector<Constant*, kTableSize> Segment;
		Segment.reserve(kTableSize);

		// Choose decoy slots (excluding real slot)
		SmallVector<unsigned, kTableSize> Slots;
		Slots.reserve(kTableSize - 1);
		for (unsigned i = 0; i < kTableSize; ++i)
			if (i != RealSlotOut) Slots.push_back(i);

		auto Arr = llvm::MutableArrayRef<unsigned>(Slots.data(), Slots.size());
		Ctx.DecoyRng.shuffle(Arr);

		uint32_t DecoyMask = 0;
		for (unsigned i = 0; i < DecoyCount && i < Slots.size(); ++i)
			DecoyMask |= (1u << Slots[i]);

		for (unsigned i = 0; i < kTableSize; ++i) {
			Function* Fp = nullptr;
			if (i == RealSlotOut) {
				Fp = Callee;
			}
			else if (DecoyMask & (1u << i)) {
				Fp = getOrCreateDecoyThunk(M, Callee, i);
			}
			else {
				Fp = getOrCreateThunk(M, Callee, i);
			}

			// Store as opaque ptr in the merged table
			Constant* CFn = ConstantExpr::getBitCast(Fp, PtrTy);
			Segment.push_back(CFn);
		}

		// Append segment by rebuilding array (immutable)
		auto* OldAT = cast<ArrayType>(Info.GV->getValueType());
		unsigned OldN = OldAT->getNumElements();

		SmallVector<Constant*, 512> NewElems;
		NewElems.reserve(OldN + kTableSize);

		if (auto* CA = dyn_cast<ConstantArray>(Info.GV->getInitializer())) {
			for (unsigned i = 0; i < OldN; ++i)
				NewElems.push_back(CA->getOperand(i));
		}
		else {
			for (unsigned i = 0; i < OldN; ++i)
				NewElems.push_back(Constant::getNullValue(PtrTy));
		}

		BaseOut = OldN; // base offset for this callee’s segment (aligned)
		for (Constant* E : Segment) NewElems.push_back(E);

		ArrayType* NewAT = ArrayType::get(PtrTy, (unsigned)NewElems.size());
		Constant* NewInit = ConstantArray::get(NewAT, NewElems);

		std::string KeepName = Info.GV->getName().str();
		auto* NewGV = new GlobalVariable(M, NewAT, /*isConstant=*/true, GlobalValue::PrivateLinkage, NewInit, KeepName);
		NewGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
		NewGV->setAlignment(Info.GV->getAlign().valueOrOne());

		Info.GV->replaceAllUsesWith(ConstantExpr::getBitCast(NewGV, Info.GV->getType()));
		Info.GV->eraseFromParent();
		Info.GV = NewGV;
		Info.Size = (unsigned)NewElems.size();
		Info.BaseByCallee[Callee] = BaseOut;

		return Info.GV;
	}


	// ----------------------------------------------------------------------------
	// Index that always selects real slot at runtime, but doesn't fold
	// ----------------------------------------------------------------------------
	Value* VCallImpl::makeRuntimeZeroDelta(IRBuilder<>& B, AllocaInst* VolSlot, llvm::obf::Rng& IndexRng) {
		assert(VolSlot && "VolSlot must not be null");

		// Use the real allocated type instead of hardcoding i32.
		Type* ElemTy = VolSlot->getAllocatedType();
		auto* ITy = dyn_cast<IntegerType>(ElemTy);
		assert(ITy && "VolSlot must be an alloca of integer type");

		// Two distinct volatile loads from the same address:
		// LLVM cannot assume they're equal, so it cannot fold (L1 - L2) to 0.
		auto* L1 = B.CreateLoad(ITy, VolSlot, "vcall.l1");
		auto* L2 = B.CreateLoad(ITy, VolSlot, "vcall.l2");
		L1->setVolatile(true);
		L2->setVolatile(true);

		// Optional "shape" noise. K cancels out algebraically, but keeps extra ops in IR.
		uint64_t K = (uint64_t)IndexRng.u32() | 1ull;
		Value* Kc = ConstantInt::get(ITy, K);

		Value* A1 = B.CreateAdd(L1, Kc, "vcall.a1");
		Value* A2 = B.CreateAdd(L2, Kc, "vcall.a2");

		return B.CreateSub(A1, A2, "vcall.delta0");
	}

	// ----------------------------------------------------------------------------
	// Vary index computation per callsite (semantics-preserving)
	// ----------------------------------------------------------------------------
	static uint32_t modInverseU32Odd(uint32_t A) {
		// Newton iteration for inverse mod 2^32; A must be odd.
		uint32_t inv = 1;
		for (int i = 0; i < 5; ++i)
			inv *= 2u - A * inv;
		return inv;
	}

	Value* VCallImpl::obfuscateIndexPerCallsite(IRBuilder<>& B, Value* IdxI32, VCallCtx& Ctx) {
		if (!Ctx.Cfg.varyIndexPerCallsite || Ctx.Cfg.indexStrength == 0)
			return IdxI32;

		LLVMContext& C = B.getContext();
		Type* I32 = Type::getInt32Ty(C);

		// Reuse runtime-zero delta to create “unknown but equals 0” value.
		Value* Z = makeRuntimeZeroDelta(B, Ctx.VolSlot, Ctx.SiteRng);
		Value* V = B.CreateAdd(IdxI32, Z, "vcall.idx.zadd");

		unsigned S = Ctx.Cfg.indexStrength;
		if (S >= 1) {
			V = B.CreateXor(V, Z, "vcall.idx.zxor");
		}

		if (S >= 2) {
			uint32_t A = (Ctx.SiteRng.u32() | 1u);
			uint32_t Bc = Ctx.SiteRng.u32();
			uint32_t invA = modInverseU32Odd(A);

			Value* Aval = ConstantInt::get(I32, A);
			Value* Bval = ConstantInt::get(I32, Bc);
			Value* InvA = ConstantInt::get(I32, invA);

			// T = V*A + B
			Value* T = B.CreateAdd(B.CreateMul(V, Aval, "vcall.idx.mul"), Bval, "vcall.idx.addb");
			// V = (T - B) * invA  => equals original V
			V = B.CreateMul(B.CreateSub(T, Bval, "vcall.idx.subb"), InvA, "vcall.idx.inv");
		}

		if (S >= 3) {
			// Opaque-looking select that still returns V.
			// Cond is runtime-opaque but must not change semantics: both arms equal.
			Value* Alt = B.CreateAdd(V, Z, "vcall.idx.alt");
			// Create a not-foldable cond
			Value* Cnd = B.CreateICmpEQ(Z, ConstantInt::get(I32, 0), "vcall.idx.cond"); // Z == 0 (but not foldable)
			V = B.CreateSelect(Cnd, V, Alt, "vcall.idx.sel");
		}

		return V;
	}

	// ----------------------------------------------------------------------------
	// Virtualize one callsite
	// ----------------------------------------------------------------------------
	void VCallImpl::virtualizeCall(CallInst* CI, VCallCtx& Ctx) {
		Function* Callee = CI->getCalledFunction();
		if (!Callee)
			return;

		Module& M = *CI->getModule();
		LLVMContext& C = M.getContext();

		uint32_t RealSlot = 0;
		uint32_t BaseOff = 0;
		GlobalVariable* VTable = nullptr;

		const bool Merged = Ctx.Cfg.mergeVTables;
		if (Merged) {
			VTable = getOrCreateMergedVTable(M, Callee, Ctx, BaseOff, RealSlot);
		}
		else {
			VTable = getOrCreateVTable(M, Callee, Ctx.TableRng, RealSlot);
			if (Ctx.Cfg.opaqueVTableNames) {
				// (optional, safe to leave empty for now)
			}
		}

		IRBuilder<> B(CI);
		B.SetCurrentDebugLocation(CI->getDebugLoc());

		Type* I32 = Type::getInt32Ty(C);
		Value* Mask = ConstantInt::get(I32, kTableSize - 1);

		// Compute Idx = (BaseOff + RealSlot + delta0) & mask.
		Value* Delta0 = makeRuntimeZeroDelta(B, Ctx.VolSlot, Ctx.IndexRng);
		Value* Base = ConstantInt::get(I32, (uint32_t)(BaseOff + RealSlot));
		Value* Idx = B.CreateAnd(B.CreateAdd(Base, Delta0, "vcall.idx.add"), Mask, "vcall.idx");
		Idx = obfuscateIndexPerCallsite(B, Idx, Ctx);

		Value* GEPIdx[] = { ConstantInt::get(I32, 0), Idx };
		Value* SlotPtr = B.CreateGEP(VTable->getValueType(), VTable, GEPIdx, "vcall.slot");

		// Volatile load prevents folding/devirtualization.
		Value* LoadedFunc = nullptr;
		if (Merged) {
			// merged table stores opaque ptr entries
			Type* PtrTy = PointerType::get(C, 0);
			auto* L = B.CreateLoad(PtrTy, SlotPtr, "vcall.fn.ptr");
			L->setVolatile(true);

			// Bitcast opaque ptr to the callee's pointer type (still 'ptr' in LLVM 21, but IR keeps the intent)
			LoadedFunc = B.CreateBitCast(L, Callee->getType(), "vcall.fn");
		}
		else {
			auto* L = B.CreateLoad(Callee->getType(), SlotPtr, "vcall.fn");
			L->setVolatile(true);
			LoadedFunc = L;
		}

		SmallVector<Value*, 8> Args;
		Args.reserve(CI->arg_size());
		for (Use& U : CI->args())
			Args.push_back(U.get());

		SmallVector<OperandBundleDef, 4> Bundles;
		CI->getOperandBundlesAsDefs(Bundles);

		// Use the *callsite* function type (robust).
		FunctionType* CallFTy = CI->getFunctionType();

		// Opaque pointers: expected callee pointer type is just ptr (addrspace 0).
		Type* ExpectedPtrTy = PointerType::get(C, 0);

		Value* CalleePtr = LoadedFunc;
		if (CalleePtr->getType() != ExpectedPtrTy)
			CalleePtr = B.CreateBitCast(CalleePtr, ExpectedPtrTy, "vcall.callee.cast");

		CallInst* NewCall = B.CreateCall(CallFTy, CalleePtr, Args, Bundles);

		// Preserve call site properties.
		NewCall->setCallingConv(CI->getCallingConv());
		NewCall->setAttributes(CI->getAttributes());
		NewCall->setTailCallKind(CI->getTailCallKind());
		NewCall->copyMetadata(*CI);
		NewCall->setDebugLoc(CI->getDebugLoc());

		CI->replaceAllUsesWith(NewCall);
		CI->eraseFromParent();

		++VirtualizedCalls;
	}

	// ----------------------------------------------------------------------------
	// Main pass logic
	// ----------------------------------------------------------------------------
	bool VCallImpl::runVirtualCall(VCallCtx& Ctx, int Probability, unsigned MaxSites) {
		Function& F = Ctx.F;

		std::vector<CallInst*> Candidates;
		Candidates.reserve(64);

		for (BasicBlock& BB : F) {
			for (Instruction& I : BB) {
				auto* CI = dyn_cast<CallInst>(&I);
				if (!CI) continue;
				if (!canVirtualize(CI)) continue;

				Candidates.push_back(CI);
			}
		}

		// Stable randomized order (does not consume SelectRng).
		if (!Candidates.empty()) {
			llvm::MutableArrayRef<CallInst*> Arr(Candidates.data(), Candidates.size());
			Ctx.PickRng.shuffle(Arr);

		}

		std::vector<CallInst*> ToVirtualize;
		ToVirtualize.reserve(std::min<size_t>(Candidates.size(), 32));
		for (CallInst* CI : Candidates) {
			if (Probability <= 0) break;
			if (Probability < 100 && Ctx.SelectRng.range(100) >= (uint32_t)Probability)
				continue;
			ToVirtualize.push_back(CI);
			if (MaxSites && ToVirtualize.size() >= MaxSites)
				break;

		}

		for (CallInst* CI : ToVirtualize)
			virtualizeCall(CI, Ctx);

		return !ToVirtualize.empty();
	}

}

// ============================================================================
// Pass Implementation
// ============================================================================
PreservedAnalyses VirtualCallPass::run(Function& F, FunctionAnalysisManager& AM) {
	if (F.isDeclaration())
		return PreservedAnalyses::all();

	VCallCtx Ctx(F, AM);
	if (!Ctx.Cfg.enable)
		return PreservedAnalyses::all();

	if (ObfVerbose) {
		errs() << "[vcall] Processing: " << F.getName()
			<< " prob=" << Ctx.Cfg.prob << "\n";
	}

	unsigned Budget = Ctx.Cfg.maxSites;
	if (Budget == 0) {
		// Auto: scale with calls, bounded.
		unsigned Calls = std::max<unsigned>(1u, Ctx.FOC.NumCalls);
		Budget = std::min<unsigned>(24u, std::max<unsigned>(2u, Calls / 3));

	}
	if (ObfVerbose)
		errs() << " maxSites=" << Budget << "\n";

	bool Changed = VCallImpl::runVirtualCall(Ctx, Ctx.Cfg.prob, Budget);

	if (!Changed)
		return PreservedAnalyses::all();

	// No CFG change: preserve CFG analyses.
	PreservedAnalyses PA = PreservedAnalyses::none();
	PA.preserveSet<CFGAnalyses>();
	return PA;
}
