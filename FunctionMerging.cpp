#include "llvm/Transforms/Obfuscator/FunctionMerging.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/Rng.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/ModRef.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ValueMapper.h"

#include <algorithm>
#include <map>
#include <string>
#include <vector>

using namespace llvm;

#define DEBUG_TYPE "fmerge"

STATISTIC(FMergeGroupsMerged, "Number of function-merge groups collapsed");
STATISTIC(FMergeFunctionsFolded, "Number of original functions folded into super-functions");
STATISTIC(FMergeCallSitesRewritten, "Number of call sites rewritten to super-function calls");
STATISTIC(FMergeThunksBuilt, "Number of address-taken/external functions converted to thunks");

namespace {

	// One annotated candidate: the function plus its own parsed fmerge config.
	struct AnnotatedFn {
		Function* F;
		FunctionMergingConfig Cfg;
	};

	// ── llvm.used / llvm.compiler.used membership check ──────────────────────
	bool isInUsedList(Module& M, StringRef Name, const Function* F) {
		GlobalVariable* GV = M.getGlobalVariable(Name);
		if (!GV || !GV->hasInitializer()) return false;
		auto* CA = dyn_cast<ConstantArray>(GV->getInitializer());
		if (!CA) return false;
		for (unsigned i = 0, e = CA->getNumOperands(); i != e; ++i) {
			if (CA->getOperand(i)->stripPointerCasts() == F)
				return true;
		}
		return false;
	}

	// Deterministic "shape" fingerprint for dissimilarity grouping.
	// Functions with different return types / arities / parameter types / sizes
	// hash differently; sorting the _auto pool by this key and round-robining
	// members across chunks makes each super-function mix maximally unrelated
	// behaviors (harder to reverse than a bag of look-alike siblings).
	uint64_t functionShapeKey(const Function* F) {
		uint64_t H = 14695981039346656037ull;              // FNV-1a offset
		auto mix = [&](uint64_t V) { H ^= V; H *= 1099511628211ull; };
		mix((uint64_t)F->getReturnType()->getTypeID());
		mix((uint64_t)F->arg_size());
		for (const Argument& A : F->args())
			mix((uint64_t)A.getType()->getTypeID());
		unsigned NumInsts = 0;
		for (const BasicBlock& BB : *F)
			NumInsts += (unsigned)BB.size();
		mix((uint64_t)(NumInsts / 8));                     // coarse size bucket
		mix((uint64_t)F->size());                          // block count
		return H;
	}

	// A constant user of a function is "ignorable" if it exists only to feed
	// llvm.global.annotations / llvm.used / llvm.compiler.used / llvm.metadata.
	// Every annotated function necessarily carries such a reference — it is not
	// a real address-taken.
	bool usedOnlyBySpecialGlobals(const Constant* C) {
		for (const User* U : C->users()) {
			if (auto* GV = dyn_cast<GlobalVariable>(U)) {
				StringRef N = GV->getName();
				if (N == "llvm.global.annotations" || N == "llvm.used" ||
					N == "llvm.compiler.used" || N == "llvm.metadata")
					continue;
				return false;
			}
			if (auto* CC = dyn_cast<Constant>(U)) {
				if (usedOnlyBySpecialGlobals(CC))
					continue;
				return false;
			}
			return false;
		}
		return true;
	}

	// ── Eligibility (skip-list) ──────────────────────────────────────────────
	bool isEligible(Function& F, const FunctionMergingConfig& Cfg, std::string& Reason) {
		if (F.isDeclaration() || F.hasAvailableExternallyLinkage()) {
			Reason = "declaration"; return false;
		}
		if (!Cfg.thunkAddrTaken && !F.hasLocalLinkage()) {
			Reason = "not_local_linkage"; return false;
		}
		if (F.isVarArg()) {
			Reason = "vararg"; return false;
		}
		if (F.hasPersonalityFn()) {
			Reason = "has_personality_fn"; return false;
		}
		if (F.hasFnAttribute(Attribute::Naked)) {
			Reason = "naked"; return false;
		}

		// Incompatible parameter attributes — memory repacking would break
		// their ABI copy semantics.
		for (Argument& A : F.args()) {
			if (A.hasByValAttr() || A.hasStructRetAttr() || A.hasInAllocaAttr() ||
				A.hasAttribute(Attribute::Preallocated) ||
				A.hasAttribute(Attribute::SwiftSelf) ||
				A.hasAttribute(Attribute::SwiftAsync) ||
				A.hasAttribute(Attribute::SwiftError)) {
				Reason = "incompatible_param_attr";
				return false;
			}
		}

		unsigned NumInsts = 0;
		for (BasicBlock& BB : F) {
			// blockaddress targeting this block, or an indirectbr inside it —
			// both complicate cloning the block into the super-function.
			if (BB.hasAddressTaken()) {
				Reason = "blockaddress_target";
				return false;
			}
			if (const Instruction* Term = BB.getTerminator()) {
				if (isa<IndirectBrInst>(Term)) {
					Reason = "indirectbr";
					return false;
				}
			}

			for (Instruction& I : BB) {
				if (isa<InvokeInst>(I) || isa<LandingPadInst>(I) || isa<ResumeInst>(I) ||
					isa<CatchSwitchInst>(I) || isa<CatchPadInst>(I) ||
					isa<CatchReturnInst>(I) || isa<CleanupPadInst>(I) ||
					isa<CleanupReturnInst>(I)) {
					Reason = "exception_handling";
					return false;
				}
				if (auto* CB = dyn_cast<CallBase>(&I)) {
					if (CB->isInlineAsm()) {
						Reason = "inline_asm";
						return false;
					}
				}
				if (auto* CI = dyn_cast<CallInst>(&I)) {
					if (CI->isMustTailCall()) {
						Reason = "musttail";
						return false;
					}
				}
				++NumInsts;
			}
		}

		if (NumInsts < Cfg.minInsts || NumInsts > Cfg.maxInsts) {
			Reason = "inst_count_out_of_range";
			return false;
		}

		Module& M = *F.getParent();
		if (!Cfg.thunkAddrTaken &&
			(isInUsedList(M, "llvm.used", &F) || isInUsedList(M, "llvm.compiler.used", &F))) {
			Reason = "in_llvm_used";
			return false;
		}

		// Reject address-taken functions: every use must be either the callee
		// operand of a direct CallInst, or a reference from the special metadata
		// globals (llvm.global.annotations / llvm.used / llvm.compiler.used),
		// which every annotated function carries. Anything else — F passed as a
		// call argument, stored, bitcast into a table — is a real address-taken.
		// With thunkAddrTaken a thunk preserves the symbol/address for any
		// caller, so any use shape is fine — skip this scan entirely.
		if (!Cfg.thunkAddrTaken) {
			for (const Use& U : F.uses()) {
				User* Ur = U.getUser();
				if (auto* CI = dyn_cast<CallInst>(Ur)) {
					if (CI->isCallee(&U))
						continue;                     // direct call — fine
					Reason = "address_taken_call_arg"; // F used as a call argument
					return false;
				}
				if (auto* C = dyn_cast<Constant>(Ur)) {
					if (usedOnlyBySpecialGlobals(C))
						continue;                     // annotation / used-list only
				}
				Reason = "address_taken_or_non_call_use";
				return false;
			}
		}

		return true;
	}

	// ── Group-wide knob resolution ────────────────────────────────────────
	// Members is sorted by function name (lexicographic); the first member's
	// knobs win. Warn (unconditionally — this is a real configuration
	// conflict, not chatter) if another member disagrees.
	FunctionMergingConfig resolveGroupConfig(StringRef Label,
		const std::vector<AnnotatedFn*>& Members) {
		FunctionMergingConfig Base = Members.front()->Cfg;
		for (size_t i = 1; i < Members.size(); ++i) {
			const FunctionMergingConfig& Other = Members[i]->Cfg;
			if (Other.opaqueSel != Base.opaqueSel || Other.dispatch != Base.dispatch ||
				Other.minInsts != Base.minInsts || Other.maxInsts != Base.maxInsts ||
				Other.stripDbg != Base.stripDbg || Other.chunk != Base.chunk ||
				Other.thunkAddrTaken != Base.thunkAddrTaken ||
				Other.launderSel != Base.launderSel) {
				errs() << "fmerge: group '" << Label << "': member '"
					<< Members[i]->F->getName()
					<< "' knobs disagree with lexicographically-first member '"
					<< Members.front()->F->getName() << "' — using the first member's settings\n";
			}
		}
		return Base;
	}

	// Rebuild llvm.global.annotations to drop every entry whose annotated
	// target is a merged-away function. Without this the originals keep a
	// (constant) use and can never be erased. Done once for the whole module.
	void pruneAnnotationsFor(Module& M, const SmallPtrSetImpl<Function*>& Dead) {
		GlobalVariable* GV = M.getGlobalVariable("llvm.global.annotations");
		if (!GV || !GV->hasInitializer()) return;
		auto* CA = dyn_cast<ConstantArray>(GV->getInitializer());
		if (!CA) return;

		SmallVector<Constant*, 16> Keep;
		for (unsigned i = 0, e = CA->getNumOperands(); i != e; ++i) {
			Constant* Entry = CA->getOperand(i);
			Function* AnnFn = nullptr;
			if (auto* CS = dyn_cast<ConstantStruct>(Entry))
				if (CS->getNumOperands() > 0)
					AnnFn = dyn_cast<Function>(CS->getOperand(0)->stripPointerCasts());
			if (AnnFn && Dead.count(AnnFn))
				continue;                 // drop this annotation entry
			Keep.push_back(Entry);
		}
		if (Keep.size() == CA->getNumOperands())
			return;                       // nothing pruned

		if (Keep.empty()) {
			GV->eraseFromParent();
			return;
		}
		ArrayType* NewTy = ArrayType::get(CA->getType()->getElementType(), Keep.size());
		Constant* NewInit = ConstantArray::get(NewTy, Keep);
		auto* NewGV = new GlobalVariable(M, NewTy, GV->isConstant(), GV->getLinkage(),
			NewInit, "", GV, GV->getThreadLocalMode(), GV->getAddressSpace());
		NewGV->copyAttributesFrom(GV);
		GV->replaceAllUsesWith(NewGV);
		NewGV->takeName(GV);
		GV->eraseFromParent();
	}

	// Produce the selector value at a call site. With a laundering table the
	// selector is a volatile load from a mutable global (so constant-propagation
	// devirtualization can't recover which behavior runs); otherwise it is the
	// plain constant.
	Value* emitSelector(IRBuilder<>& B, GlobalVariable* SelTable, ArrayType* SelTableTy,
		size_t Slot, uint64_t ConstSel, Type* I64Ty) {
		if (!SelTable)
			return ConstantInt::get(I64Ty, ConstSel);
		Value* Zero = ConstantInt::get(I64Ty, 0);
		Value* Gep = B.CreateInBoundsGEP(SelTableTy, SelTable,
			{ Zero, ConstantInt::get(I64Ty, (uint64_t)Slot) }, "fmerge.selslot");
		LoadInst* L = B.CreateLoad(I64Ty, Gep, "fmerge.sel");
		L->setVolatile(true);
		return L;
	}

	// Replace Fi's body with a thin forwarder that packs its own arguments and
	// tail-calls the already-verified super-function. Preserves Fi's
	// symbol/address/signature/linkage so function pointers and external callers
	// keep working; only the body changes (deleteBody() turns Fi into a
	// declaration, then a fresh entry block makes it a definition again).
	void buildThunk(Function* Fi, Function* Merged, StructType* PackTy, uint64_t Sel,
		PointerType* PtrTy, Type* I64Ty, GlobalVariable* SelTable,
		ArrayType* SelTableTy, size_t Slot) {
		Type* RetTy = Fi->getReturnType();
		// Function::deleteBody() forces ExternalLinkage as a side effect — not
		// what we want for a still-internal-but-address-taken Fi. Save/restore
		// around the call so the thunk keeps Fi's original linkage.
		GlobalValue::LinkageTypes OrigLinkage = Fi->getLinkage();
		Fi->deleteBody();
		Fi->setLinkage(OrigLinkage);

		// The forwarder now calls into the merged body, so drop fn-level
		// attributes it could violate; ABI-relevant param/ret attributes are
		// untouched since the signature itself is unchanged.
		Fi->setMemoryEffects(MemoryEffects::unknown());
		Fi->removeFnAttr(Attribute::WillReturn);
		Fi->removeFnAttr(Attribute::NoRecurse);

		LLVMContext& Ctx = Fi->getContext();
		BasicBlock* BB = BasicBlock::Create(Ctx, "entry", Fi);
		IRBuilder<> B(BB);

		AllocaInst* Pack = B.CreateAlloca(PackTy, nullptr, "fmerge.pack");
		for (unsigned j = 0, je = Fi->arg_size(); j != je; ++j) {
			Value* Gep = B.CreateStructGEP(PackTy, Pack, j, "fmerge.argp");
			B.CreateStore(Fi->getArg(j), Gep);
		}

		AllocaInst* Ret = RetTy->isVoidTy() ? nullptr
			: B.CreateAlloca(RetTy, nullptr, "fmerge.ret");
		Value* SelV = emitSelector(B, SelTable, SelTableTy, Slot, Sel, I64Ty);
		Value* RetSlot = Ret ? (Value*)Ret : (Value*)ConstantPointerNull::get(PtrTy);

		B.CreateCall(Merged->getFunctionType(), Merged, { SelV, Pack, RetSlot });

		if (RetTy->isVoidTy())
			B.CreateRetVoid();
		else {
			Value* V = B.CreateLoad(RetTy, Ret, "fmerge.retval");
			B.CreateRet(V);
		}
	}

	// ── Merge one group of >=2 eligible functions into one super-function ──
	// Transactional: builds the super-function fully, verifies it, and only
	// then rewrites call sites. Originals whose uses are all gone (bar the
	// annotation metadata pruned later by run()) are queued in DeadOut for
	// erasure; every merged-away member (thunked or erased) is queued in
	// MergedOut so run() can prune its stale annotation entry. On
	// verification failure the super-function is discarded and every
	// original is left untouched.
	bool mergeGroup(Module& M, StringRef Label, std::vector<AnnotatedFn*>& Members,
		const llvm::obf::Rng& GroupRng, std::vector<Function*>& DeadOut,
		std::vector<Function*>& MergedOut) {
		if (Members.size() < 2)
			return false;

		LLVMContext& Ctx = M.getContext();
		Type* I64Ty = Type::getInt64Ty(Ctx);
		PointerType* PtrTy = PointerType::getUnqual(Ctx);

		FunctionMergingConfig GroupCfg = resolveGroupConfig(Label, Members);
		llvm::obf::Rng R = GroupRng;

		// ── Super-function shell ──
		FunctionType* FT = FunctionType::get(I64Ty, { I64Ty, PtrTy, PtrTy }, /*isVarArg=*/false);
		Function* Merged = Function::Create(FT, GlobalValue::InternalLinkage,
			(Twine("__obf_merged_") + Label).str(), &M);
		Merged->addFnAttr(Attribute::NoInline);
		Merged->getArg(0)->setName("selector");
		Merged->getArg(1)->setName("argpack");
		Merged->getArg(2)->setName("retslot");
		Value* SelectorArg = Merged->getArg(0);
		Value* ArgpackArg = Merged->getArg(1);
		Value* RetslotArg = Merged->getArg(2);

		BasicBlock* EntryBB = BasicBlock::Create(Ctx, "entry", Merged);
		BasicBlock* ExitBB = BasicBlock::Create(Ctx, "exit", Merged);
		BasicBlock* TrapBB = BasicBlock::Create(Ctx, "trap", Merged);

		IRBuilder<> ExB(ExitBB);
		ExB.CreateRet(ConstantInt::get(I64Ty, 0));

		IRBuilder<> TB(TrapBB);
		TB.CreateUnreachable();

		IRBuilder<> EB(EntryBB);
		uint64_t K = 0;
		Value* Idx = SelectorArg;
		if (GroupCfg.opaqueSel) {
			K = R.u64();
			Idx = EB.CreateXor(SelectorArg, ConstantInt::get(I64Ty, K), "fmerge.idx");
		}
		// Entry's terminator is built after the per-member case blocks exist:
		// indirectbr dispatch needs their blockaddresses.
		GlobalVariable* JT = nullptr; // indirectbr jump table; null in switch mode

		// ── Per-member case blocks ──
		std::vector<StructType*> PackTypes(Members.size(), nullptr);
		std::vector<uint64_t> SelForMember(Members.size(), 0);
		std::vector<BasicBlock*> CaseBlocks(Members.size(), nullptr);

		for (size_t i = 0; i < Members.size(); ++i) {
			Function* Fi = Members[i]->F;

			SmallVector<Type*, 8> ParamTypes;
			ParamTypes.reserve(Fi->arg_size());
			for (Argument& A : Fi->args())
				ParamTypes.push_back(A.getType());

			StructType* PackTy = StructType::create(
				Ctx, ParamTypes,
				(Twine("__obf_pack_") + Label + "_" + Twine((unsigned)i)).str());
			PackTypes[i] = PackTy;

			BasicBlock* CaseBB =
				BasicBlock::Create(Ctx, (Twine("case_") + Twine((unsigned)i)).str(), Merged);
			CaseBlocks[i] = CaseBB;

			IRBuilder<> CB(CaseBB);
			ValueToValueMapTy VMap;
			for (unsigned j = 0, je = Fi->arg_size(); j != je; ++j) {
				Argument* Aj = Fi->getArg(j);
				Value* Gep = CB.CreateStructGEP(PackTy, ArgpackArg, j, "fmerge.argp");
				Value* Loaded = CB.CreateLoad(Aj->getType(), Gep, "fmerge.arg");
				VMap[Aj] = Loaded;
			}

			// Clone every block of Fi into Merged (first pass — no remapping
			// yet, CloneBasicBlock leaves operands pointing at the originals).
			SmallVector<BasicBlock*, 16> ClonedBlocks;
			ClonedBlocks.reserve(Fi->size());
			for (BasicBlock& BB : *Fi) {
				BasicBlock* NBB = CloneBasicBlock(
					&BB, VMap, (Twine(".fm") + Twine((unsigned)i)).str(), Merged);
				VMap[&BB] = NBB;
				ClonedBlocks.push_back(NBB);
			}

			BasicBlock* ClonedEntry = cast<BasicBlock>(VMap[&Fi->getEntryBlock()]);
			CB.CreateBr(ClonedEntry);

			// Second pass — remap operands now that every block/arg is mapped.
			for (BasicBlock* NBB : ClonedBlocks)
				for (Instruction& I : *NBB)
					RemapInstruction(&I, VMap, RF_IgnoreMissingLocals | RF_NoModuleLevelChanges);

			// Rewrite `ret` terminators: store to retslot (non-void) + branch
			// to the shared exit block. Collect first to avoid mutating the
			// blocks while iterating their terminators.
			Type* RetTy = Fi->getReturnType();
			SmallVector<ReturnInst*, 8> Returns;
			for (BasicBlock* NBB : ClonedBlocks)
				if (auto* RI = dyn_cast<ReturnInst>(NBB->getTerminator()))
					Returns.push_back(RI);

			for (ReturnInst* RI : Returns) {
				IRBuilder<> RB(RI);
				if (!RetTy->isVoidTy())
					RB.CreateStore(RI->getReturnValue(), RetslotArg);
				RB.CreateBr(ExitBB);
				RI->eraseFromParent();
			}

			if (GroupCfg.stripDbg) {
				for (BasicBlock* NBB : ClonedBlocks)
					for (Instruction& I : *NBB)
						I.setDebugLoc(DebugLoc());
			}

			uint64_t Sel = (uint64_t)i;
			if (GroupCfg.opaqueSel) Sel ^= K;
			SelForMember[i] = Sel;
		}

		// ── Entry dispatch terminator ──
		// Built now that every case block exists: indirectbr needs their
		// blockaddresses.
		if (GroupCfg.dispatch == "indirectbr") {
			SmallVector<Constant*, 16> Addrs;
			Addrs.reserve(Members.size());
			for (size_t i = 0; i < Members.size(); ++i)
				Addrs.push_back(BlockAddress::get(Merged, CaseBlocks[i]));
			ArrayType* JTTy = ArrayType::get(PtrTy, Members.size());
			Constant* JTInit = ConstantArray::get(JTTy, Addrs);
			JT = new GlobalVariable(M, JTTy, /*isConstant=*/true, GlobalValue::InternalLinkage,
				JTInit, (Twine("__obf_fmjt_") + Label).str());

			Value* Zero = ConstantInt::get(I64Ty, 0);
			Value* JGep = EB.CreateInBoundsGEP(JTTy, JT, { Zero, Idx }, "fmerge.jtslot");
			Value* Tgt = EB.CreateLoad(PtrTy, JGep, "fmerge.jttgt");
			IndirectBrInst* IBR = EB.CreateIndirectBr(Tgt, (unsigned)Members.size());
			for (size_t i = 0; i < Members.size(); ++i)
				IBR->addDestination(CaseBlocks[i]);

			// TrapBB is unused in indirectbr mode (the selector is always in
			// range by construction) — erase it so it doesn't dangle as a
			// disconnected block. Not part of rollback: it's already gone by
			// the time verify runs below.
			TrapBB->eraseFromParent();
			TrapBB = nullptr;
		}
		else {
			SwitchInst* SW = EB.CreateSwitch(Idx, TrapBB, (unsigned)Members.size());
			for (size_t i = 0; i < Members.size(); ++i)
				SW->addCase(cast<ConstantInt>(ConstantInt::get(I64Ty, (uint64_t)i)), CaseBlocks[i]);
		}

		// ── Transactional verify: roll back the whole group on failure ──
		if (verifyFunction(*Merged, &errs())) {
			errs() << "fmerge: group '" << Label
				<< "' produced an invalid super-function — rolled back, originals left untouched\n";
			Merged->eraseFromParent();
			if (JT) JT->eraseFromParent();
			return false;
		}

		// Optional selector-laundering table: a mutable global holding each
		// member's selector. Built only after verify succeeds, so it needs no
		// rollback handling. Call sites load their selector from it (volatile)
		// instead of embedding a constant.
		ArrayType* SelTableTy = nullptr;
		GlobalVariable* SelTable = nullptr;
		if (GroupCfg.launderSel) {
			SmallVector<Constant*, 16> Sels;
			Sels.reserve(Members.size());
			for (size_t i = 0; i < Members.size(); ++i)
				Sels.push_back(ConstantInt::get(I64Ty, SelForMember[i]));
			SelTableTy = ArrayType::get(I64Ty, Members.size());
			SelTable = new GlobalVariable(M, SelTableTy, /*isConstant=*/false,
				GlobalValue::InternalLinkage, ConstantArray::get(SelTableTy, Sels),
				(Twine("__obf_fmsel_") + Label).str());
		}

		// ── Call-site rewrite (per member; self-recursive / cross-member
		// calls inside the cloned bodies are ordinary users of the original
		// Function and get picked up here too). ──
		for (size_t i = 0; i < Members.size(); ++i) {
			Function* Fi = Members[i]->F;
			StructType* PackTy = PackTypes[i];
			Type* RetTy = Fi->getReturnType();
			uint64_t Sel = SelForMember[i];

			SmallVector<CallInst*, 8> Calls;
			for (User* U : Fi->users()) {
				auto* CI = dyn_cast<CallInst>(U);
				if (!CI || CI->getCalledOperand() != Fi) continue; // defensive; eligibility already enforces this
				Calls.push_back(CI);
			}
			// Deterministic order: group by caller name, stable within a
			// caller (use-list order is itself deterministic for a fixed
			// input IR — it is insertion order, not pointer-hash order).
			llvm::stable_sort(Calls, [](CallInst* A, CallInst* B) {
				return A->getFunction()->getName() < B->getFunction()->getName();
				});

			for (CallInst* CI : Calls) {
				Function* Caller = CI->getFunction();
				Instruction* AllocaIP = &*Caller->getEntryBlock().getFirstInsertionPt();
				IRBuilder<> AB(AllocaIP);

				AllocaInst* Pack = AB.CreateAlloca(PackTy, nullptr, "fmerge.pack");
				AllocaInst* RetAlloca = RetTy->isVoidTy()
					? nullptr
					: AB.CreateAlloca(RetTy, nullptr, "fmerge.ret");

				IRBuilder<> CBI(CI);
				for (unsigned j = 0, je = CI->arg_size(); j != je; ++j) {
					Value* Gep = CBI.CreateStructGEP(PackTy, Pack, j, "fmerge.argp");
					CBI.CreateStore(CI->getArgOperand(j), Gep);
				}

				Value* SelVal = emitSelector(CBI, SelTable, SelTableTy, i, Sel, I64Ty);
				Value* RetSlotVal = RetAlloca
					? (Value*)RetAlloca
					: (Value*)ConstantPointerNull::get(PtrTy);

				CallInst* NC = CBI.CreateCall(Merged->getFunctionType(), Merged,
					{ SelVal, Pack, RetSlotVal });
				NC->setCallingConv(Merged->getCallingConv());

				if (!RetTy->isVoidTy()) {
					Value* RV = CBI.CreateLoad(RetTy, RetAlloca, "fmerge.retval");
					CI->replaceAllUsesWith(RV);
				}
				CI->eraseFromParent();
				++FMergeCallSitesRewritten;
			}

			// Fi is still referenced by llvm.global.annotations (pruned once
			// for the whole module below). "Real" uses are anything beyond
			// that special metadata — direct calls were just rewritten above,
			// so any remaining real use is either an address-taken reference
			// or (with thunkAddrTaken) external visibility.
			bool HasRealUses = false;
			for (const Use& U : Fi->uses()) {
				auto* C = dyn_cast<Constant>(U.getUser());
				if (!C || !usedOnlyBySpecialGlobals(C)) { HasRealUses = true; break; }
			}

			bool NeedsThunk = GroupCfg.thunkAddrTaken &&
				(!Fi->hasLocalLinkage() || HasRealUses);

			if (NeedsThunk) {
				// Keep the symbol alive as a forwarder instead of erasing it.
				// The annotation is still pruned (MergedOut) but Fi is NOT queued
				// in DeadOut — it must not be erased.
				buildThunk(Fi, Merged, PackTy, Sel, PtrTy, I64Ty, SelTable, SelTableTy, i);
				MergedOut.push_back(Fi);
				++FMergeThunksBuilt;
			}
			else if (!HasRealUses) {
				// Every remaining use is annotation-only — safe to erase once
				// run() prunes that annotation.
				DeadOut.push_back(Fi);
				MergedOut.push_back(Fi);
			}
			else if (ObfVerbose) {
				errs() << "fmerge: '" << Fi->getName()
					<< "' still has real uses after call-site rewrite; leaving the original in place\n";
			}
		}

		++FMergeGroupsMerged;
		return true;
	}

} // namespace

PreservedAnalyses FunctionMergingPass::run(Module& M, ModuleAnalysisManager& AM) {
	auto& Cache = AM.getResult<ObfuscationAnnotationAnalysis>(M);
	if (!Cache.hasAnyConfig())
		return PreservedAnalyses::all();

	// Collect annotated, name-sorted candidates for determinism.
	std::vector<Function*> Fns;
	for (Function& F : M)
		if (!F.isDeclaration())
			Fns.push_back(&F);
	llvm::sort(Fns, [](const Function* A, const Function* B) {
		return A->getName() < B->getName();
		});

	std::vector<AnnotatedFn> Annotated;
	Annotated.reserve(Fns.size());
	for (Function* F : Fns) {
		auto PC = Cache.getConfig(*F).getPassConfig("fmerge");
		if (!PC) continue;
		FunctionMergingConfig Cfg = FunctionMergingConfig::fromPassConfig(*PC);
		if (!Cfg.enable || !Cfg.validate()) continue;
		Annotated.push_back(AnnotatedFn{ F, std::move(Cfg) });
	}

	if (Annotated.empty())
		return PreservedAnalyses::all();

	// Eligibility filter.
	std::vector<AnnotatedFn> Eligible;
	Eligible.reserve(Annotated.size());
	for (auto& AF : Annotated) {
		std::string Reason;
		if (!isEligible(*AF.F, AF.Cfg, Reason)) {
			errs() << "fmerge: dropping '" << AF.F->getName() << "' from group '"
				<< (AF.Cfg.group.empty() ? std::string("_auto") : AF.Cfg.group)
				<< "': " << Reason << "\n";
			continue;
		}
		Eligible.push_back(std::move(AF));
	}

	if (Eligible.size() < 2)
		return PreservedAnalyses::all();

	// Bucket by group label; std::map gives deterministic (sorted) key
	// iteration. Members preserve the name-sorted relative order established
	// above since we only ever append.
	std::map<std::string, std::vector<AnnotatedFn*>> Buckets;
	for (auto& AF : Eligible) {
		std::string Label = AF.Cfg.group.empty() ? "_auto" : AF.Cfg.group;
		Buckets[Label].push_back(&AF);
	}

	llvm::obf::Rng R(llvm::obf::mix64(Cache.ModuleSeed ^ llvm::obf::fnv1a64("fmerge")));

	bool Changed = false;
	std::vector<Function*> Dead;
	std::vector<Function*> MergedAway; // thunked or erased; all need their annotation pruned

	for (auto& Entry : Buckets) {
		const std::string& Label = Entry.first;
		std::vector<AnnotatedFn*>& Members = Entry.second;

		if (Label == "_auto") {
			unsigned ChunkSz = Members.empty() ? 4 : Members.front()->Cfg.chunk;
			if (ChunkSz < 2) ChunkSz = 2;
			bool Dissim = Members.empty() ? true : Members.front()->Cfg.dissimilar;

			size_t NumChunks = (Members.size() + ChunkSz - 1) / ChunkSz;
			std::vector<std::vector<AnnotatedFn*>> Chunks(NumChunks);

			if (Dissim && NumChunks > 1) {
				// Sort by shape fingerprint, then round-robin across chunks so
				// each chunk is maximally heterogeneous. Deterministic (stable
				// sort on shape key + name; fixed round-robin).
				std::vector<AnnotatedFn*> Ordered(Members.begin(), Members.end());
				llvm::stable_sort(Ordered, [](AnnotatedFn* A, AnnotatedFn* B) {
					uint64_t KA = functionShapeKey(A->F), KB = functionShapeKey(B->F);
					if (KA != KB) return KA < KB;
					return A->F->getName() < B->F->getName();
					});
				for (size_t i = 0; i < Ordered.size(); ++i)
					Chunks[i % NumChunks].push_back(Ordered[i]);
			}
			else {
				// Sequential contiguous chunks (dissimilar off, or single chunk).
				for (size_t c = 0; c < NumChunks; ++c) {
					size_t Begin = c * ChunkSz;
					size_t End = std::min(Members.size(), Begin + ChunkSz);
					Chunks[c].assign(Members.begin() + Begin, Members.begin() + End);
				}
			}

			for (size_t c = 0; c < NumChunks; ++c) {
				if (Chunks[c].size() < 2) continue;
				std::string ChunkLabel = "_auto" + std::to_string(c);
				llvm::obf::Rng GroupR = R.fork(ChunkLabel);
				if (mergeGroup(M, ChunkLabel, Chunks[c], GroupR, Dead, MergedAway))
					Changed = true;
			}
		}
		else {
			if (Members.size() < 2) continue;
			llvm::obf::Rng GroupR = R.fork(Label);
			if (mergeGroup(M, Label, Members, GroupR, Dead, MergedAway))
				Changed = true;
		}
	}

	// Prune annotation metadata for every merged-away member (thunked or
	// erased) once, BEFORE erasing Dead — thunked functions keep their real
	// uses (the thunk body) and are never in Dead, so this only drops the
	// now-stale llvm.global.annotations entries; it does not by itself make
	// anything erasable.
	if (!MergedAway.empty()) {
		SmallPtrSet<Function*, 16> MergedSet(MergedAway.begin(), MergedAway.end());
		pruneAnnotationsFor(M, MergedSet);
		Changed = true;
	}

	// Erase the functions fully folded away (their only remaining uses were
	// those annotation references, now pruned above).
	if (!Dead.empty()) {
		for (Function* F : Dead) {
			F->removeDeadConstantUsers();
			if (F->use_empty()) {
				F->eraseFromParent();
				++FMergeFunctionsFolded;
			}
			else if (ObfVerbose) {
				errs() << "fmerge: could not erase '" << F->getName()
					<< "' — uses remain\n";
			}
		}
		Changed = true;
	}

	return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
