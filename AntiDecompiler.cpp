// ============================================================================
// AntiDecompiler.cpp — IR-level anti-decompilation patterns
//
// Targets specific weaknesses in decompilers (IDA Pro, Ghidra, Binary Ninja):
//
//  1. Inline ASM anti-disassembly gadgets  (x86-64 / AArch64)
//     Emit opaque byte sequences that desync linear-sweep disassemblers.
//
//  2. IndirectBr trampolines
//     Replace unconditional branches with volatile-loaded blockaddress
//     indirectbr.  CFG recovery fails on unresolved indirect targets.
//
//  3. Opaque-predicate dead-code decoys
//     Inject unreachable blocks with type-confusing IR (int ↔ float casts,
//     aliased stores) that pollute decompiler variable/type output.
//
//  4. Stack-frame pollution
//     Fake allocas with volatile stores that corrupt stack-frame recovery
//     and local-variable identification.
//
//  5. Indirect-call trampolines
//     Replace direct calls with loads from volatile function-pointer slots.
//     Destroys call-graph and cross-reference reconstruction.
//
//  6. Pointer-alias confusion
//     Create aliased pointers through ptrtoint → add volatile_zero → inttoptr
//     chains that break alias analysis / type propagation in decompilers.
//
// ============================================================================

#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/Transforms/Obfuscator/EhUtils.h"
#include "llvm/Transforms/Obfuscator/AntiDecompiler.h"
#include "llvm/Transforms/Obfuscator/PassCtx.h"
#include "llvm/Transforms/Obfuscator/FunctionObfContextAnalysis.h"
#include "llvm/Transforms/Obfuscator/Utils.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/OpaqueUtils.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"

using namespace llvm;

#define DEBUG_TYPE "adec"

STATISTIC(ADecFunctions, "Functions processed by anti-decompiler");
STATISTIC(ADecAsmGadgets, "Inline ASM anti-disasm gadgets inserted");
STATISTIC(ADecIndirectBrs, "Branches converted to indirectbr trampolines");
STATISTIC(ADecDeadDecoys, "Opaque-predicate dead-code decoy blocks");
STATISTIC(ADecStackSlots, "Fake stack-frame pollution slots");
STATISTIC(ADecIndirectCalls, "Direct calls converted to indirect trampolines");
STATISTIC(ADecAliasPairs, "Pointer-alias confusion pairs");

namespace {

	// ============================================================================
	// Forward declarations
	// ============================================================================
	struct ADecCtx;

	// ============================================================================
	// x86-64 anti-disassembly gadgets
	//
	// Each gadget is a short unconditional jmp that skips over bytes which,
	// when decoded linearly, look like the start of a multi-byte instruction.
	// This causes linear-sweep disassemblers (and recursive-descent ones that
	// fall through) to desync their instruction stream.
	// ============================================================================
	static constexpr const char* kX86Gadgets[] = {
		// jmp +1, fake CALL prefix (linear scan eats 4 bytes as rel32 operand)
		".byte 0xeb,0x01,0xe8",
		// jmp +2, fake JZ near prefix (eats 4 bytes as rel32)
		".byte 0xeb,0x02,0x0f,0x84",
		// jmp +1, LOCK prefix (next insn gets illegal LOCK → decode confusion)
		".byte 0xeb,0x01,0xf0",
		// jmp +3, fake REX.W + MOV imm64 prefix (eats 8 more bytes)
		".byte 0xeb,0x03,0x48,0xb8,0xff",
		// jmp +2, fake REP RET sequence (confuses AMD64 return prediction)
		".byte 0xeb,0x02,0xf3,0xc3",
		// jmp +1, VEX 3-byte prefix (eats 2 more bytes as VEX fields)
		".byte 0xeb,0x01,0xc4",
		// jmp +2, fake JNZ near prefix
		".byte 0xeb,0x02,0x0f,0x85",
		// jmp +4, fake CALL with partial modrm — linear scan misreads 4 bytes
		".byte 0xeb,0x04,0xe8,0x00,0x00,0x00",
		// jmp +3, fake LEA r64,[rip+disp32] prefix — common IDA pattern
		".byte 0xeb,0x03,0x48,0x8d,0x05",
		// jmp +2, fake 2-byte NOP prefix (0f 1f) — benign but desync
		".byte 0xeb,0x02,0x0f,0x1f",
	};
	static constexpr unsigned kNumX86Gadgets =
		sizeof(kX86Gadgets) / sizeof(kX86Gadgets[0]);

	// ============================================================================
	// AArch64 anti-disassembly gadgets
	//
	// AArch64 uses fixed 4-byte instructions, so overlapping isn't possible.
	// Instead we branch over data words that decode as valid but misleading
	// instructions, confusing CFG recovery and data-flow analysis.
	// ============================================================================
	static constexpr const char* kAArch64Gadgets[] = {
		// branch over fake stack adjustment
		"b 1f\n.4byte 0xd10043ff\n1:",
		// branch over fake register save
		"b 1f\n.4byte 0xa9bf7bfd\n1:",
		// branch over fake load
		"b 1f\n.4byte 0xf9400000\n1:",
		// branch over fake str (store register pair)
		"b 1f\n.4byte 0xa9007bfd\n1:",
		// branch over two fake instructions (double-width data)
		"b 1f\n.4byte 0xd10083ff\n.4byte 0xa9007bfd\n1:",
		// branch over fake branch-link (confuses call-graph recovery)
		"b 1f\n.4byte 0x94000001\n1:",
	};
	static constexpr unsigned kNumAArch64Gadgets =
		sizeof(kAArch64Gadgets) / sizeof(kAArch64Gadgets[0]);


	// ============================================================================
	// Implementation
	// ============================================================================
	struct ADecImpl final {

		// --- Config ---------------------------------------------------------------
		static AntiDecompilerConfig getConfig(Function& F,
			FunctionAnalysisManager& AM);

		static bool isEligible(const FunctionObfContext& Ctx, raw_ostream* Reason);

		// --- Technique 1: inline ASM anti-disasm ----------------------------------
		static unsigned emitAsmGadgets(ADecCtx& Ctx, unsigned Budget);

		// --- Technique 2: indirectbr trampolines ----------------------------------
		static unsigned emitIndirectBrTrampolines(ADecCtx& Ctx, unsigned Budget);

		// --- Technique 3: opaque-predicate dead-code decoys -----------------------
		static unsigned emitDeadCodeDecoys(ADecCtx& Ctx, unsigned Budget);
		static void     buildDecoyBlock(ADecCtx& Ctx, BasicBlock* DeadBB,
			BasicBlock* MergeBB);

		// --- Technique 4: stack-frame pollution -----------------------------------
		static void emitStackPollution(ADecCtx& Ctx);

		// --- Technique 5: indirect-call trampolines -------------------------------
		static unsigned emitCallTrampolines(ADecCtx& Ctx, unsigned Budget);

		// --- Technique 6: pointer-alias confusion ---------------------------------
		static unsigned emitAliasConfusion(ADecCtx& Ctx, unsigned Budget);

		// --- Helpers --------------------------------------------------------------
		static bool canConvertBranch(BranchInst* BI);
		static bool canConvertCall(CallInst* CI);
		static bool blockHasPhis(BasicBlock* BB);

		// --- Main entry -----------------------------------------------------------
		static bool run(ADecCtx& Ctx);
	};


	// ============================================================================
	// Context
	// ============================================================================
	struct ADecCtx : llvm::obf::FuncPassCtx {
		AntiDecompilerConfig Cfg;
		FunctionObfContext& FOC;

		llvm::obf::OpaqueUtils Opaque;

		// Sub-RNGs
		llvm::obf::Rng SelectRng;   // per-site probability gating
		llvm::obf::Rng GadgetRng;   // gadget variant selection
		llvm::obf::Rng StackRng;    // stack pollution constants
		llvm::obf::Rng DecoyRng;    // dead-code decoy content
		llvm::obf::Rng CallRng;     // call trampoline salts
		llvm::obf::Rng AliasRng;    // alias confusion salts
		llvm::obf::Rng ShuffleRng;  // block/inst ordering

		// Cached target info
		bool IsX86_64 = false;
		bool IsAArch64 = false;

		ADecCtx(Function& F, FunctionAnalysisManager& AM)
			: FuncPassCtx(F, AM, "adec"),
			Cfg(ADecImpl::getConfig(F, AM)),
			FOC(*AM.getResult<FunctionObfContextAnalysis>(F)),
			Opaque(M, R, "adec.opaque.salt.i32",
				[&]() {
					llvm::obf::OpaqueUtils::Options O;
					O.EnableOpaqueConsts = true;
					O.EnableOpaqueBools = true;
					O.EnableHardPreds = true;
					O.VolatileLoads = true;
					O.PredStrength = std::min<unsigned>(Cfg.strength, 3u);
					return O;
				}()),
			SelectRng(R.fork("select")),
			GadgetRng(R.fork("gadget")),
			StackRng(R.fork("stack")),
			DecoyRng(R.fork("decoy")),
			CallRng(R.fork("call")),
			AliasRng(R.fork("alias")),
			ShuffleRng(R.fork("shuffle"))
		{
			Triple T(M.getTargetTriple());
			IsX86_64 = T.isX86() && T.isArch64Bit();
			IsAArch64 = T.isAArch64();
		}
	};


	// ============================================================================
	// Config
	// ============================================================================
	AntiDecompilerConfig ADecImpl::getConfig(Function& F,
		FunctionAnalysisManager& AM) {
		const ObfuscationConfig& OC = getObfConfig(F, AM);
		auto PC = OC.getPassConfig("adec");
		if (!PC.has_value()) {
			AntiDecompilerConfig cfg;
			cfg.enable = false;
			return cfg;
		}
		AntiDecompilerConfig cfg = AntiDecompilerConfig::fromPassConfig(*PC);
		if (!cfg.validate()) {
			if (ObfVerbose)
				errs() << "[adec] Invalid config for " << F.getName()
				<< ", disabling\n";
			cfg.enable = false;
		}
		return cfg;
	}


	// ============================================================================
	// Eligibility
	// ============================================================================
	bool ADecImpl::isEligible(const FunctionObfContext& Ctx, raw_ostream* R) {
		if (Ctx.HasNaked) {
			if (R) *R << "naked function";
			return false;
		}
		if (Ctx.HasCallBr) {
			if (R) *R << "callbr present";
			return false;
		}
		if (Ctx.HasConvergentCalls) {
			if (R) *R << "convergent calls present";
			return false;
		}
		// Need at least 2 blocks for meaningful transforms
		if (Ctx.NumBlocks < 2) {
			if (R) *R << "too few blocks (" << Ctx.NumBlocks << ")";
			return false;
		}
		return true;
	}


	// ============================================================================
	// Helpers
	// ============================================================================

	/// Can we safely convert this unconditional branch to an indirectbr?
	bool ADecImpl::canConvertBranch(BranchInst* BI) {
		if (!BI || !BI->isUnconditional())
			return false;

		BasicBlock* BB = BI->getParent();

		// Don't touch the entry block's terminator
		if (BB == &BB->getParent()->getEntryBlock())
			return false;

		// Don't touch EH pads
		if (BB->isEHPad())
			return false;

		BasicBlock* Succ = BI->getSuccessor(0);
		// Don't convert self-loops (would create degenerate indirectbr)
		if (Succ == BB)
			return false;

		return true;
	}

	/// Can we safely replace this direct call with an indirect trampoline?
	bool ADecImpl::canConvertCall(CallInst* CI) {
		if (!CI)
			return false;

		// Must be a direct call to a known function
		Function* Callee = CI->getCalledFunction();
		if (!Callee)
			return false;

		// Skip intrinsics, inline asm
		if (Callee->isIntrinsic() || CI->isInlineAsm())
			return false;

		// Skip calls with special attributes
		if (CI->isMustTailCall() || CI->isNoTailCall())
			return false;

		// Skip calls in EH pads
		if (CI->getParent()->isEHPad())
			return false;

		// Skip variadic callees (tricky ABI)
		if (Callee->isVarArg())
			return false;

		// Skip functions with personality (exception handling)
		if (Callee->hasPersonalityFn())
			return false;

		return true;
	}

	bool ADecImpl::blockHasPhis(BasicBlock* BB) {
		return BB && !BB->empty() && isa<PHINode>(&BB->front());
	}


	// ============================================================================
	// Technique 1: Inline ASM Anti-Disassembly Gadgets
	// ============================================================================
	unsigned ADecImpl::emitAsmGadgets(ADecCtx& Ctx, unsigned Budget) {
		if (!Ctx.Cfg.enableAsmAntiDisasm)
			return 0;

		// Only emit gadgets for known targets
		if (!Ctx.IsX86_64 && !Ctx.IsAArch64)
			return 0;

		const char* const* Gadgets;
		unsigned NumGadgets;
		const char* Clobbers;
		if (Ctx.IsX86_64) {
			Gadgets = kX86Gadgets;
			NumGadgets = kNumX86Gadgets;
			Clobbers = "~{dirflag},~{fpsr},~{flags}";
		}
		else {
			Gadgets = kAArch64Gadgets;
			NumGadgets = kNumAArch64Gadgets;
			Clobbers = "";
		}

		LLVMContext& C = Ctx.F.getContext();
		FunctionType* VoidFnTy = FunctionType::get(Type::getVoidTy(C), false);

		// Collect insertion points: before non-phi, non-terminator instructions
		SmallVector<Instruction*, 64> InsertPts;
		for (BasicBlock& BB : Ctx.F) {
			// Skip entry block to preserve prologue patterns
			if (&BB == &Ctx.F.getEntryBlock())
				continue;
			if (BB.isEHPad())
				continue;

			for (auto It = BB.getFirstNonPHI()->getIterator(),
				E = BB.end(); It != E; ++It) {
				Instruction* I = &*It;
				// Don't insert after terminators
				if (I->isTerminator())
					break;
				// Don't insert before PHIs, landingpads
				if (isa<PHINode>(I) || isa<LandingPadInst>(I))
					continue;
				InsertPts.push_back(I);
			}
		}

		if (InsertPts.empty())
			return 0;

		// Randomize order for deterministic-but-varied placement
		Ctx.ShuffleRng.shuffle(
			MutableArrayRef<Instruction*>(InsertPts.data(), InsertPts.size()));

		unsigned Inserted = 0;
		for (Instruction* IP : InsertPts) {
			if (Inserted >= Budget)
				break;
			if (Ctx.SelectRng.range(100) >= (uint32_t)Ctx.Cfg.prob)
				continue;

			unsigned Variant = Ctx.GadgetRng.range(NumGadgets);
			InlineAsm* IA = InlineAsm::get(
				VoidFnTy, Gadgets[Variant], Clobbers,
				/*hasSideEffects=*/true, /*isAlignStack=*/false);

			CallInst::Create(IA, {}, "", IP);

			++Inserted;
			++ADecAsmGadgets;
		}

		return Inserted;
	}


	// ============================================================================
	// Technique 2: IndirectBr Trampolines
	//
	// Replace:  br label %target
	// With:     %slot = alloca ptr (entry)
	//           store volatile ptr blockaddress(@F, %target), ptr %slot
	//           %addr = load volatile ptr, ptr %slot
	//           indirectbr ptr %addr, [label %target, label %decoy1, ...]
	//
	// Decompilers cannot resolve the volatile-loaded address statically,
	// destroying CFG reconstruction.  Decoy destinations in the successor
	// list force conservative analysis to consider all targets.
	// ============================================================================
	unsigned ADecImpl::emitIndirectBrTrampolines(ADecCtx& Ctx, unsigned Budget) {
		if (!Ctx.Cfg.enableIndirectBr)
			return 0;

		// Collect candidate unconditional branches
		SmallVector<BranchInst*, 32> Cands;
		for (BasicBlock& BB : Ctx.F) {
			auto* BI = dyn_cast<BranchInst>(BB.getTerminator());
			if (canConvertBranch(BI))
				Cands.push_back(BI);
		}

		if (Cands.empty())
			return 0;

		Ctx.ShuffleRng.shuffle(
			MutableArrayRef<BranchInst*>(Cands.data(), Cands.size()));

		// Collect possible decoy targets (blocks without PHIs for simplicity)
		SmallVector<BasicBlock*, 16> DecoyPool;
		for (BasicBlock& BB : Ctx.F) {
			// FIX: Never allow the entry block to be a decoy target.
			// Branching to the entry block creates a predecessor, which is illegal in LLVM.
			if (&BB == &Ctx.F.getEntryBlock())
				continue;

			if (!BB.isEHPad() && !blockHasPhis(&BB))
				DecoyPool.push_back(&BB);
		}

		LLVMContext& C = Ctx.F.getContext();
		BasicBlock& Entry = Ctx.F.getEntryBlock();
		Type* PtrTy = PointerType::getUnqual(C);

		unsigned Converted = 0;
		for (BranchInst* BI : Cands) {
			if (Converted >= Budget)
				break;
			if (Ctx.SelectRng.range(100) >= (uint32_t)Ctx.Cfg.prob)
				continue;

			BasicBlock* Target = BI->getSuccessor(0);
			BasicBlock* SrcBB = BI->getParent();

			// Create volatile alloca in entry block
			IRBuilder<> EntryB(&*Entry.getFirstInsertionPt());
			AllocaInst* Slot = EntryB.CreateAlloca(PtrTy, nullptr, "adec.ibr.slot");

			// Store blockaddress to slot just before the branch
			IRBuilder<> B(BI);
			Value* BA = BlockAddress::get(&Ctx.F, Target);
			auto* St = B.CreateStore(BA, Slot);
			St->setVolatile(true);

			// Load address from volatile slot
			auto* Ld = B.CreateLoad(PtrTy, Slot, "adec.ibr.addr");
			Ld->setVolatile(true);

			// Build indirectbr with real target + up to 3 decoys
			unsigned NumDecoys = std::min<unsigned>(
				3u, (unsigned)DecoyPool.size());
			auto* IBr = IndirectBrInst::Create(Ld, 1 + NumDecoys, BI);
			IBr->addDestination(Target);

			// Add decoy destinations
			unsigned Added = 0;
			for (unsigned i = 0; i < DecoyPool.size() && Added < NumDecoys; ++i) {
				unsigned Pick = Ctx.GadgetRng.range((uint32_t)DecoyPool.size());
				BasicBlock* Decoy = DecoyPool[Pick];
				if (Decoy == Target || Decoy == SrcBB)
					continue;
				// Verify decoy has no PHIs (we checked, but be safe)
				if (blockHasPhis(Decoy))
					continue;
				IBr->addDestination(Decoy);
				++Added;
			}

			// Remove original branch
			BI->eraseFromParent();

			++Converted;
			++ADecIndirectBrs;
		}

		return Converted;
	}


	// ============================================================================
	// Technique 3: Opaque-Predicate Dead-Code Decoys
	//
	// Before a selected block, insert:
	//   br i1 <opaque_true>, label %real, label %dead
	//
	// The %dead block contains type-confusing IR that pollutes decompiler output:
	// - int* float casts (confuses type recovery)
	// - volatile stores to fresh allocas (confuses stack-frame analysis)
	// - bitwise mixing chains (generates phantom "variables")
	//
	// The opaque predicate is volatile-anchored so LLVM cannot fold it.
	// ============================================================================
	unsigned ADecImpl::emitDeadCodeDecoys(ADecCtx& Ctx, unsigned Budget) {
		if (!Ctx.Cfg.enableDeadCodeDecoys)
			return 0;

		// Collect blocks (skip entry, EH pads, EH regions, invoke-terminated)
		SmallVector<BasicBlock*, 32> Blocks;
		for (BasicBlock& BB : Ctx.F) {
			if (&BB == &Ctx.F.getEntryBlock())
				continue;
			if (BB.isEHPad())
				continue;
			// Skip blocks in EH regions — inserting decoy blocks could
			// confuse EH personality routines and create unexpected
			// predecessors for cleanup/catch blocks.
			if (llvm::obf::isInEHRegion(&BB))
				continue;
			// Skip invoke-terminated blocks — splitBasicBlock before an invoke
			// would create a new predecessor for the invoke's normal dest
			// without updating PHIs.
			if (isa<InvokeInst>(BB.getTerminator()))
				continue;
			if (BB.size() < 2) // need at least a non-phi + terminator
				continue;
			Blocks.push_back(&BB);
		}

		if (Blocks.empty())
			return 0;

		Ctx.ShuffleRng.shuffle(
			MutableArrayRef<BasicBlock*>(Blocks.data(), Blocks.size()));

		LLVMContext& C = Ctx.F.getContext();
		unsigned Injected = 0;

		for (BasicBlock* BB : Blocks) {
			if (Injected >= Budget)
				break;
			if (Ctx.SelectRng.range(100) >= (uint32_t)Ctx.Cfg.prob)
				continue;

			// Find split point: after PHIs and allocas
			auto SplitIt = BB->getFirstNonPHIOrDbgOrLifetime();
			while (SplitIt != BB->end() && isa<AllocaInst>(&*SplitIt))
				++SplitIt;
			// FIX: Skip if we've reached the end OR if we're at the terminator
			// Splitting at the terminator creates degenerate blocks and crashes
			if (SplitIt == BB->end() || SplitIt->isTerminator())
				continue;

			// Split the block
			BasicBlock* RealBB = BB->splitBasicBlock(SplitIt, "adec.real");

			// Create dead-code block
			BasicBlock* DeadBB =
				BasicBlock::Create(C, "adec.dead", &Ctx.F, RealBB);

			// Remove auto-inserted unconditional branch from split
			BB->getTerminator()->eraseFromParent();

			// Insert opaque conditional: always-true → real, false → dead
			IRBuilder<> B(BB);
			Value* OpaqueTrue = Ctx.Opaque.enhancedTrue(B, Ctx.Cfg.strength);
			B.CreateCondBr(OpaqueTrue, RealBB, DeadBB);

			// Populate dead block with type-confusing IR
			buildDecoyBlock(Ctx, DeadBB, RealBB);

			++Injected;
			++ADecDeadDecoys;
		}

		return Injected;
	}


	/// Fill a dead-code block with IR patterns that corrupt decompiler output.
	void ADecImpl::buildDecoyBlock(ADecCtx& Ctx, BasicBlock* DeadBB,
		BasicBlock* MergeBB) {
		LLVMContext& C = DeadBB->getContext();
		IRBuilder<>  B(DeadBB);

		Type* I32 = Type::getInt32Ty(C);
		Type* I64 = Type::getInt64Ty(C);
		Type* DblTy = Type::getDoubleTy(C);
		Type* FltTy = Type::getFloatTy(C);
		Type* I8Ty = Type::getInt8Ty(C);
		Type* I8ArrTy = ArrayType::get(I8Ty, 24);

		// --- Fake alloca cluster (confuses stack frame recovery) ---
		AllocaInst* FakeI32 = B.CreateAlloca(I32, nullptr, "adec.dk.i");
		AllocaInst* FakeDbl = B.CreateAlloca(DblTy, nullptr, "adec.dk.d");
		AllocaInst* FakeArr = B.CreateAlloca(I8ArrTy, nullptr, "adec.dk.a");

		// --- Phase 1: integer operations with volatile store ---
		uint32_t K0 = Ctx.DecoyRng.u32();
		uint32_t K1 = Ctx.DecoyRng.u32();
		auto* StI = B.CreateStore(ConstantInt::get(I32, K0), FakeI32);
		StI->setVolatile(true);
		Value* Ld1 = B.CreateLoad(I32, FakeI32, "adec.dk.v1");
		cast<LoadInst>(Ld1)->setVolatile(true);

		// Mixing chain: looks like meaningful computation to decompiler
		Value* Mix1 = B.CreateXor(Ld1, ConstantInt::get(I32, K1), "adec.dk.x1");
		Value* Mix2 = B.CreateMul(Mix1, ConstantInt::get(I32, 0x9e3779b1u),
			"adec.dk.m1");
		Value* Mix3 = B.CreateLShr(Mix2, ConstantInt::get(I32, 7), "adec.dk.s1");
		Value* Mix4 = B.CreateXor(Mix2, Mix3, "adec.dk.x2");

		// --- Phase 2: type confusion (int → float) ---
		Value* AsFloat = B.CreateSIToFP(Mix4, DblTy, "adec.dk.f1");
		auto* StD = B.CreateStore(AsFloat, FakeDbl);
		StD->setVolatile(true);

		Value* LdD = B.CreateLoad(DblTy, FakeDbl, "adec.dk.df");
		cast<LoadInst>(LdD)->setVolatile(true);

		// float → int cross-cast (confuses type inference badly)
		Value* FTrunc = B.CreateFPToUI(LdD, I32, "adec.dk.fti");
		auto* StI2 = B.CreateStore(FTrunc, FakeI32);
		StI2->setVolatile(true);

		// --- Phase 3: array access pattern (looks like string/buffer op) ---
		// FIX: Use GEP directly without unnecessary bitcast (opaque pointer mode)
		Value* ArrGEP0 = B.CreateConstInBoundsGEP2_32(I8ArrTy, FakeArr, 0, 0,
			"adec.dk.g0");
		uint8_t Bytes[4];
		for (int i = 0; i < 4; ++i)
			Bytes[i] = (uint8_t)Ctx.DecoyRng.range(128);
		for (int i = 0; i < 4; ++i) {
			Value* GEP = B.CreateConstInBoundsGEP1_32(I8Ty, ArrGEP0, i,
				"adec.dk.p");
			auto* St = B.CreateStore(ConstantInt::get(I8Ty, Bytes[i]), GEP);
			St->setVolatile(true);
		}

		// --- Phase 4 (strength ≥ 2): additional float arithmetic decoy ---
		if (Ctx.Cfg.strength >= 2) {
			Value* FConv = B.CreateUIToFP(Mix4, FltTy, "adec.dk.fc");
			Value* FMul = B.CreateFMul(FConv,
				ConstantFP::get(FltTy, 3.14159), "adec.dk.fm");
			Value* FAdd = B.CreateFAdd(FMul,
				ConstantFP::get(FltTy, 2.71828), "adec.dk.fa");
			(void)FAdd; // result unused — decompiler still tracks it

			// 64-bit integer chain (looks like pointer/address calculation)
			Value* Wide = B.CreateZExt(Mix4, I64, "adec.dk.w");
			Value* Shl = B.CreateShl(Wide, ConstantInt::get(I64, 32), "adec.dk.wsh");
			Value* Or = B.CreateOr(Wide, Shl, "adec.dk.wor");
			// FIX: Use GEP to get i64* view of array instead of bitcast
			// In opaque pointer mode, we can store i64 directly to the array pointer
			// after using a GEP to get the correct offset
			AllocaInst * FakeI64 = B.CreateAlloca(I64, nullptr, "adec.dk.i64");
			auto* St64 = B.CreateStore(Or, FakeI64);
			St64->setVolatile(true);
		}

		// Terminate: branch to merge (making this reachable from CFG perspective)
		B.CreateBr(MergeBB);
	}


	// ============================================================================
	// Technique 4: Stack-Frame Pollution
	//
	// Create a cluster of fake allocas in the entry block with volatile stores.
	// Decompilers see these as local variables and include them in their output,
	// diluting the real variables with phantom ones.
	// ============================================================================
	void ADecImpl::emitStackPollution(ADecCtx& Ctx) {
		if (!Ctx.Cfg.enableStackPollution)
			return;

		LLVMContext& C = Ctx.F.getContext();
		BasicBlock& Entry = Ctx.F.getEntryBlock();
		IRBuilder<> B(&*Entry.getFirstInsertionPt());

		Type* I32 = Type::getInt32Ty(C);
		Type* I64 = Type::getInt64Ty(C);
		Type* DblTy = Type::getDoubleTy(C);
		Type* I8Ty = Type::getInt8Ty(C);
		Type* I8Arr = ArrayType::get(I8Ty, 16);

		// Number of fake slots scales with strength
		unsigned NumSlots = 2 + Ctx.Cfg.strength;

		struct SlotSpec { Type* Ty; const char* Name; };
		SmallVector<SlotSpec, 8> Specs;
		Specs.push_back({ I32,   "adec.stk.i32" });
		Specs.push_back({ I64,   "adec.stk.i64" });
		Specs.push_back({ DblTy, "adec.stk.dbl" });
		Specs.push_back({ I8Arr, "adec.stk.buf" });
		Specs.push_back({ I32,   "adec.stk.cnt" });
		Specs.push_back({ I64,   "adec.stk.ptr" });

		for (unsigned i = 0; i < NumSlots && i < Specs.size(); ++i) {
			AllocaInst* AI = B.CreateAlloca(Specs[i].Ty, nullptr, Specs[i].Name);
			AI->setAlignment(Align(8));

			// Write a volatile value (entropy-mixed constant)
			uint64_t Val = Ctx.StackRng.u64();
			Value* InitVal;
			if (Specs[i].Ty == DblTy)
				InitVal = ConstantFP::get(DblTy, (double)(Val & 0xFFFF));
			else if (Specs[i].Ty == I8Arr) {
				// FIX: Store to array using GEP instead of bitcast (opaque pointer mode)
				// Get pointer to first element, then store i64 there
				AllocaInst * StoreSlot = B.CreateAlloca(I64, nullptr, "adec.stk.i64");
				auto* St = B.CreateStore(ConstantInt::get(I64, Val), StoreSlot);
				St->setVolatile(true);
				++ADecStackSlots;
				continue;
			}
			else {
				InitVal = ConstantInt::get(Specs[i].Ty, Val);
			}

			auto* St = B.CreateStore(InitVal, AI);
			St->setVolatile(true);

			// For strength ≥ 2, add a volatile read-back (prevents dead store elim)
			if (Ctx.Cfg.strength >= 2) {
				auto* Rd = B.CreateLoad(Specs[i].Ty, AI, "adec.stk.rd");
				Rd->setVolatile(true);
			}

			++ADecStackSlots;
		}
	}


	// ============================================================================
	// Technique 5: Indirect-Call Trampolines
	//
	// Replace:   %r = call @target(args...)
	// With:      %slot = alloca ptr
	//            store volatile ptr @target, ptr %slot
	//            %fp = load volatile ptr, ptr %slot
	//            %r = call ptr %fp(args...)
	//
	// Decompilers cannot resolve the function pointer through volatile, so
	// cross-references and call-graph edges are destroyed.
	// ============================================================================
	unsigned ADecImpl::emitCallTrampolines(ADecCtx& Ctx, unsigned Budget) {
		if (!Ctx.Cfg.enableCallObfuscation)
			return 0;

		SmallVector<CallInst*, 32> Cands;
		for (BasicBlock& BB : Ctx.F) {
			if (BB.isEHPad())
				continue;
			for (Instruction& I : BB) {
				if (auto* CI = dyn_cast<CallInst>(&I)) {
					if (canConvertCall(CI))
						Cands.push_back(CI);
				}
			}
		}

		if (Cands.empty())
			return 0;

		Ctx.ShuffleRng.shuffle(
			MutableArrayRef<CallInst*>(Cands.data(), Cands.size()));

		LLVMContext& C = Ctx.F.getContext();
		BasicBlock& Entry = Ctx.F.getEntryBlock();
		Type* PtrTy = PointerType::getUnqual(C);

		unsigned Converted = 0;
		for (CallInst* CI : Cands) {
			if (Converted >= Budget)
				break;
			if (Ctx.SelectRng.range(100) >= (uint32_t)Ctx.Cfg.prob)
				continue;

			Function* Callee = CI->getCalledFunction();
			if (!Callee)
				continue;

			// Create volatile function pointer slot in entry
			IRBuilder<> EntryB(&*Entry.getFirstInsertionPt());
			AllocaInst* FpSlot = EntryB.CreateAlloca(PtrTy, nullptr,
				"adec.fp.slot");

			// Store function pointer to slot before the call
			IRBuilder<> B(CI);
			auto* St = B.CreateStore(Callee, FpSlot);
			St->setVolatile(true);

			// Load function pointer from volatile slot
			auto* Fp = B.CreateLoad(PtrTy, FpSlot, "adec.fp.addr");
			Fp->setVolatile(true);

			// Build the indirect call with same args and attributes
			SmallVector<Value*, 8> Args;
			for (unsigned i = 0; i < CI->arg_size(); ++i)
				Args.push_back(CI->getArgOperand(i));

			CallInst* NewCI = B.CreateCall(CI->getFunctionType(), Fp, Args);
			NewCI->setCallingConv(CI->getCallingConv());
			NewCI->setAttributes(CI->getAttributes());

			if (!CI->getType()->isVoidTy()) {
				CI->replaceAllUsesWith(NewCI);
				NewCI->takeName(CI);
			}

			CI->eraseFromParent();

			++Converted;
			++ADecIndirectCalls;
		}

		return Converted;
	}


	// ============================================================================
	// Technique 6: Pointer-Alias Confusion
	//
	// For selected store instructions, create an aliased pointer through:
	//   %raw  = ptrtoint ptr %p to i64
	//   %zero = <volatile-anchored runtime zero>
	//   %raw2 = add i64 %raw, %zero
	//   %p2   = inttoptr i64 %raw2 to ptr
	//   store <val>, ptr %p2    (replaces: store <val>, ptr %p)
	//
	// Decompilers see p2 as a different pointer (can't prove p==p2 through
	// volatile + ptrtoint chain), generating duplicate variable assignments
	// and corrupting data-flow analysis.
	// ============================================================================
	unsigned ADecImpl::emitAliasConfusion(ADecCtx& Ctx, unsigned Budget) {
		if (!Ctx.Cfg.enableAliasConfusion)
			return 0;

		// Collect candidate store instructions to non-volatile, non-atomic stores
		SmallVector<StoreInst*, 32> Cands;
		for (BasicBlock& BB : Ctx.F) {
			if (BB.isEHPad() || &BB == &Ctx.F.getEntryBlock())
				continue;
			for (Instruction& I : BB) {
				auto* SI = dyn_cast<StoreInst>(&I);
				if (!SI || SI->isVolatile() || SI->isAtomic())
					continue;
				// Only handle stores to allocas (local variables)
				if (!isa<AllocaInst>(SI->getPointerOperand()))
					continue;
				// Only handle integer/float stores (skip aggregates)
				Type* ValTy = SI->getValueOperand()->getType();
				if (!ValTy->isIntegerTy() && !ValTy->isFloatingPointTy())
					continue;
				Cands.push_back(SI);
			}
		}

		if (Cands.empty())
			return 0;

		Ctx.ShuffleRng.shuffle(
			MutableArrayRef<StoreInst*>(Cands.data(), Cands.size()));

		LLVMContext& C = Ctx.F.getContext();
		Type* I64 = Type::getInt64Ty(C);

		// We need a volatile slot for the runtime-zero value
		AllocaInst* ZeroSlot = llvm::obf::getOrCreateVolatileI32Slot(
			Ctx.F, "adec.alias.slot", Ctx.AliasRng);

		unsigned Confused = 0;
		for (StoreInst* SI : Cands) {
			if (Confused >= Budget)
				break;
			if (Ctx.SelectRng.range(100) >= (uint32_t)Ctx.Cfg.prob)
				continue;

			Value* OrigPtr = SI->getPointerOperand();
			IRBuilder<> B(SI);

			// ptrtoint → add volatile_zero → inttoptr
			Value* PtrInt = B.CreatePtrToInt(OrigPtr, I64, "adec.al.p2i");

			// Build a runtime-zero from volatile slot: load XOR load
			Value* RuntimeZero = llvm::obf::makeRuntimeZero(
				B, ZeroSlot, 64, Ctx.AliasRng, "adec.al");

			Value* Shifted = B.CreateAdd(PtrInt, RuntimeZero, "adec.al.add");
			Value* NewPtr = B.CreateIntToPtr(Shifted,
				OrigPtr->getType(), "adec.al.p");

			// Replace the store's pointer operand
			SI->setOperand(1, NewPtr);

			++Confused;
			++ADecAliasPairs;
		}

		return Confused;
	}


	// ============================================================================
	// Main entry point
	// ============================================================================
	bool ADecImpl::run(ADecCtx& Ctx) {




		unsigned TotalBudget = Ctx.Cfg.maxSites;

		// Distribute budget across techniques.
		// Weights reflect cost-effectiveness:
		//   ASM gadgets are cheap (1 insn each, very effective against linear disasm)
		//   IndirectBr is moderate (5 insns, very effective against CFG recovery)
		//   Dead-code decoys are expensive (15+ insns, effective against type recovery)
		//   Call trampolines are moderate (4 insns, effective against xref/callgraph)
		//   Alias confusion is cheap (4 insns, effective against alias analysis)

		// Budget allocation (roughly):
		// 30% ASM gadgets, 20% indirectbr, 20% dead-code, 10% calls, 10% alias
		// Stack pollution always runs (fixed cost, ~4-6 insns)
		unsigned AsmBudget = std::max<unsigned>(1u, TotalBudget * 30 / 100);
		unsigned IbrBudget = std::max<unsigned>(1u, TotalBudget * 20 / 100);
		unsigned DecoyBudget = std::max<unsigned>(1u, TotalBudget * 20 / 100);
		unsigned CallBudget = std::max<unsigned>(1u, TotalBudget * 15 / 100);
		unsigned AliasBudget = std::max<unsigned>(1u, TotalBudget * 15 / 100);

		bool Changed = false;
		unsigned TotalApplied = 0;

		// Phase 0: Stack pollution (always, fixed cost)
		emitStackPollution(Ctx);
		Changed = true;

		// Phase 1: Inline ASM gadgets (most impactful for anti-disassembly)
		unsigned N = emitAsmGadgets(Ctx, AsmBudget);
		TotalApplied += N;
		if (N > 0) Changed = true;

		// Phase 2: IndirectBr trampolines (destroys CFG recovery)
		N = emitIndirectBrTrampolines(Ctx, IbrBudget);
		TotalApplied += N;
		if (N > 0) Changed = true;

		// Phase 3: Call trampolines (destroys xref/callgraph)
		N = emitCallTrampolines(Ctx, CallBudget);
		TotalApplied += N;
		if (N > 0) Changed = true;

		// Phase 4: Pointer-alias confusion (destroys data-flow analysis)
		N = emitAliasConfusion(Ctx, AliasBudget);
		TotalApplied += N;
		if (N > 0) Changed = true;

		// Phase 5: Dead-code decoys (destroys type recovery)
		// Run last because it splits blocks, which could invalidate iterators
		N = emitDeadCodeDecoys(Ctx, DecoyBudget);
		TotalApplied += N;
		if (N > 0) Changed = true;

		if (ObfVerbose) {
			errs() << "[adec] " << Ctx.F.getName()
				<< ": applied " << TotalApplied << " transforms"
				<< " (asm=" << (unsigned)ADecAsmGadgets
				<< " ibr=" << (unsigned)ADecIndirectBrs
				<< " decoy=" << (unsigned)ADecDeadDecoys
				<< " call=" << (unsigned)ADecIndirectCalls
				<< " alias=" << (unsigned)ADecAliasPairs
				<< " stack=" << (unsigned)ADecStackSlots
				<< ")\n";
		}

		return Changed;
	}


} // end anonymous namespace


// ============================================================================
// Pass entry point
// ============================================================================
PreservedAnalyses AntiDecompilerPass::run(Function& F,
	FunctionAnalysisManager& AM) {
	if (F.isDeclaration())
		return PreservedAnalyses::all();

	ADecCtx Ctx(F, AM);
	if (!Ctx.Cfg.enable)
		return PreservedAnalyses::all();

	{
		std::string R;
		raw_string_ostream OS(R);
		if (!ADecImpl::isEligible(Ctx.FOC, &OS)) {
			if (ObfVerbose)
				errs() << "[adec] Skipping " << F.getName()
				<< " (" << OS.str() << ")\n";
			return PreservedAnalyses::all();
		}
	}

	if (ObfVerbose)
		errs() << "[adec] Processing: " << F.getName()
		<< " prob=" << Ctx.Cfg.prob
		<< " strength=" << Ctx.Cfg.strength
		<< " maxSites=" << Ctx.Cfg.maxSites << "\n";

	++ADecFunctions;

	bool Changed = ADecImpl::run(Ctx);

	if (!Changed)
		return PreservedAnalyses::all();

	return PreservedAnalyses::none();
}