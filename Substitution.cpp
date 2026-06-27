#include "llvm/Transforms/Obfuscator/Substitution.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/Utils.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/PassCtx.h"
#include "llvm/Transforms/Obfuscator/FunctionObfContextAnalysis.h"

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

using namespace llvm;

#define DEBUG_TYPE "substitution"

STATISTIC(Add, "Add substituted");
STATISTIC(Sub, "Sub substituted");
STATISTIC(And, "And substituted");
STATISTIC(Or, "Or substituted");
STATISTIC(Xor, "Xor substituted");

namespace {

	struct SubstCtx;
	struct SubstImpl final {
		static AllocaInst* ensureEntropyAllocaAtEntryBegin(Function& F);
		static void emitSubXorMarkerOnce(SubstCtx& Ctx, Instruction* InsertBefore);
		static bool hasPoisonSensitiveFlags(const BinaryOperator& BO);
		static Value* maybeNoise(IRBuilder<>& B, Value* V, SubstCtx& Ctx, StringRef Tag);
		static Value* getNonConstantRand(IRBuilder<>& B, Type* Ty, llvm::obf::Rng& Rng);


		// ============================================================================
		// ADD Substitution Transformations
		// ============================================================================
		static void addNeg(BinaryOperator* BO, SubstCtx& Ctx);
		static void addDoubleNeg(BinaryOperator* BO, SubstCtx& Ctx);
		static void addRand(BinaryOperator* BO, SubstCtx& Ctx);
		static void addRand2(BinaryOperator* BO, SubstCtx& Ctx);

		// ============================================================================
		// SUB Substitution Transformations
		// ============================================================================
		static void subNeg(BinaryOperator* BO, SubstCtx& Ctx);
		static void subRand(BinaryOperator* BO, SubstCtx& Ctx);
		static void subRand2(BinaryOperator* BO, SubstCtx& Ctx);

		// ============================================================================
		// AND Substitution Transformations
		// ============================================================================
		static void andSubstitution(BinaryOperator* BO, SubstCtx& Ctx);
		static void andSubstitutionRand(BinaryOperator* BO, SubstCtx& Ctx);

		// ============================================================================
		// OR Substitution Transformations
		// ============================================================================
		static void orSubstitution(BinaryOperator* BO, SubstCtx& Ctx);
		static void orSubstitutionRand(BinaryOperator* BO, SubstCtx& Ctx);

		// ============================================================================
		// XOR Substitution Transformations
		// ============================================================================
		static void xorSubstitution(BinaryOperator* BO, SubstCtx& Ctx);
		static void xorSubstitutionRand(BinaryOperator* BO, SubstCtx& Ctx);

		// ============================================================================
		// Helper Functions & Dispatch Tables
		// ============================================================================
		static bool shouldSubstitute(Instruction& I);
		static void collectFromBlock(BasicBlock& BB, SmallVectorImpl<BinaryOperator*>& output);
		static void applyRandomSubstitution(SubstCtx& Ctx, BinaryOperator* BO);


		// ============================================================================
		// Configuration
		// ============================================================================
		static SubstitutionConfig getSubConfig(Function& F, FunctionAnalysisManager& AM);

		// ============================================================================
		// Main Transformation Logic
		// ============================================================================
		static bool substitute(SubstCtx& Ctx, int loopCount, unsigned MaxSites);
	};




	struct SubstCtx : llvm::obf::FuncPassCtx {
		SubstitutionConfig Cfg;
		FunctionObfContext& FOC;
		bool MarkerEmitted = false;

		llvm::obf::Rng ChoiceRng; // selects which transform to apply
		llvm::obf::Rng ConstRng;  // random constants mixed with entropy
		llvm::obf::Rng NoiseRng;
		AllocaInst* NoiseSlot = nullptr;

		SubstCtx(Function& F, FunctionAnalysisManager& AM)
			: FuncPassCtx(F, AM, "substitution"),
			Cfg(SubstImpl::getSubConfig(F, AM)),
			FOC(*AM.getResult<FunctionObfContextAnalysis>(F)),
			ChoiceRng(R.fork("choice")),
			ConstRng(R.fork("const")),
			NoiseRng(R.fork("noise")) {
			NoiseSlot = llvm::obf::getOrCreateVolatileI32Slot(F, "obf.sub.noise.i32", NoiseRng);
		}
	};



	AllocaInst* SubstImpl::ensureEntropyAllocaAtEntryBegin(Function& F) {
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

		// Insert/move it to the earliest legal point (after PHIs; entry usually has none).
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
			// Force it to dominate *everything* (including early entry instrumentation).
			Entropy->moveBefore(InsertBefore);
		}

		return Entropy;
	}



	void SubstImpl::emitSubXorMarkerOnce(SubstCtx& Ctx, Instruction* InsertBefore) {
		if (Ctx.MarkerEmitted || !InsertBefore)
			return;

		IRBuilder<> B(InsertBefore);
		Value* E32 = llvm::obf::getObfEntropyI32(B);

		// Fixed non-zero constant: avoids shifting RNG streams, avoids constant-folding.
		auto* I32 = Type::getInt32Ty(B.getContext());
		Value* K = ConstantInt::get(I32, 0x9e3779b1u);
		Value* X = B.CreateXor(E32, K, "sub.xor");
		(void)B.CreateFreeze(X, "sub.xor.fr");

		Ctx.MarkerEmitted = true;

	}

	bool SubstImpl::hasPoisonSensitiveFlags(const BinaryOperator& BO)
	{
		switch (BO.getOpcode())
		{
		case Instruction::Add:
		case Instruction::Sub:
			return BO.hasNoSignedWrap() || BO.hasNoUnsignedWrap();
		default:
			return false;
		}
	}


	Value* SubstImpl::maybeNoise(IRBuilder<>& B, Value* V, SubstCtx& Ctx, StringRef Tag)
	{
		// 50% default; tweak later if perf/size is to heavy
		return llvm::obf::xorWithRuntimeZero(B, V, Ctx.NoiseSlot, Ctx.NoiseRng, Tag, /*Prob=*/50);
	}

	Value* SubstImpl::getNonConstantRand(IRBuilder<>& B, Type* Ty, llvm::obf::Rng& Rng) {
		if (!Ty || !Ty->isIntegerTy())
			return nullptr;


		Function* F = B.GetInsertBlock() ? B.GetInsertBlock()->getParent() : nullptr;
		if (F)
			(void)ensureEntropyAllocaAtEntryBegin(*F);

		unsigned BW = cast<IntegerType>(Ty)->getBitWidth();
		Value* E32 = llvm::obf::getObfEntropyI32Stable(B);
		Value* E = E32;

		if (BW > 32)
			E = B.CreateZExt(E32, Ty, "sub.ent.zext");
		else if (BW < 32)
			E = B.CreateTrunc(E32, Ty, "sub.ent.trunc");
		else
			E = B.CreateBitCast(E32, Ty);

		// Mix with a random constant, but keep it non-constant overall.
		// Mask to BW bits so APInt ctor does not assert on i1/i8/i16/i32.
		uint64_t C = Rng.u64();
		if (BW < 64)
			C &= (uint64_t(1) << BW) - 1;
		Value* K = ConstantInt::get(Ty, C);
		Value* X = B.CreateXor(E, K, "sub.rand");
		return B.CreateFreeze(X, "sub.rand.fr");
	}


	// ============================================================================
	// ADD Substitution Transformations
	// ============================================================================

	// Transform: a = b + c  =>  a = b - (-c)
	void SubstImpl::addNeg(BinaryOperator* BO, SubstCtx& Ctx) {
		IRBuilder<> builder(BO);
		Value* negC = builder.CreateNeg(BO->getOperand(1), "sub.neg");
		Value* result = builder.CreateSub(BO->getOperand(0), negC, "sub.result");

		result = maybeNoise(builder, result, Ctx, "sub.addNeg");

		BO->replaceAllUsesWith(result);
	}

	// Transform: a = b + c  =>  a = -(-b + (-c))
	void SubstImpl::addDoubleNeg(BinaryOperator* BO, SubstCtx& Ctx) {
		IRBuilder<> builder(BO);
		Value* negB = builder.CreateNeg(BO->getOperand(0), "sub.negb");
		Value* negC = builder.CreateNeg(BO->getOperand(1), "sub.negc");
		Value* add = builder.CreateAdd(negB, negC, "sub.add");
		Value* result = builder.CreateNeg(add, "sub.doubleneg");

		result = maybeNoise(builder, result, Ctx, "sub.addDoubleNeg");

		BO->replaceAllUsesWith(result);
	}

	// Transform: a = b + c  =>  r = rand(); a = (b + r) + c - r
	void SubstImpl::addRand(BinaryOperator* BO, SubstCtx& Ctx) {
		IRBuilder<> builder(BO);

		Type* Ty = BO->getType();
		Value* randVal = getNonConstantRand(builder, Ty, Ctx.ConstRng);
		if (!randVal) return;

		Value* addR = builder.CreateAdd(BO->getOperand(0), randVal, "sub.addr");
		Value* addC = builder.CreateAdd(addR, BO->getOperand(1), "sub.addc");
		Value* result = builder.CreateSub(addC, randVal, "sub.subr");

		result = maybeNoise(builder, result, Ctx, "sub.addRand");

		BO->replaceAllUsesWith(result);
	}

	// Transform: a = b + c  =>  r = rand(); a = (b - r) + c + r
	void SubstImpl::addRand2(BinaryOperator* BO, SubstCtx& Ctx) {
		IRBuilder<> builder(BO);
		Type* ty = BO->getType();

		Value* randVal = getNonConstantRand(builder, ty, Ctx.ConstRng);
		if (!randVal)
			return;

		Value* subR = builder.CreateSub(BO->getOperand(0), randVal, "sub.subr");
		Value* addC = builder.CreateAdd(subR, BO->getOperand(1), "sub.addc");
		Value* result = builder.CreateAdd(addC, randVal, "sub.addr");

		result = maybeNoise(builder, result, Ctx, "sub.addRand2");

		BO->replaceAllUsesWith(result);
	}

	// ============================================================================
	// SUB Substitution Transformations
	// ============================================================================

	// Transform: a = b - c  =>  a = b + (-c)
	void SubstImpl::subNeg(BinaryOperator* BO, SubstCtx& Ctx) {
		IRBuilder<> builder(BO);
		Value* negC = builder.CreateNeg(BO->getOperand(1), "sub.neg");
		Value* result = builder.CreateAdd(BO->getOperand(0), negC, "sub.add");

		result = maybeNoise(builder, result, Ctx, "sub.subNeg");

		BO->replaceAllUsesWith(result);
	}

	// Transform: a = b - c  =>  r = rand(); a = (b + r) - c - r
	void SubstImpl::subRand(BinaryOperator* BO, SubstCtx& Ctx) {
		IRBuilder<> builder(BO);
		Type* ty = BO->getType();

		Value* randVal = getNonConstantRand(builder, ty, Ctx.ConstRng);
		if (!randVal)
			return;

		Value* addR = builder.CreateAdd(BO->getOperand(0), randVal, "sub.addr");
		Value* subC = builder.CreateSub(addR, BO->getOperand(1), "sub.subc");
		Value* result = builder.CreateSub(subC, randVal, "sub.subr");

		result = maybeNoise(builder, result, Ctx, "sub.subRand");

		BO->replaceAllUsesWith(result);
	}

	// Transform: a = b - c  =>  r = rand(); a = (b - r) - c + r
	void SubstImpl::subRand2(BinaryOperator* BO, SubstCtx& Ctx) {
		IRBuilder<> builder(BO);
		Type* ty = BO->getType();

		Value* randVal = getNonConstantRand(builder, ty, Ctx.ConstRng);
		if (!randVal)
			return;

		Value* subR = builder.CreateSub(BO->getOperand(0), randVal, "sub.subr");
		Value* subC = builder.CreateSub(subR, BO->getOperand(1), "sub.subc");
		Value* result = builder.CreateAdd(subC, randVal, "sub.addr");

		result = maybeNoise(builder, result, Ctx, "sub.subRand2");

		BO->replaceAllUsesWith(result);
	}

	// ============================================================================
	// AND Substitution Transformations
	// ============================================================================

	// Transform: a = b & c  =>  a = (b ^ ~c) & b
	void SubstImpl::andSubstitution(BinaryOperator* BO, SubstCtx& Ctx) {
		IRBuilder<> builder(BO);
		Value* notC = builder.CreateNot(BO->getOperand(1), "sub.not");
		Value* xorOp = builder.CreateXor(BO->getOperand(0), notC, "sub.xor");
		Value* result = builder.CreateAnd(xorOp, BO->getOperand(0), "sub.and");

		result = maybeNoise(builder, result, Ctx, "sub.and");

		BO->replaceAllUsesWith(result);
	}

	// Transform: a = b & c  =>  a = !(!b | !c) & (r | !r)
	void SubstImpl::andSubstitutionRand(BinaryOperator* BO, SubstCtx& Ctx) {
		IRBuilder<> builder(BO);
		Type* ty = BO->getType();

		//Constant* randVal = ConstantInt::get(ty, getCryptoUtils().get_uint64_t());
		Value* randVal = getNonConstantRand(builder, ty, Ctx.ConstRng);
		if (!randVal)
			return;

		Value* notB = builder.CreateNot(BO->getOperand(0), "sub.notb");
		Value* notC = builder.CreateNot(BO->getOperand(1), "sub.notc");
		Value* notR = builder.CreateNot(randVal, "sub.notr");

		Value* orBC = builder.CreateOr(notB, notC, "sub.or1");
		Value* orR = builder.CreateOr(randVal, notR, "sub.or2");

		Value* notOr = builder.CreateNot(orBC, "sub.notor");
		Value* result = builder.CreateAnd(notOr, orR, "sub.and");

		result = maybeNoise(builder, result, Ctx, "sub.and");

		BO->replaceAllUsesWith(result);
	}

	// ============================================================================
	// OR Substitution Transformations
	// ============================================================================

	// Transform: a = b | c  =>  a = (b & c) | (b ^ c)
	void SubstImpl::orSubstitution(BinaryOperator* BO, SubstCtx& Ctx) {
		IRBuilder<> builder(BO);
		Value* andOp =
			builder.CreateAnd(BO->getOperand(0), BO->getOperand(1), "sub.and");
		Value* xorOp =
			builder.CreateXor(BO->getOperand(0), BO->getOperand(1), "sub.xor");
		Value* result = builder.CreateOr(andOp, xorOp, "sub.or");

		result = maybeNoise(builder, result, Ctx, "sub.or");

		BO->replaceAllUsesWith(result);
	}

	// Transform: a = b | c  =>  complex random-based transformation
	void SubstImpl::orSubstitutionRand(BinaryOperator* BO, SubstCtx& Ctx) {
		IRBuilder<> builder(BO);
		Type* ty = BO->getType();

		//Constant* randVal = ConstantInt::get(ty, getCryptoUtils().get_uint64_t());
		Value* randVal = getNonConstantRand(builder, ty, Ctx.ConstRng);
		if (!randVal)
			return;

		Value* notB = builder.CreateNot(BO->getOperand(0), "sub.notb");
		Value* notC = builder.CreateNot(BO->getOperand(1), "sub.notc");
		Value* notR = builder.CreateNot(randVal, "sub.notr");

		// (!b & r) | (b & !r)
		Value* and1 = builder.CreateAnd(notB, randVal, "sub.and1");
		Value* and2 = builder.CreateAnd(BO->getOperand(0), notR, "sub.and2");
		Value* or1 = builder.CreateOr(and1, and2, "sub.or1");

		// (!c & r) | (c & !r)
		Value* and3 = builder.CreateAnd(notC, randVal, "sub.and3");
		Value* and4 = builder.CreateAnd(BO->getOperand(1), notR, "sub.and4");
		Value* or2 = builder.CreateOr(and3, and4, "sub.or2");

		// XOR the two parts
		Value* xorPart = builder.CreateXor(or1, or2, "sub.xor");

		// !(!b | !c) & (r | !r)
		Value* orBC = builder.CreateOr(notB, notC, "sub.or3");
		Value* notOr = builder.CreateNot(orBC, "sub.notor");
		Value* orR = builder.CreateOr(randVal, notR, "sub.or4");
		Value* andPart = builder.CreateAnd(notOr, orR, "sub.and5");

		Value* result = builder.CreateOr(xorPart, andPart, "sub.or.final");

		result = maybeNoise(builder, result, Ctx, "sub.or.final");

		BO->replaceAllUsesWith(result);
	}

	// ============================================================================
	// XOR Substitution Transformations
	// ============================================================================

	// Transform: a = b ^ c  =>  a = (!b & c) | (b & !c)
	void SubstImpl::xorSubstitution(BinaryOperator* BO, SubstCtx& Ctx) {
		IRBuilder<> builder(BO);
		Value* notB = builder.CreateNot(BO->getOperand(0), "sub.notb");
		Value* notC = builder.CreateNot(BO->getOperand(1), "sub.notc");

		Value* and1 = builder.CreateAnd(notB, BO->getOperand(1), "sub.and1");
		Value* and2 = builder.CreateAnd(BO->getOperand(0), notC, "sub.and2");
		Value* result = builder.CreateOr(and1, and2, "sub.xor");

		result = maybeNoise(builder, result, Ctx, "sub.xor");

		BO->replaceAllUsesWith(result);
	}

	// Transform: a = b ^ c  =>  a = (!b & r | b & !r) ^ (!c & r | c & !r)
	void SubstImpl::xorSubstitutionRand(BinaryOperator* BO, SubstCtx& Ctx) {
		IRBuilder<> builder(BO);
		Type* ty = BO->getType();

		//Constant* randVal = ConstantInt::get(ty, getCryptoUtils().get_uint64_t());
		Value* randVal = getNonConstantRand(builder, ty, Ctx.ConstRng);
		if (!randVal) return;

		Value* notB = builder.CreateNot(BO->getOperand(0), "sub.notb");
		Value* notC = builder.CreateNot(BO->getOperand(1), "sub.notc");
		Value* notR = builder.CreateNot(randVal, "sub.notr");

		// (!b & r) | (b & !r)
		Value* and1 = builder.CreateAnd(notB, randVal, "sub.and1");
		Value* and2 = builder.CreateAnd(BO->getOperand(0), notR, "sub.and2");
		Value* or1 = builder.CreateOr(and1, and2, "sub.or1");

		// (!c & r) | (c & !r)
		Value* and3 = builder.CreateAnd(notC, randVal, "sub.and3");
		Value* and4 = builder.CreateAnd(BO->getOperand(1), notR, "sub.and4");
		Value* or2 = builder.CreateOr(and3, and4, "sub.or2");

		Value* result = builder.CreateXor(or1, or2, "sub.xor");


		result = maybeNoise(builder, result, Ctx, "sub.xor");
		BO->replaceAllUsesWith(result);
	}

	// ============================================================================
	// Helper Functions & Dispatch Tables
	// ============================================================================

	using SubstFunc = void (*)(BinaryOperator*, SubstCtx&);

	constexpr std::array<SubstFunc, 4> ADD_TRANSFORMS = {
	  SubstImpl::addNeg, SubstImpl::addDoubleNeg, SubstImpl::addRand, SubstImpl::addRand2
	};

	constexpr std::array<SubstFunc, 3> SUB_TRANSFORMS = {
	  SubstImpl::subNeg, SubstImpl::subRand, SubstImpl::subRand2
	};

	constexpr std::array<SubstFunc, 2> AND_TRANSFORMS = {
	  SubstImpl::andSubstitution, SubstImpl::andSubstitutionRand
	};

	constexpr std::array<SubstFunc, 2> OR_TRANSFORMS = {
	  SubstImpl::orSubstitution, SubstImpl::orSubstitutionRand
	};

	constexpr std::array<SubstFunc, 2> XOR_TRANSFORMS = {
	  SubstImpl::xorSubstitution, SubstImpl::xorSubstitutionRand
	};

	// Check if opcode is a substitution target
	constexpr bool isSubstitutionTarget(unsigned opcode) {
		return opcode == Instruction::Add || opcode == Instruction::Sub ||
			opcode == Instruction::And || opcode == Instruction::Or ||
			opcode == Instruction::Xor;
	}

	// Check if instruction should be substituted
	bool SubstImpl::shouldSubstitute(Instruction& I) {
		auto* BO = dyn_cast<BinaryOperator>(&I);
		if (!BO)
			return false;
		if (BO->hasName() && BO->getName().starts_with("sub."))
			return false;

		if (!BO->getType()->isIntegerTy())
			return false;
		if (!isSubstitutionTarget(BO->getOpcode()))
			return false;
		if (hasPoisonSensitiveFlags(*BO))
			return false;
		// Avoid trivial constant folds.
		if (isa<Constant>(BO->getOperand(0)) && isa<Constant>(BO->getOperand(1)))
			return false;
		return true;
	}

	// Collect substitution candidates from a basic block
	void SubstImpl::collectFromBlock(BasicBlock& BB,
		SmallVectorImpl<BinaryOperator*>& output) {
		for (Instruction& I : BB) {
			if (shouldSubstitute(I)) {
				output.push_back(cast<BinaryOperator>(&I));
			}
		}
	}

	// Apply random substitution based on opcode
	void SubstImpl::applyRandomSubstitution(SubstCtx& Ctx, BinaryOperator* BO) {
		unsigned opcode = BO->getOpcode();

		switch (opcode) {
		case Instruction::Add: {
			size_t idx = (size_t)Ctx.ChoiceRng.range((uint32_t)ADD_TRANSFORMS.size());
			ADD_TRANSFORMS[idx](BO, Ctx);
			++Add;
			break;
		}

		case Instruction::Sub: {
			size_t idx = (size_t)Ctx.ChoiceRng.range((uint32_t)SUB_TRANSFORMS.size());
			SUB_TRANSFORMS[idx](BO, Ctx);
			++Sub;
			break;
		}

		case Instruction::And: {
			size_t idx = (size_t)Ctx.ChoiceRng.range((uint32_t)AND_TRANSFORMS.size());
			AND_TRANSFORMS[idx](BO, Ctx);
			++And;
			break;
		}

		case Instruction::Or: {
			size_t idx = (size_t)Ctx.ChoiceRng.range((uint32_t)OR_TRANSFORMS.size());
			OR_TRANSFORMS[idx](BO, Ctx);
			++Or;
			break;
		}

		case Instruction::Xor: {
			size_t idx = (size_t)Ctx.ChoiceRng.range((uint32_t)XOR_TRANSFORMS.size());
			XOR_TRANSFORMS[idx](BO, Ctx);
			++Xor;
			break;
		}

		default:
			break;
		}
	}

	// ============================================================================
	// Configuration
	// ============================================================================

	SubstitutionConfig SubstImpl::getSubConfig(Function& F, FunctionAnalysisManager& AM) {
		const ObfuscationConfig obfConfig = getObfConfig(F, AM);

		auto subPassConfig = obfConfig.getPassConfig("sub");
		if (!subPassConfig.has_value()) {
			subPassConfig = obfConfig.getPassConfig("substitution");
		}

		if (!subPassConfig.has_value()) {
			SubstitutionConfig cfg;
			cfg.enable = false;
			return cfg;
		}

		SubstitutionConfig cfg = SubstitutionConfig::fromPassConfig(*subPassConfig);

		if (!cfg.validate()) {
			errs() << "Substitution: Invalid configuration for function " << F.getName()
				<< ", disabling pass\n";
			cfg.enable = false;
		}

		return cfg;
	}

	// ============================================================================
	// Main Transformation Logic
	// ============================================================================

	bool SubstImpl::substitute(SubstCtx& Ctx, int loopCount, unsigned MaxSites)
	{
		Function& F = Ctx.F;
		bool modified = false;

		// Budget-aware: each substitution generates ~3-5 new instructions.
		if (Ctx.FOC.BudgetRemaining != UINT_MAX) {
			unsigned budgetSites = std::max(1u, Ctx.FOC.BudgetRemaining / 4);
			if (budgetSites < MaxSites) {
				MaxSites = budgetSites;
				if (ObfVerbose)
					errs() << "[sub] budget-throttled MaxSites to " << MaxSites << "\n";
			}
		}

		unsigned SitesDone = 0;

		for (int iteration = 0; iteration < loopCount; ++iteration) {
			SmallVector<BinaryOperator*, 64> toSubstitute;

			// Collect candidates from all basic blocks
			for (BasicBlock& BB : F) {
				collectFromBlock(BB, toSubstitute);
			}

			if (toSubstitute.empty()) {
				break; // No more candidates to transform
			}

			// Apply substitutions
			for (BinaryOperator* BO : toSubstitute) {
				if (SitesDone >= MaxSites)
					break;


				if (!BO || !BO->getParent())
					continue;

				applyRandomSubstitution(Ctx, BO);

				// If we successfully produced *any* substitution, emit a stable marker
				// once per function so tests can detect the pass in combos.
				emitSubXorMarkerOnce(Ctx, BO);

				// Defensive: never erase if uses remain (prevents hard abort).
				// If this triggers, it means a transform returned early or failed to RAUW.
				if (!BO->use_empty()) {
					errs() << "[Substitution] WARNING: candidate still has uses; skipping erase: "
						<< *BO << "\n";
					continue;

				}

				BO->eraseFromParent();
				modified = true;
				++SitesDone;
			}
		}

		return modified;
	}

} // anonymous namespace

// ============================================================================
// Pass Implementation
// ============================================================================

PreservedAnalyses SubstitutionPass::run(Function& F,
	FunctionAnalysisManager& AM) {


	if (F.isDeclaration())
		return PreservedAnalyses::all();

	SubstCtx Ctx(F, AM);
	if (!Ctx.Cfg.enable) return PreservedAnalyses::all();

	if (Ctx.Cfg.loop <= 0) {
		if (ObfVerbose) {
			errs() << "Substitution: Invalid loop count " << Ctx.Cfg.loop << "\n";
		}
		return PreservedAnalyses::all();
	}

	if (ObfVerbose) {
		errs() << "[Substitution] Processing: " << F.getName() << "\n";
		errs() << "iterations=" << Ctx.Cfg.loop << "\n";
	}

	unsigned Budget = Ctx.Cfg.maxSites;
	if (Budget == 0) {
		// Auto budget: scaled by size, hard cap.
		unsigned Insts = Ctx.FOC.NumInsts;
		Budget = std::min<unsigned>(1500u, std::max<unsigned>(64u, Insts / 2));

	}
	if (ObfVerbose) {
		errs() << "maxSites=" << Budget << "\n";

	}

	bool success = SubstImpl::substitute(Ctx, Ctx.Cfg.loop, Budget);

	if (success) {
		if (ObfVerbose) {
			errs() << "Substituted " << (Add + Sub + And + Or + Xor) << " operations\n";
		}

		PreservedAnalyses PA = PreservedAnalyses::none();
		PA.preserveSet<CFGAnalyses>();
		return PA;
	}
	else
	{
		if (ObfVerbose) {
			errs() << "No substitutions applied\n";
		}
		return PreservedAnalyses::all();
	}


}