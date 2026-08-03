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






// ============================================================================
// Nested-VM
//
// Concept: an eligible opcode's compute step is a call to a pure helper
// function, and that helper is itself virtualized. Executing one outer
// nested-eligible instruction therefore drives a full inner VM dispatch loop
// -- depth-2 interpretation. Eligible opcodes: BINOP, BINOP64, ICMP, ICMP64,
// FCMP, CAST (kNestedHelperOrder below; the nestedVMOpcodes cap -- see
// opcodeNests() -- selects a prefix of this fixed order).
//
// Two engines, not a runtime flag on one: a build with NestedVM=true targets
// EngineId 1 (@__vm_engine.nest), whose nested-eligible handlers call their
// helper. Every helper is always inner-virtualized with nestedVM=false, so it
// targets EngineId 0 (@__vm_engine), whose handlers compute inline. This is
// what makes recursion terminate: a helper's own bytecode may itself contain
// nested-eligible opcodes (its body is a plain switch like any other
// function), but those run through the PLAIN engine, which never calls back
// into a helper. An earlier version of this shared one engine for both layers
// and used the same handler code regardless of which bytecode it was
// interpreting -- that recursed unboundedly (engine -> helper -> engine ->
// helper -> ...) and stack-overflowed at runtime; see EngineId below.
//
// Sequencing (see call sites in run()):
//   1. getOrCreateNestedHelper(Op) runs BEFORE populateVMEngine(), once per
//      eligible Op. It only creates the helper Function with a plain
//      (non-virtualized) switch body -- the opcode's handler case needs the
//      Function* to exist so it can emit a call to it.
//   2. populateVMEngine() builds EngineId 1's (@__vm_engine.nest) handler
//      blocks as normal (first NestedVM function only; independent of, and
//      does not perturb, EngineId 0's SharedState).
//   3. virtualizeNestedHelpersOnce() runs AFTER populateVMEngine(), guarded
//      to run once per module. For every helper Function that was created,
//      this replaces its plain body with a VM wrapper by running a second,
//      independent VMImpl over it with nestedVM=false (so it targets
//      EngineId 0) and a forked RNG.
//
// Step 3 MUST come after step 2: with a single shared engine, inner-
// virtualizing a helper first would make it the one to trigger
// populateVMEngine()'s "first function" build, baking non-nested handler
// bodies in permanently. With two independent EngineId-keyed SharedStates
// this specific failure mode can no longer happen (helpers target id 0,
// outer targets id 1), but the ordering is kept because it's already been
// verified correct and step 3 still depends on nothing from step 2 that
// would change.
// ============================================================================

bool VMImpl::opcodeNests(VMOp Op) const {
	if (!NestedVM) return false;
	for (unsigned i = 0; i < kNumNestedHelpers; ++i) {
		if (kNestedHelperOrder[i].Op == Op)
			return NestedVMOpcodes == 0 || i < NestedVMOpcodes;
	}
	return false;
}


Function* VMImpl::getOrCreateNestedHelper(VMOp Op) {
	switch (Op) {
	case OP_BINOP:   return getOrCreateNestedBinopHelper();
	case OP_BINOP64: return getOrCreateNestedBinop64Helper();
	case OP_ICMP:    return getOrCreateNestedIcmpHelper();
	case OP_ICMP64:  return getOrCreateNestedIcmp64Helper();
	case OP_FCMP:    return getOrCreateNestedFcmpHelper();
	case OP_CAST:    return getOrCreateNestedCastHelper();
	case OP_BINOP_F: return getOrCreateNestedBinopFHelper();
	default:         return nullptr;
	}
}


// Pure helper `i32 __vm_h_binop(i32 a, i32 b, i8 subop)` -- replicates
// OP_BINOP's subop switch (VMPass_Impl.cpp buildHandlersIntArith) exactly,
// including using a switch (not a select chain) so div/rem are never
// speculatively executed for a non-div/rem subop. Idempotent: reused across
// every nested-eligible function in the module.
Function* VMImpl::getOrCreateNestedBinopHelper() {
	if (Function* Existing = M.getFunction(kNestedBinopHelperName))
		return Existing;

	FunctionType* FTy = FunctionType::get(I32Ty, { I32Ty, I32Ty, I8Ty }, false);
	Function* HF = Function::Create(FTy, GlobalValue::InternalLinkage,
		kNestedBinopHelperName, &M);
	HF->addFnAttr(Attribute::NoUnwind);
	Argument* AArg = HF->getArg(0); AArg->setName("a");
	Argument* BArg = HF->getArg(1); BArg->setName("b");
	Argument* SubArg = HF->getArg(2); SubArg->setName("subop");

	BasicBlock* EntryBB = BasicBlock::Create(Ctx, "entry", HF);
	IRBuilder<> B(EntryBB);
	Value* Sub32 = B.CreateZExt(SubArg, I32Ty, "sub32");

	BasicBlock* MergeBB = BasicBlock::Create(Ctx, "merge", HF);
	BasicBlock* DefBB = BasicBlock::Create(Ctx, "def", HF);
	SwitchInst* SW = B.CreateSwitch(Sub32, DefBB, 12);

	IRBuilder<> BM(MergeBB);
	auto* Phi = BM.CreatePHI(I32Ty, 13, "r");
	BM.CreateRet(Phi);

	{
		// Default implements BS_ADD (matches OP_BINOP's fallback).
		IRBuilder<> BD(DefBB);
		Value* Rv = BD.CreateAdd(AArg, BArg, "add");
		Phi->addIncoming(Rv, DefBB);
		BD.CreateBr(MergeBB);
	}

	auto addCase = [&](uint32_t Case, const Twine& Name, auto Emit) {
		BasicBlock* CBB = BasicBlock::Create(Ctx, Name, HF);
		IRBuilder<> BC(CBB);
		Value* Rv = Emit(BC);
		Phi->addIncoming(Rv, CBB);
		BC.CreateBr(MergeBB);
		SW->addCase(B.getInt32(IsaEnc.encBinSubop((uint8_t)Case)), CBB);
		};

	addCase(BS_SUB, "sub", [&](IRBuilder<>& BC) { return BC.CreateSub(AArg, BArg, "sub"); });
	addCase(BS_MUL, "mul", [&](IRBuilder<>& BC) { return BC.CreateMul(AArg, BArg, "mul"); });
	addCase(BS_AND, "and", [&](IRBuilder<>& BC) { return BC.CreateAnd(AArg, BArg, "and"); });
	addCase(BS_OR, "or", [&](IRBuilder<>& BC) { return BC.CreateOr(AArg, BArg, "or"); });
	addCase(BS_XOR, "xor", [&](IRBuilder<>& BC) { return BC.CreateXor(AArg, BArg, "xor"); });
	addCase(BS_SHL, "shl", [&](IRBuilder<>& BC) { return BC.CreateShl(AArg, BArg, "shl"); });
	addCase(BS_LSHR, "lshr", [&](IRBuilder<>& BC) { return BC.CreateLShr(AArg, BArg, "lshr"); });
	addCase(BS_ASHR, "ashr", [&](IRBuilder<>& BC) { return BC.CreateAShr(AArg, BArg, "ashr"); });
	addCase(BS_SDIV, "sdiv", [&](IRBuilder<>& BC) { return BC.CreateSDiv(AArg, BArg, "sdiv"); });
	addCase(BS_UDIV, "udiv", [&](IRBuilder<>& BC) { return BC.CreateUDiv(AArg, BArg, "udiv"); });
	addCase(BS_SREM, "srem", [&](IRBuilder<>& BC) { return BC.CreateSRem(AArg, BArg, "srem"); });
	addCase(BS_UREM, "urem", [&](IRBuilder<>& BC) { return BC.CreateURem(AArg, BArg, "urem"); });

	return HF;
}


// Pure helper `i64 __vm_h_binop64(i64 a, i64 b, i8 subop)` -- replicates
// OP_BINOP64's subop switch (buildHandlersIntArith) exactly, same shape as
// getOrCreateNestedBinopHelper() but over I64Ty operands/result.
Function* VMImpl::getOrCreateNestedBinop64Helper() {
	if (Function* Existing = M.getFunction(kNestedBinop64HelperName))
		return Existing;

	FunctionType* FTy = FunctionType::get(I64Ty, { I64Ty, I64Ty, I8Ty }, false);
	Function* HF = Function::Create(FTy, GlobalValue::InternalLinkage,
		kNestedBinop64HelperName, &M);
	HF->addFnAttr(Attribute::NoUnwind);
	Argument* AArg = HF->getArg(0); AArg->setName("a");
	Argument* BArg = HF->getArg(1); BArg->setName("b");
	Argument* SubArg = HF->getArg(2); SubArg->setName("subop");

	BasicBlock* EntryBB = BasicBlock::Create(Ctx, "entry", HF);
	IRBuilder<> B(EntryBB);
	Value* Sub32 = B.CreateZExt(SubArg, I32Ty, "sub32");

	BasicBlock* MergeBB = BasicBlock::Create(Ctx, "merge", HF);
	BasicBlock* DefBB = BasicBlock::Create(Ctx, "def", HF);
	SwitchInst* SW = B.CreateSwitch(Sub32, DefBB, 12);

	IRBuilder<> BM(MergeBB);
	auto* Phi = BM.CreatePHI(I64Ty, 13, "r");
	BM.CreateRet(Phi);

	{
		// Default implements BS_ADD (matches OP_BINOP64's fallback).
		IRBuilder<> BD(DefBB);
		Value* Rv = BD.CreateAdd(AArg, BArg, "add");
		Phi->addIncoming(Rv, DefBB);
		BD.CreateBr(MergeBB);
	}

	auto addCase = [&](uint32_t Case, const Twine& Name, auto Emit) {
		BasicBlock* CBB = BasicBlock::Create(Ctx, Name, HF);
		IRBuilder<> BC(CBB);
		Value* Rv = Emit(BC);
		Phi->addIncoming(Rv, CBB);
		BC.CreateBr(MergeBB);
		SW->addCase(B.getInt32(IsaEnc.encBinSubop((uint8_t)Case)), CBB);
		};

	addCase(BS_SUB, "sub", [&](IRBuilder<>& BC) { return BC.CreateSub(AArg, BArg, "sub"); });
	addCase(BS_MUL, "mul", [&](IRBuilder<>& BC) { return BC.CreateMul(AArg, BArg, "mul"); });
	addCase(BS_AND, "and", [&](IRBuilder<>& BC) { return BC.CreateAnd(AArg, BArg, "and"); });
	addCase(BS_OR, "or", [&](IRBuilder<>& BC) { return BC.CreateOr(AArg, BArg, "or"); });
	addCase(BS_XOR, "xor", [&](IRBuilder<>& BC) { return BC.CreateXor(AArg, BArg, "xor"); });
	addCase(BS_SHL, "shl", [&](IRBuilder<>& BC) { return BC.CreateShl(AArg, BArg, "shl"); });
	addCase(BS_LSHR, "lshr", [&](IRBuilder<>& BC) { return BC.CreateLShr(AArg, BArg, "lshr"); });
	addCase(BS_ASHR, "ashr", [&](IRBuilder<>& BC) { return BC.CreateAShr(AArg, BArg, "ashr"); });
	addCase(BS_SDIV, "sdiv", [&](IRBuilder<>& BC) { return BC.CreateSDiv(AArg, BArg, "sdiv"); });
	addCase(BS_UDIV, "udiv", [&](IRBuilder<>& BC) { return BC.CreateUDiv(AArg, BArg, "udiv"); });
	addCase(BS_SREM, "srem", [&](IRBuilder<>& BC) { return BC.CreateSRem(AArg, BArg, "srem"); });
	addCase(BS_UREM, "urem", [&](IRBuilder<>& BC) { return BC.CreateURem(AArg, BArg, "urem"); });

	return HF;
}


// Pure helper `i32 __vm_h_icmp(i32 a, i32 b, i8 pred)` -- replicates OP_ICMP's
// predicate select-chain (buildHandlersIntArith) as a switch. `pred` is the
// raw CmpInst::Predicate byte (ICMP_EQ..ICMP_SLE). Default (pred matches none
// of the 10 integer predicates) returns 0, matching the select chain's
// initial R=false.
Function* VMImpl::getOrCreateNestedIcmpHelper() {
	if (Function* Existing = M.getFunction(kNestedIcmpHelperName))
		return Existing;

	FunctionType* FTy = FunctionType::get(I32Ty, { I32Ty, I32Ty, I8Ty }, false);
	Function* HF = Function::Create(FTy, GlobalValue::InternalLinkage,
		kNestedIcmpHelperName, &M);
	HF->addFnAttr(Attribute::NoUnwind);
	Argument* AArg = HF->getArg(0); AArg->setName("a");
	Argument* BArg = HF->getArg(1); BArg->setName("b");
	Argument* PredArg = HF->getArg(2); PredArg->setName("pred");

	BasicBlock* EntryBB = BasicBlock::Create(Ctx, "entry", HF);
	IRBuilder<> B(EntryBB);
	Value* Pred32 = B.CreateZExt(PredArg, I32Ty, "pred32");

	BasicBlock* MergeBB = BasicBlock::Create(Ctx, "merge", HF);
	BasicBlock* DefBB = BasicBlock::Create(Ctx, "def", HF);
	SwitchInst* SW = B.CreateSwitch(Pred32, DefBB, 10);

	IRBuilder<> BM(MergeBB);
	auto* Phi = BM.CreatePHI(I32Ty, 11, "r");
	BM.CreateRet(Phi);

	{
		// Default: pred matches none of the 10 -- result 0 (matches OP_ICMP's
		// initial R=false).
		IRBuilder<> BD(DefBB);
		Phi->addIncoming(BD.getInt32(0), DefBB);
		BD.CreateBr(MergeBB);
	}

	using P = CmpInst::Predicate;
	auto addCase = [&](P Pred, const Twine& Name, auto Emit) {
		BasicBlock* CBB = BasicBlock::Create(Ctx, Name, HF);
		IRBuilder<> BC(CBB);
		Value* Rv = BC.CreateZExt(Emit(BC), I32Ty, "z");
		Phi->addIncoming(Rv, CBB);
		BC.CreateBr(MergeBB);
		SW->addCase(B.getInt32(IsaEnc.encIcmpPred((uint8_t)Pred)), CBB);
		};

	addCase(P::ICMP_EQ, "eq", [&](IRBuilder<>& BC) { return BC.CreateICmpEQ(AArg, BArg); });
	addCase(P::ICMP_NE, "ne", [&](IRBuilder<>& BC) { return BC.CreateICmpNE(AArg, BArg); });
	addCase(P::ICMP_UGT, "ugt", [&](IRBuilder<>& BC) { return BC.CreateICmpUGT(AArg, BArg); });
	addCase(P::ICMP_UGE, "uge", [&](IRBuilder<>& BC) { return BC.CreateICmpUGE(AArg, BArg); });
	addCase(P::ICMP_ULT, "ult", [&](IRBuilder<>& BC) { return BC.CreateICmpULT(AArg, BArg); });
	addCase(P::ICMP_ULE, "ule", [&](IRBuilder<>& BC) { return BC.CreateICmpULE(AArg, BArg); });
	addCase(P::ICMP_SGT, "sgt", [&](IRBuilder<>& BC) { return BC.CreateICmpSGT(AArg, BArg); });
	addCase(P::ICMP_SGE, "sge", [&](IRBuilder<>& BC) { return BC.CreateICmpSGE(AArg, BArg); });
	addCase(P::ICMP_SLT, "slt", [&](IRBuilder<>& BC) { return BC.CreateICmpSLT(AArg, BArg); });
	addCase(P::ICMP_SLE, "sle", [&](IRBuilder<>& BC) { return BC.CreateICmpSLE(AArg, BArg); });

	return HF;
}


// Pure helper `i32 __vm_h_icmp64(i64 a, i64 b, i8 pred)` -- replicates
// OP_ICMP64's predicate select-chain, same shape as getOrCreateNestedIcmpHelper()
// but over I64Ty operands (result stays i32, matching OP_ICMP64's vreg dest).
Function* VMImpl::getOrCreateNestedIcmp64Helper() {
	if (Function* Existing = M.getFunction(kNestedIcmp64HelperName))
		return Existing;

	FunctionType* FTy = FunctionType::get(I32Ty, { I64Ty, I64Ty, I8Ty }, false);
	Function* HF = Function::Create(FTy, GlobalValue::InternalLinkage,
		kNestedIcmp64HelperName, &M);
	HF->addFnAttr(Attribute::NoUnwind);
	Argument* AArg = HF->getArg(0); AArg->setName("a");
	Argument* BArg = HF->getArg(1); BArg->setName("b");
	Argument* PredArg = HF->getArg(2); PredArg->setName("pred");

	BasicBlock* EntryBB = BasicBlock::Create(Ctx, "entry", HF);
	IRBuilder<> B(EntryBB);
	Value* Pred32 = B.CreateZExt(PredArg, I32Ty, "pred32");

	BasicBlock* MergeBB = BasicBlock::Create(Ctx, "merge", HF);
	BasicBlock* DefBB = BasicBlock::Create(Ctx, "def", HF);
	SwitchInst* SW = B.CreateSwitch(Pred32, DefBB, 10);

	IRBuilder<> BM(MergeBB);
	auto* Phi = BM.CreatePHI(I32Ty, 11, "r");
	BM.CreateRet(Phi);

	{
		// Default: pred matches none of the 10 -- result 0 (matches OP_ICMP64's
		// initial R=false).
		IRBuilder<> BD(DefBB);
		Phi->addIncoming(BD.getInt32(0), DefBB);
		BD.CreateBr(MergeBB);
	}

	using P = CmpInst::Predicate;
	auto addCase = [&](P Pred, const Twine& Name, auto Emit) {
		BasicBlock* CBB = BasicBlock::Create(Ctx, Name, HF);
		IRBuilder<> BC(CBB);
		Value* Rv = BC.CreateZExt(Emit(BC), I32Ty, "z");
		Phi->addIncoming(Rv, CBB);
		BC.CreateBr(MergeBB);
		SW->addCase(B.getInt32(IsaEnc.encIcmpPred((uint8_t)Pred)), CBB);
		};

	addCase(P::ICMP_EQ, "eq", [&](IRBuilder<>& BC) { return BC.CreateICmpEQ(AArg, BArg); });
	addCase(P::ICMP_NE, "ne", [&](IRBuilder<>& BC) { return BC.CreateICmpNE(AArg, BArg); });
	addCase(P::ICMP_UGT, "ugt", [&](IRBuilder<>& BC) { return BC.CreateICmpUGT(AArg, BArg); });
	addCase(P::ICMP_UGE, "uge", [&](IRBuilder<>& BC) { return BC.CreateICmpUGE(AArg, BArg); });
	addCase(P::ICMP_ULT, "ult", [&](IRBuilder<>& BC) { return BC.CreateICmpULT(AArg, BArg); });
	addCase(P::ICMP_ULE, "ule", [&](IRBuilder<>& BC) { return BC.CreateICmpULE(AArg, BArg); });
	addCase(P::ICMP_SGT, "sgt", [&](IRBuilder<>& BC) { return BC.CreateICmpSGT(AArg, BArg); });
	addCase(P::ICMP_SGE, "sge", [&](IRBuilder<>& BC) { return BC.CreateICmpSGE(AArg, BArg); });
	addCase(P::ICMP_SLT, "slt", [&](IRBuilder<>& BC) { return BC.CreateICmpSLT(AArg, BArg); });
	addCase(P::ICMP_SLE, "sle", [&](IRBuilder<>& BC) { return BC.CreateICmpSLE(AArg, BArg); });

	return HF;
}


// Pure helper `i32 __vm_h_fcmp(double a, double b, i8 pred)` -- replicates
// OP_FCMP's predicate switch (buildHandlersFloat) exactly. `pred` is the raw
// CmpInst::Predicate byte (FCMP_OEQ..FCMP_UNO). Default -- FCMP_FALSE
// (pred=0), and any unmatched pred value (e.g. FCMP_TRUE) -- returns 0,
// matching OP_FCMP's default block exactly (including its FCMP_TRUE gap).
Function* VMImpl::getOrCreateNestedFcmpHelper() {
	if (Function* Existing = M.getFunction(kNestedFcmpHelperName))
		return Existing;

	FunctionType* FTy = FunctionType::get(I32Ty, { DoubleTy, DoubleTy, I8Ty }, false);
	Function* HF = Function::Create(FTy, GlobalValue::InternalLinkage,
		kNestedFcmpHelperName, &M);
	HF->addFnAttr(Attribute::NoUnwind);
	Argument* AArg = HF->getArg(0); AArg->setName("a");
	Argument* BArg = HF->getArg(1); BArg->setName("b");
	Argument* PredArg = HF->getArg(2); PredArg->setName("pred");

	BasicBlock* EntryBB = BasicBlock::Create(Ctx, "entry", HF);
	IRBuilder<> B(EntryBB);
	Value* Pred32 = B.CreateZExt(PredArg, I32Ty, "pred32");

	BasicBlock* MergeBB = BasicBlock::Create(Ctx, "merge", HF);
	BasicBlock* DefBB = BasicBlock::Create(Ctx, "def", HF);
	SwitchInst* SW = B.CreateSwitch(Pred32, DefBB, 14);

	IRBuilder<> BM(MergeBB);
	auto* Phi = BM.CreatePHI(I32Ty, 15, "r");
	BM.CreateRet(Phi);

	{
		IRBuilder<> BD(DefBB);
		Phi->addIncoming(BD.getInt32(0), DefBB);
		BD.CreateBr(MergeBB);
	}

	using FP = CmpInst::Predicate;
	auto addCase = [&](FP Pred, const Twine& Name, auto Emit) {
		BasicBlock* CBB = BasicBlock::Create(Ctx, Name, HF);
		IRBuilder<> BC(CBB);
		Value* Rv = BC.CreateZExt(Emit(BC), I32Ty, "z");
		Phi->addIncoming(Rv, CBB);
		BC.CreateBr(MergeBB);
		SW->addCase(B.getInt32(IsaEnc.encFcmpPred((uint8_t)Pred)), CBB);
		};

	addCase(FP::FCMP_OEQ, "oeq", [&](IRBuilder<>& BC) { return BC.CreateFCmpOEQ(AArg, BArg); });
	addCase(FP::FCMP_OGT, "ogt", [&](IRBuilder<>& BC) { return BC.CreateFCmpOGT(AArg, BArg); });
	addCase(FP::FCMP_OGE, "oge", [&](IRBuilder<>& BC) { return BC.CreateFCmpOGE(AArg, BArg); });
	addCase(FP::FCMP_OLT, "olt", [&](IRBuilder<>& BC) { return BC.CreateFCmpOLT(AArg, BArg); });
	addCase(FP::FCMP_OLE, "ole", [&](IRBuilder<>& BC) { return BC.CreateFCmpOLE(AArg, BArg); });
	addCase(FP::FCMP_ONE, "one", [&](IRBuilder<>& BC) { return BC.CreateFCmpONE(AArg, BArg); });
	addCase(FP::FCMP_ORD, "ord", [&](IRBuilder<>& BC) { return BC.CreateFCmpORD(AArg, BArg); });
	addCase(FP::FCMP_UEQ, "ueq", [&](IRBuilder<>& BC) { return BC.CreateFCmpUEQ(AArg, BArg); });
	addCase(FP::FCMP_UGT, "ugt", [&](IRBuilder<>& BC) { return BC.CreateFCmpUGT(AArg, BArg); });
	addCase(FP::FCMP_UGE, "uge", [&](IRBuilder<>& BC) { return BC.CreateFCmpUGE(AArg, BArg); });
	addCase(FP::FCMP_ULT, "ult", [&](IRBuilder<>& BC) { return BC.CreateFCmpULT(AArg, BArg); });
	addCase(FP::FCMP_ULE, "ule", [&](IRBuilder<>& BC) { return BC.CreateFCmpULE(AArg, BArg); });
	addCase(FP::FCMP_UNE, "une", [&](IRBuilder<>& BC) { return BC.CreateFCmpUNE(AArg, BArg); });
	addCase(FP::FCMP_UNO, "uno", [&](IRBuilder<>& BC) { return BC.CreateFCmpUNO(AArg, BArg); });

	return HF;
}


// Pure helper `i32 __vm_h_cast(i32 src, i8 kind)` -- replicates OP_CAST's
// kind select-chain (buildHandlersIntArith) as a switch. `kind` 0..7 covers
// CK_ZEXT1/8/16, CK_SEXT8/16, CK_TRUNC1/8/16 -- all operate within the i32
// reg file, so zextN and truncN of an already-i32 value share the same
// AND/shift body (mirroring OP_CAST's Cvs[] table, which reuses ze() for both
// the ZEXT and TRUNC cases). Default (kind not in 0..7) returns src
// unchanged, matching the select chain's initial R=SV.
Function* VMImpl::getOrCreateNestedCastHelper() {
	if (Function* Existing = M.getFunction(kNestedCastHelperName))
		return Existing;

	FunctionType* FTy = FunctionType::get(I32Ty, { I32Ty, I8Ty }, false);
	Function* HF = Function::Create(FTy, GlobalValue::InternalLinkage,
		kNestedCastHelperName, &M);
	HF->addFnAttr(Attribute::NoUnwind);
	Argument* SrcArg = HF->getArg(0); SrcArg->setName("src");
	Argument* KindArg = HF->getArg(1); KindArg->setName("kind");

	BasicBlock* EntryBB = BasicBlock::Create(Ctx, "entry", HF);
	IRBuilder<> B(EntryBB);
	Value* Kind32 = B.CreateZExt(KindArg, I32Ty, "kind32");

	BasicBlock* MergeBB = BasicBlock::Create(Ctx, "merge", HF);
	BasicBlock* DefBB = BasicBlock::Create(Ctx, "def", HF);
	SwitchInst* SW = B.CreateSwitch(Kind32, DefBB, 8);

	IRBuilder<> BM(MergeBB);
	auto* Phi = BM.CreatePHI(I32Ty, 9, "r");
	BM.CreateRet(Phi);

	{
		// Default: kind not in 0..7 -- result is src unchanged.
		IRBuilder<> BD(DefBB);
		Phi->addIncoming(SrcArg, DefBB);
		BD.CreateBr(MergeBB);
	}

	auto addCase = [&](uint32_t Case, const Twine& Name, auto Emit) {
		BasicBlock* CBB = BasicBlock::Create(Ctx, Name, HF);
		IRBuilder<> BC(CBB);
		Value* Rv = Emit(BC);
		Phi->addIncoming(Rv, CBB);
		BC.CreateBr(MergeBB);
		SW->addCase(B.getInt32(IsaEnc.encCastKind((uint8_t)Case)), CBB);
		};

	auto ze = [&](IRBuilder<>& BC, uint32_t Mask) -> Value* {
		return BC.CreateAnd(SrcArg, BC.getInt32(Mask), "ze"); };
	auto se = [&](IRBuilder<>& BC, uint32_t W) -> Value* {
		return BC.CreateAShr(BC.CreateShl(SrcArg, BC.getInt32(32 - W), "ssl"),
			BC.getInt32(32 - W), "ssr");
		};

	addCase(CK_ZEXT1, "zext1", [&](IRBuilder<>& BC) { return ze(BC, 1); });
	addCase(CK_ZEXT8, "zext8", [&](IRBuilder<>& BC) { return ze(BC, 0xFF); });
	addCase(CK_ZEXT16, "zext16", [&](IRBuilder<>& BC) { return ze(BC, 0xFFFF); });
	addCase(CK_SEXT8, "sext8", [&](IRBuilder<>& BC) { return se(BC, 8); });
	addCase(CK_SEXT16, "sext16", [&](IRBuilder<>& BC) { return se(BC, 16); });
	addCase(CK_TRUNC1, "trunc1", [&](IRBuilder<>& BC) { return ze(BC, 1); });
	addCase(CK_TRUNC8, "trunc8", [&](IRBuilder<>& BC) { return ze(BC, 0xFF); });
	addCase(CK_TRUNC16, "trunc16", [&](IRBuilder<>& BC) { return ze(BC, 0xFFFF); });

	return HF;
}


// Pure helper `double __vm_h_binop_f(double a, double b, i8 subop)` -- replicates
// OP_BINOP_F's compute (buildHandlersFloat). subop bits[6:0] = FBinSubop, bit[7]
// = f32-mode flag: when set, the f64 result is rounded to f32 precision
// (fptrunc->fpext), matching native float arithmetic. Plain (no fast-math) FP
// ops, mirroring the handler. Default case is FBS_FADD.
Function* VMImpl::getOrCreateNestedBinopFHelper() {
	if (Function* Existing = M.getFunction(kNestedBinopFHelperName))
		return Existing;

	FunctionType* FTy = FunctionType::get(DoubleTy, { DoubleTy, DoubleTy, I8Ty }, false);
	Function* HF = Function::Create(FTy, GlobalValue::InternalLinkage,
		kNestedBinopFHelperName, &M);
	HF->addFnAttr(Attribute::NoUnwind);
	Argument* AArg = HF->getArg(0); AArg->setName("a");
	Argument* BArg = HF->getArg(1); BArg->setName("b");
	Argument* SubArg = HF->getArg(2); SubArg->setName("subop");

	BasicBlock* EntryBB = BasicBlock::Create(Ctx, "entry", HF);
	IRBuilder<> B(EntryBB);
	Value* Sub32 = B.CreateZExt(SubArg, I32Ty, "sub32");
	Value* Op = B.CreateAnd(Sub32, B.getInt32(0x7F), "op");      // FBinSubop
	Value* IsF32 = B.CreateICmpNE(
		B.CreateAnd(Sub32, B.getInt32(0x80), "f32b"), B.getInt32(0), "f32");

	BasicBlock* MergeBB = BasicBlock::Create(Ctx, "merge", HF);
	BasicBlock* DefBB = BasicBlock::Create(Ctx, "def", HF);
	SwitchInst* SW = B.CreateSwitch(Op, DefBB, 5);

	IRBuilder<> BM(MergeBB);
	auto* Phi = BM.CreatePHI(DoubleTy, 6, "r");
	// Round to f32 precision when bit 7 was set (matches the handler).
	Value* Narrow = BM.CreateFPExt(
		BM.CreateFPTrunc(Phi, Type::getFloatTy(Ctx), "nt"), DoubleTy, "ne");
	Value* Final = BM.CreateSelect(IsF32, Narrow, Phi, "fin");
	BM.CreateRet(Final);

	{
		// Default implements FBS_FADD (matches OP_BINOP_F's fallback).
		IRBuilder<> BD(DefBB);
		Phi->addIncoming(BD.CreateFAdd(AArg, BArg, "fadd"), DefBB);
		BD.CreateBr(MergeBB);
	}

	auto addCase = [&](uint32_t Case, const Twine& Name, auto Emit) {
		BasicBlock* CBB = BasicBlock::Create(Ctx, Name, HF);
		IRBuilder<> BC(CBB);
		Phi->addIncoming(Emit(BC), CBB);
		BC.CreateBr(MergeBB);
		SW->addCase(B.getInt32(IsaEnc.encFBinSubop((uint8_t)Case)), CBB);
		};

	addCase(FBS_FSUB, "fsub", [&](IRBuilder<>& BC) { return BC.CreateFSub(AArg, BArg, "fsub"); });
	addCase(FBS_FMUL, "fmul", [&](IRBuilder<>& BC) { return BC.CreateFMul(AArg, BArg, "fmul"); });
	addCase(FBS_FDIV, "fdiv", [&](IRBuilder<>& BC) { return BC.CreateFDiv(AArg, BArg, "fdiv"); });
	addCase(FBS_FREM, "frem", [&](IRBuilder<>& BC) { return BC.CreateFRem(AArg, BArg, "frem"); });

	return HF;
}


// Inner-virtualize every created pure helper, exactly once per module. Must
// run AFTER populateVMEngine() -- see the sequencing note above. Loops over
// the fixed nesting order; a helper not found by name was never referenced
// (opcodeNests() excluded it, e.g. via the nestedVMOpcodes cap).
void VMImpl::virtualizeNestedHelpersOnce() {
	VMEngine::SharedState* SS = VMEngine::getSharedState(M, EngineId);
	if (SS->NestedHelpersBuilt) return;
	SS->NestedHelpersBuilt = true;

	VMPassConfig InnerCfg = Cfg;
	InnerCfg.nestedVM = false; // hard recursion guard: no helper is ever itself nested
	InnerCfg.minBlocks = 1;    // helper is a single small switch
	// NOTE: NestedVMHardened is reserved. Hardening the helper's thin wrapper
	// via the standard wrapper-hardening passes currently yields dominance-
	// invalid IR on the helper's small wrapper shape; left off until that is
	// fixed. The distinct inner engine already provides the second layer.
	InnerCfg.hardened = false;

	for (unsigned i = 0; i < kNumNestedHelpers; ++i) {
		Function* HelperFn = M.getFunction(kNestedHelperOrder[i].Name);
		if (!HelperFn) continue; // this opcode's helper was never referenced

		obf::Rng InnerRng = R.fork((Twine("vm.nested.inner.") + kNestedHelperOrder[i].Name).str());
		// Forward MasterSeed so the inner emitter's RandISA subop map matches the
		// plain engine's handler switch-cases (same module-uniform permutation).
		VMImpl Inner(*HelperFn, InnerCfg, InnerRng, MasterSeed);
		if (!Inner.run()) {
			LLVM_DEBUG(dbgs() << "[vm] nested-VM: failed to virtualize '"
				<< HelperFn->getName() << "': " << Inner.FailReason << "\n");
			if (ObfVerbose)
				errs() << "[vm] nested-VM: failed to virtualize '" << HelperFn->getName()
				<< "': " << Inner.FailReason << "\n";
		}
	}
}
