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

#include <functional>
using namespace llvm;

#define DEBUG_TYPE "vm"

// ISAEnc encodes the ICmp predicate domain as literals (kIcmpPredBase..+10) to
// stay free of LLVM IR includes; assert here — the one TU that sees both — that
// those literals still match the real CmpInst::Predicate enum values.
static_assert(ISAEnc::kIcmpPredBase == (uint8_t)CmpInst::ICMP_EQ,
	"ISAEnc::kIcmpPredBase drifted from CmpInst::ICMP_EQ");
static_assert((uint8_t)CmpInst::ICMP_SLE - (uint8_t)CmpInst::ICMP_EQ + 1
	== ISAEnc::kNumIcmpPred, "ICmp predicate run is not 10 contiguous values");
static_assert(ISAEnc::kFcmpPredBase == (uint8_t)CmpInst::FCMP_OEQ,
	"ISAEnc::kFcmpPredBase drifted from CmpInst::FCMP_OEQ");
// The permuted run is FCMP_OEQ(1)..FCMP_UNE(14) — the 14 ordered predicates the
// handler dispatches. FCMP_FALSE(0) and FCMP_TRUE(15) bracket it and pass
// through unchanged to the handler default. (FCMP_UNO=8 sits inside the run.)
static_assert((uint8_t)CmpInst::FCMP_UNE - (uint8_t)CmpInst::FCMP_OEQ + 1
	== ISAEnc::kNumFcmpPred, "FCmp predicate run is not 14 contiguous values");

void VMImpl::buildOpcodeHandlers() {
	for (unsigned v = 0; v < NumVariants; ++v) {
		CurVariant = v;
		// Marker = last block before this variant's blocks are appended.
		BasicBlock* Marker = HFn->empty() ? nullptr : &HFn->back();
		buildHandlersIntArith();
		buildHandlersConv();
		buildHandlersMem();
		buildHandlersControl();
		buildHandlersFloat();
		buildHandlersCall();
		// Tag every block appended during this iteration as variant v.
		Function::iterator It =
			Marker ? std::next(Marker->getIterator()) : HFn->begin();
		for (; It != HFn->end(); ++It)
			VariantOf[&*It] = (uint8_t)v;
	}
	CurVariant = 0;
}

void VMImpl::buildHandlersIntArith() {
	//  OP_LOADI  [dst:u8 imm:u32le] -- vreg[dst] = imm 
	{
		auto B = mkOpc(OP_LOADI, "loadi");
		Value* IP = advIP(B, 5);
		stVR(B, rdVR(B, IP, 0, "vm.li.d"), rdU32(B, IP, 1, "vm.li.i"));
		nextInsn(B);
	}

	//  OP_LOADI64  [dst64:u8 imm:i64le] -- vreg64[dst] = imm
	{
		auto B = mkOpc(OP_LOADI64, "loadi64");
		Value* IP = advIP(B, 9);
		Value* Dst = rdVR64(B, IP, 0, "vm.li64.d");
		Value* Lo = B.CreateZExt(rdU32(B, IP, 1, "vm.li64.lo"), I64Ty, "vm.li64.loz");
		Value* Hi = B.CreateZExt(rdU32(B, IP, 5, "vm.li64.hi"), I64Ty, "vm.li64.hiz");
		Value* Imm = B.CreateOr(Lo, B.CreateShl(Hi, B.getInt64(32), "vm.li64.hs"), "vm.li64.v");
		stVR64(B, Dst, Imm);
		nextInsn(B);
	}

	//  OP_MOVR  [dst:u8 src:u8] -- vreg[dst] = vreg[src]
	{
		auto B = mkOpc(OP_MOVR, "movr");
		Value* IP = advIP(B, 2);
		stVR(B, rdVR(B, IP, 0, "vm.mr.d"), ldVR(B, rdVR(B, IP, 1, "vm.mr.s")));
		nextInsn(B);
	}

	//  OP_BINOP  -- [dst:u8 a:u8 b:u8 subop:u8] 
	// NOTE: must not speculatively execute div/rem for other subops (would trap on BV==0).
	{
		auto B = mkOpc(OP_BINOP, "binop");
		Value* IP = advIP(B, 4);
		Value* Dst = rdVR(B, IP, 0, "vm.bo.d");
		Value* AIdx = rdVR(B, IP, 1, "vm.bo.a");
		Value* BIdx = rdVR(B, IP, 2, "vm.bo.b");
		Value* Sub = rdByte(B, IP, 3, "vm.bo.op");
		Value* AV = ldVR(B, AIdx);
		Value* BV = ldVR(B, BIdx);

		if (NestedVM) {
			// Compute via a call into the pure helper, itself separately
			// inner-virtualized (see virtualizeNestedHelpersOnce()), instead
			// of the inline switch below. Decode/load stay identical to the
			// non-nested path; only the compute step differs.
			Function* HelperFn = M.getFunction(kNestedBinopHelperName);
			Value* Sub8 = B.CreateTrunc(Sub, I8Ty, "vm.bo.sub8");
			Value* Rv = B.CreateCall(HelperFn, { AV, BV, Sub8 }, "vm.bo.nested");
			stVR(B, Dst, Rv);
			nextInsn(B);
		} else {
			BasicBlock* MergeBB = BasicBlock::Create(Ctx, "vm.bo.merge", HFn);
			BasicBlock* DefBB = BasicBlock::Create(Ctx, "vm.bo.def", HFn);


			// Default implements BS_ADD (matches previous select-chain fallback)
			SwitchInst* SW = B.CreateSwitch(Sub, DefBB, 12);

			IRBuilder<> BM(MergeBB);
			auto* Phi = BM.CreatePHI(I32Ty, 13, "vm.bo.r");
			stVR(BM, Dst, Phi);
			nextInsn(BM);

			{
				IRBuilder<> BD(DefBB);
				Value* R = BD.CreateAdd(AV, BV, "vm.add");
				Phi->addIncoming(R, DefBB);
				BD.CreateBr(MergeBB);
			}

			auto addCase = [&](uint32_t Case, const Twine& BBName, auto Emit) {
				BasicBlock* CBB = BasicBlock::Create(Ctx, BBName, HFn);
				IRBuilder<> BC(CBB);
				Value* R = Emit(BC);
				Phi->addIncoming(R, CBB);
				BC.CreateBr(MergeBB);
				SW->addCase(B.getInt32(IsaEnc.encBinSubop((uint8_t)Case)), CBB);
				};

			addCase(BS_SUB, "vm.bo.sub", [&](IRBuilder<>& BC) { return BC.CreateSub(AV, BV, "vm.sub"); });
			addCase(BS_MUL, "vm.bo.mul", [&](IRBuilder<>& BC) { return BC.CreateMul(AV, BV, "vm.mul"); });
			addCase(BS_AND, "vm.bo.and", [&](IRBuilder<>& BC) { return BC.CreateAnd(AV, BV, "vm.and"); });
			addCase(BS_OR, "vm.bo.or", [&](IRBuilder<>& BC) { return BC.CreateOr(AV, BV, "vm.or"); });
			addCase(BS_XOR, "vm.bo.xor", [&](IRBuilder<>& BC) { return BC.CreateXor(AV, BV, "vm.xor"); });
			addCase(BS_SHL, "vm.bo.shl", [&](IRBuilder<>& BC) { return BC.CreateShl(AV, BV, "vm.shl"); });
			addCase(BS_LSHR, "vm.bo.lshr", [&](IRBuilder<>& BC) { return BC.CreateLShr(AV, BV, "vm.lshr"); });
			addCase(BS_ASHR, "vm.bo.ashr", [&](IRBuilder<>& BC) { return BC.CreateAShr(AV, BV, "vm.ashr"); });
			addCase(BS_SDIV, "vm.bo.sdiv", [&](IRBuilder<>& BC) { return BC.CreateSDiv(AV, BV, "vm.sdiv"); });
			addCase(BS_UDIV, "vm.bo.udiv", [&](IRBuilder<>& BC) { return BC.CreateUDiv(AV, BV, "vm.udiv"); });
			addCase(BS_SREM, "vm.bo.srem", [&](IRBuilder<>& BC) { return BC.CreateSRem(AV, BV, "vm.srem"); });
			addCase(BS_UREM, "vm.bo.urem", [&](IRBuilder<>& BC) { return BC.CreateURem(AV, BV, "vm.urem"); });
		}
	}

	//  OP_MULADD  -- [dst:u8 a:u8 b:u8 c:u8] -- dst = a*b + c (i32, superOps fusion)
	{
		auto B = mkOpc(OP_MULADD, "muladd");
		Value* IP = advIP(B, 4);
		Value* Dst = rdVR(B, IP, 0, "vm.ma.d");
		Value* AIdx = rdVR(B, IP, 1, "vm.ma.a");
		Value* BIdx = rdVR(B, IP, 2, "vm.ma.b");
		Value* CIdx = rdVR(B, IP, 3, "vm.ma.c");
		Value* AV = ldVR(B, AIdx);
		Value* BV = ldVR(B, BIdx);
		Value* CV = ldVR(B, CIdx);
		Value* R = B.CreateAdd(B.CreateMul(AV, BV, "vm.ma.m"), CV, "vm.ma.r");
		stVR(B, Dst, R);
		nextInsn(B);
	}

	//  OP_SHLADD -- [dst:u8 a:u8 b:u8 c:u8] -- dst = (a<<b) + c (i32, superOps fusion)
	{
		auto B = mkOpc(OP_SHLADD, "shladd");
		Value* IP = advIP(B, 4);
		Value* Dst = rdVR(B, IP, 0, "vm.sa.d");
		Value* AIdx = rdVR(B, IP, 1, "vm.sa.a");
		Value* BIdx = rdVR(B, IP, 2, "vm.sa.b");
		Value* CIdx = rdVR(B, IP, 3, "vm.sa.c");
		Value* AV = ldVR(B, AIdx);
		Value* BV = ldVR(B, BIdx);
		Value* CV = ldVR(B, CIdx);
		Value* R = B.CreateAdd(B.CreateShl(AV, BV, "vm.sa.s"), CV, "vm.sa.r");
		stVR(B, Dst, R);
		nextInsn(B);
	}

	//  OP_CMPSEL -- [dst:u8 a:u8 b:u8 pred:u8 t:u8 f:u8] -- dst = (a <pred> b) ? t : f  (i32, superOps fusion)
	{
		auto B = mkOpc(OP_CMPSEL, "cmpsel");
		Value* IP = advIP(B, 6);
		Value* Dst = rdVR(B, IP, 0, "vm.cs.d");
		Value* AIdx = rdVR(B, IP, 1, "vm.cs.a");
		Value* BIdx = rdVR(B, IP, 2, "vm.cs.b");
		Value* Pred = rdByte(B, IP, 3, "vm.cs.p");
		Value* TIdx = rdVR(B, IP, 4, "vm.cs.t");
		Value* FIdx = rdVR(B, IP, 5, "vm.cs.f");
		Value* AV = ldVR(B, AIdx), * BV = ldVR(B, BIdx);
		using P = CmpInst::Predicate;
		Value* Cs[] = {
		  B.CreateICmpEQ(AV,BV), B.CreateICmpNE(AV,BV),
		  B.CreateICmpUGT(AV,BV), B.CreateICmpUGE(AV,BV),
		  B.CreateICmpULT(AV,BV), B.CreateICmpULE(AV,BV),
		  B.CreateICmpSGT(AV,BV), B.CreateICmpSGE(AV,BV),
		  B.CreateICmpSLT(AV,BV), B.CreateICmpSLE(AV,BV),
		};
		P Ps[] = { P::ICMP_EQ,P::ICMP_NE,P::ICMP_UGT,P::ICMP_UGE,P::ICMP_ULT,
				P::ICMP_ULE,P::ICMP_SGT,P::ICMP_SGE,P::ICMP_SLT,P::ICMP_SLE };
		Value* Cond = B.getInt1(false);
		for (unsigned i = 0; i < 10; i++)
			Cond = B.CreateSelect(B.CreateICmpEQ(Pred, B.getInt32(IsaEnc.encIcmpPred((uint8_t)Ps[i]))), Cs[i], Cond);
		Value* TV = ldVR(B, TIdx), * FV = ldVR(B, FIdx);
		Value* R = B.CreateSelect(Cond, TV, FV, "vm.cs.r");
		stVR(B, Dst, R);
		nextInsn(B);
	}


	//  OP_BINOP64 -- [dst64:u8 a64:u8 b64:u8 subop:u8]
	// NOTE: must not speculatively execute div/rem for other subops (would trap on BV==0).
	{
		auto B = mkOpc(OP_BINOP64, "binop64");
		Value* IP = advIP(B, 4);
		Value* Dst = rdVR64(B, IP, 0, "vm.bo64.d");
		Value* AIdx = rdVR64(B, IP, 1, "vm.bo64.a");
		Value* BIdx = rdVR64(B, IP, 2, "vm.bo64.b");
		Value* Sub = rdByte(B, IP, 3, "vm.bo64.op");
		Value* AV = ldVR64(B, AIdx);
		Value* BV = ldVR64(B, BIdx);

		if (NestedVM && opcodeNests(OP_BINOP64)) {
			// See OP_BINOP's NestedVM branch: decode/load stay identical to
			// the inline path below, only the compute step calls the helper.
			Function* HelperFn = M.getFunction(kNestedBinop64HelperName);
			Value* Sub8 = B.CreateTrunc(Sub, I8Ty, "vm.bo64.sub8");
			Value* Rv = B.CreateCall(HelperFn, { AV, BV, Sub8 }, "vm.bo64.nested");
			stVR64(B, Dst, Rv);
			nextInsn(B);
		} else {
			BasicBlock* MergeBB = BasicBlock::Create(Ctx, "vm.bo64.merge", HFn);
			BasicBlock* DefBB = BasicBlock::Create(Ctx, "vm.bo64.def", HFn);

			// Default implements BS_ADD (matches previous select-chain fallback)
			SwitchInst* SW = B.CreateSwitch(Sub, DefBB, 12);

			IRBuilder<> BM(MergeBB);
			auto* Phi = BM.CreatePHI(I64Ty, 13, "vm.bo64.r");
			stVR64(BM, Dst, Phi);
			nextInsn(BM);

			{
				IRBuilder<> BD(DefBB);
				Value* R = BD.CreateAdd(AV, BV, "vm64.add");
				Phi->addIncoming(R, DefBB);
				BD.CreateBr(MergeBB);
			}

			auto addCase = [&](uint32_t Case, const Twine& BBName, auto Emit) {
				BasicBlock* CBB = BasicBlock::Create(Ctx, BBName, HFn);
				IRBuilder<> BC(CBB);
				Value* R = Emit(BC);
				Phi->addIncoming(R, CBB);
				BC.CreateBr(MergeBB);
				SW->addCase(B.getInt32(IsaEnc.encBinSubop((uint8_t)Case)), CBB);
				};

			addCase(BS_SUB, "vm.bo64.sub", [&](IRBuilder<>& BC) { return BC.CreateSub(AV, BV, "vm64.sub"); });
			addCase(BS_MUL, "vm.bo64.mul", [&](IRBuilder<>& BC) { return BC.CreateMul(AV, BV, "vm64.mul"); });
			addCase(BS_AND, "vm.bo64.and", [&](IRBuilder<>& BC) { return BC.CreateAnd(AV, BV, "vm64.and"); });
			addCase(BS_OR, "vm.bo64.or", [&](IRBuilder<>& BC) { return BC.CreateOr(AV, BV, "vm64.or"); });
			addCase(BS_XOR, "vm.bo64.xor", [&](IRBuilder<>& BC) { return BC.CreateXor(AV, BV, "vm64.xor"); });
			addCase(BS_SHL, "vm.bo64.shl", [&](IRBuilder<>& BC) { return BC.CreateShl(AV, BV, "vm64.shl"); });
			addCase(BS_LSHR, "vm.bo64.lshr", [&](IRBuilder<>& BC) { return BC.CreateLShr(AV, BV, "vm64.lshr"); });
			addCase(BS_ASHR, "vm.bo64.ashr", [&](IRBuilder<>& BC) { return BC.CreateAShr(AV, BV, "vm64.ashr"); });
			addCase(BS_SDIV, "vm.bo64.sdiv", [&](IRBuilder<>& BC) { return BC.CreateSDiv(AV, BV, "vm64.sdiv"); });
			addCase(BS_UDIV, "vm.bo64.udiv", [&](IRBuilder<>& BC) { return BC.CreateUDiv(AV, BV, "vm64.udiv"); });
			addCase(BS_SREM, "vm.bo64.srem", [&](IRBuilder<>& BC) { return BC.CreateSRem(AV, BV, "vm64.srem"); });
			addCase(BS_UREM, "vm.bo64.urem", [&](IRBuilder<>& BC) { return BC.CreateURem(AV, BV, "vm64.urem"); });
		}
	}
	//  OP_ICMP -- [dst:u8 a:u8 b:u8 pred:u8] 
	{
		auto B = mkOpc(OP_ICMP, "icmp");
		Value* IP = advIP(B, 4);
		Value* Dst = rdVR(B, IP, 0, "vm.ic.d"), * AIdx = rdVR(B, IP, 1, "vm.ic.a");
		Value* BIdx = rdVR(B, IP, 2, "vm.ic.b"), * Pred = rdByte(B, IP, 3, "vm.ic.p");
		Value* AV = ldVR(B, AIdx), * BV = ldVR(B, BIdx);

		if (NestedVM && opcodeNests(OP_ICMP)) {
			Function* HelperFn = M.getFunction(kNestedIcmpHelperName);
			Value* Pred8 = B.CreateTrunc(Pred, I8Ty, "vm.ic.pred8");
			Value* Rv = B.CreateCall(HelperFn, { AV, BV, Pred8 }, "vm.ic.nested");
			stVR(B, Dst, Rv);
			nextInsn(B);
		} else {
			using P = CmpInst::Predicate;
			Value* Cs[] = {
			  B.CreateICmpEQ(AV,BV), B.CreateICmpNE(AV,BV),
			  B.CreateICmpUGT(AV,BV), B.CreateICmpUGE(AV,BV),
			  B.CreateICmpULT(AV,BV), B.CreateICmpULE(AV,BV),
			  B.CreateICmpSGT(AV,BV), B.CreateICmpSGE(AV,BV),
			  B.CreateICmpSLT(AV,BV), B.CreateICmpSLE(AV,BV),
			};
			P Ps[] = { P::ICMP_EQ,P::ICMP_NE,P::ICMP_UGT,P::ICMP_UGE,P::ICMP_ULT,
					P::ICMP_ULE,P::ICMP_SGT,P::ICMP_SGE,P::ICMP_SLT,P::ICMP_SLE };
			Value* R = B.getInt1(false);
			for (unsigned i = 0; i < 10; i++)
				R = B.CreateSelect(B.CreateICmpEQ(Pred, B.getInt32(IsaEnc.encIcmpPred((uint8_t)Ps[i]))), Cs[i], R);
			stVR(B, Dst, B.CreateZExt(R, I32Ty, "vm.ic.r")); nextInsn(B);
		}
	}






	//  OP_ICMP64 -- [dst:u8 a:u8 b:u8 pred:u8] 
	{
		auto B = mkOpc(OP_ICMP64, "icmp64");
		Value* IP = advIP(B, 4);
		Value* Dst = rdVR(B, IP, 0, "vm.ic64.d");
		Value* AIdx = rdVR64(B, IP, 1, "vm.ic64.a");
		Value* BIdx = rdVR64(B, IP, 2, "vm.ic64.b");
		Value* Pred = rdByte(B, IP, 3, "vm.ic64.p");
		Value* AV = ldVR64(B, AIdx), * BV = ldVR64(B, BIdx);

		if (NestedVM && opcodeNests(OP_ICMP64)) {
			Function* HelperFn = M.getFunction(kNestedIcmp64HelperName);
			Value* Pred8 = B.CreateTrunc(Pred, I8Ty, "vm.ic64.pred8");
			Value* Rv = B.CreateCall(HelperFn, { AV, BV, Pred8 }, "vm.ic64.nested");
			stVR(B, Dst, Rv);
			nextInsn(B);
		} else {
			using P = CmpInst::Predicate;
			Value* Cs[] = {
			  B.CreateICmpEQ(AV,BV), B.CreateICmpNE(AV,BV),
			  B.CreateICmpUGT(AV,BV), B.CreateICmpUGE(AV,BV),
			  B.CreateICmpULT(AV,BV), B.CreateICmpULE(AV,BV),
			  B.CreateICmpSGT(AV,BV), B.CreateICmpSGE(AV,BV),
			  B.CreateICmpSLT(AV,BV), B.CreateICmpSLE(AV,BV),
			};
			P Ps[] = { P::ICMP_EQ,P::ICMP_NE,P::ICMP_UGT,P::ICMP_UGE,P::ICMP_ULT,
					   P::ICMP_ULE,P::ICMP_SGT,P::ICMP_SGE,P::ICMP_SLT,P::ICMP_SLE };

			Value* R = B.getInt1(false);
			for (unsigned i = 0; i < 10; i++)
				R = B.CreateSelect(B.CreateICmpEQ(Pred, B.getInt32(IsaEnc.encIcmpPred((uint8_t)Ps[i]))), Cs[i], R);

			stVR(B, Dst, B.CreateZExt(R, I32Ty, "vm.ic64.r"));
			nextInsn(B);
		}
	}


	//  OP_CAST -- [dst:u8 src:u8 kind:u8] 
	{
		auto B = mkOpc(OP_CAST, "cast");
		Value* IP = advIP(B, 3);
		Value* Dst = rdVR(B, IP, 0, "vm.ca.d"), * Src = rdVR(B, IP, 1, "vm.ca.s"), * Kind = rdByte(B, IP, 2, "vm.ca.k");
		Value* SV = ldVR(B, Src);

		if (NestedVM && opcodeNests(OP_CAST)) {
			Function* HelperFn = M.getFunction(kNestedCastHelperName);
			Value* Kind8 = B.CreateTrunc(Kind, I8Ty, "vm.ca.kind8");
			Value* Rv = B.CreateCall(HelperFn, { SV, Kind8 }, "vm.ca.nested");
			stVR(B, Dst, Rv);
			nextInsn(B);
		} else {
			auto ze = [&](uint32_t M) {return B.CreateAnd(SV, B.getInt32(M), "vm.ze"); };
			auto se = [&](uint32_t W)->Value* {
				return B.CreateAShr(B.CreateShl(SV, B.getInt32(32 - W), "vm.ssl"), B.getInt32(32 - W), "vm.ssr"); };
			Value* Cvs[] = { ze(1),ze(0xFF),ze(0xFFFF),se(8),se(16),ze(1),ze(0xFF),ze(0xFFFF) };
			Value* R = SV;
			for (unsigned i = 0; i < 8; i++)
				R = B.CreateSelect(B.CreateICmpEQ(Kind, B.getInt32(IsaEnc.encCastKind((uint8_t)i))), Cvs[i], R, "vm.ca.r");
			stVR(B, Dst, R); nextInsn(B);
		}
	}
}

void VMImpl::buildHandlersConv() {
	//  OP_SELECT -- [kind:u8 dst:u8 cond:u8 t:u8 f:u8] 
	// kind 0: integer vregs (dst/t/f are VR) ; kind 1: pointer pregs (dst/t/f are PR) ; kind 2: i64 vregs (dst/t/f are VR64)
	{
		auto B = mkOpc(OP_SELECT, "select");
		Value* IP = advIP(B, 5);
		Value* Kind = rdByte(B, IP, 0, "vm.sl.k");
		Value* IsPtr = B.CreateICmpEQ(Kind, B.getInt32(1), "vm.sl.isp");
		Value* IsI64 = B.CreateICmpEQ(Kind, B.getInt32(2), "vm.sl.is64");

		BasicBlock* IntBB = BasicBlock::Create(Ctx, "vm.sl.int", HFn);
		BasicBlock* PtrBB = BasicBlock::Create(Ctx, "vm.sl.ptr", HFn);
		BasicBlock* I64BB = BasicBlock::Create(Ctx, "vm.sl.i64", HFn);
		BasicBlock* K0BB = BasicBlock::Create(Ctx, "vm.sl.k0", HFn);
		B.CreateCondBr(IsPtr, PtrBB, K0BB);

		// decode kind 0 vs kind 2
		{
			IRBuilder<> BK(K0BB);
			BK.CreateCondBr(IsI64, I64BB, IntBB);
		}

		//  ptr path 
		{
			IRBuilder<> BP(PtrBB);
			Value* DstP = rdPR(BP, IP, 1, "vm.sl.pd");
			Value* Cond = rdVR(BP, IP, 2, "vm.sl.pc");
			Value* TP = ldPR(BP, rdPR(BP, IP, 3, "vm.sl.pt"));
			Value* FP = ldPR(BP, rdPR(BP, IP, 4, "vm.sl.pf"));
			Value* Bool = BP.CreateICmpNE(ldVR(BP, Cond), BP.getInt32(0), "vm.sl.pb");
			stPR(BP, DstP, BP.CreateSelect(Bool, TP, FP, "vm.sl.pr"));
			nextInsn(BP);
		}

		//  int path 
		{
			IRBuilder<> BI(IntBB);
			Value* Dst = rdVR(BI, IP, 1, "vm.sl.id");
			Value* Cond = rdVR(BI, IP, 2, "vm.sl.ic");
			Value* TV = ldVR(BI, rdVR(BI, IP, 3, "vm.sl.it"));
			Value* FV = ldVR(BI, rdVR(BI, IP, 4, "vm.sl.if"));
			Value* Bool = BI.CreateICmpNE(ldVR(BI, Cond), BI.getInt32(0), "vm.sl.ib");
			stVR(BI, Dst, BI.CreateSelect(Bool, TV, FV, "vm.sl.ir"));
			nextInsn(BI);
		}

		//  i64 path 
		{
			IRBuilder<> B64(I64BB);
			Value* Dst = rdVR64(B64, IP, 1, "vm.sl.64d");
			Value* Cond = rdVR(B64, IP, 2, "vm.sl.64c");
			Value* TV = ldVR64(B64, rdVR64(B64, IP, 3, "vm.sl.64t"));
			Value* FV = ldVR64(B64, rdVR64(B64, IP, 4, "vm.sl.64f"));
			Value* Bool = B64.CreateICmpNE(ldVR(B64, Cond), B64.getInt32(0), "vm.sl.64b");
			stVR64(B64, Dst, B64.CreateSelect(Bool, TV, FV, "vm.sl.64r"));
			nextInsn(B64);
		}
	}
	//  OP_PTRTOINT -- [dst:u8 srcp:u8] 
	{
		auto B = mkOpc(OP_PTRTOINT, "ptrtoint");
		Value* IP = advIP(B, 2);
		Value* Dst = rdVR(B, IP, 0, "vm.pi.d"), * SP = rdPR(B, IP, 1, "vm.pi.s");
		stVR(B, Dst, B.CreatePtrToInt(ldPR(B, SP), I32Ty, "vm.pi.v")); nextInsn(B);
	}


	//  OP_CAST64 -- [dst:u8 src:u8 kind:u8] 
	{
		auto B = mkOpc(OP_CAST64, "cast64");
		Value* IP = advIP(B, 3);
		Value* Kind = rdByte(B, IP, 2, "vm.c64.k");

		Value* IsTrunc = B.CreateICmpUGE(Kind, B.getInt32((uint32_t)C64_TRUNC1), "vm.c64.tr");
		BasicBlock* ExtBB = BasicBlock::Create(Ctx, "vm.c64.ext", HFn);
		BasicBlock* TrBB = BasicBlock::Create(Ctx, "vm.c64.trn", HFn);
		B.CreateCondBr(IsTrunc, TrBB, ExtBB);

		//  extend path: VR(i32) -> VR64(i64) 
		{
			IRBuilder<> BE(ExtBB);
			Value* Dst = rdVR64(BE, IP, 0, "vm.c64.d");
			Value* Src = rdVR(BE, IP, 1, "vm.c64.s");
			Value* SV = ldVR(BE, Src);

			auto ze = [&](uint32_t M) -> Value* {
				return BE.CreateZExt(BE.CreateAnd(SV, BE.getInt32(M), "vm.c64.zm"), I64Ty, "vm.c64.ze");
				};
			auto se32 = [&](uint32_t W) -> Value* {
				return BE.CreateAShr(BE.CreateShl(SV, BE.getInt32(32 - W), "vm.c64.ssl"),
					BE.getInt32(32 - W), "vm.c64.ssr");
				};

			Value* Z1 = ze(1);
			Value* Z8 = ze(0xFF);
			Value* Z16 = ze(0xFFFF);
			Value* Z32 = BE.CreateZExt(SV, I64Ty, "vm.c64.z32");

			Value* S8 = BE.CreateSExt(se32(8), I64Ty, "vm.c64.s8");
			Value* S16 = BE.CreateSExt(se32(16), I64Ty, "vm.c64.s16");
			Value* S32 = BE.CreateSExt(SV, I64Ty, "vm.c64.s32");

			Value* R = Z32; // default
			R = BE.CreateSelect(BE.CreateICmpEQ(Kind, BE.getInt32((uint32_t)C64_ZEXT1)), Z1, R, "vm.c64.r");
			R = BE.CreateSelect(BE.CreateICmpEQ(Kind, BE.getInt32((uint32_t)C64_ZEXT8)), Z8, R, "vm.c64.r");
			R = BE.CreateSelect(BE.CreateICmpEQ(Kind, BE.getInt32((uint32_t)C64_ZEXT16)), Z16, R, "vm.c64.r");
			R = BE.CreateSelect(BE.CreateICmpEQ(Kind, BE.getInt32((uint32_t)C64_ZEXT32)), Z32, R, "vm.c64.r");
			R = BE.CreateSelect(BE.CreateICmpEQ(Kind, BE.getInt32((uint32_t)C64_SEXT8)), S8, R, "vm.c64.r");
			R = BE.CreateSelect(BE.CreateICmpEQ(Kind, BE.getInt32((uint32_t)C64_SEXT16)), S16, R, "vm.c64.r");
			R = BE.CreateSelect(BE.CreateICmpEQ(Kind, BE.getInt32((uint32_t)C64_SEXT32)), S32, R, "vm.c64.r");

			stVR64(BE, Dst, R);
			nextInsn(BE);
		}

		//  trunc path: VR64(i64) -> VR(i32) 
		{
			IRBuilder<> BT(TrBB);
			Value* Dst = rdVR(BT, IP, 0, "vm.c64.td");
			Value* Src = rdVR64(BT, IP, 1, "vm.c64.ts");
			Value* SV = ldVR64(BT, Src);
			Value* Lo32 = BT.CreateTrunc(SV, I32Ty, "vm.c64.lo");

			Value* T1 = BT.CreateAnd(Lo32, BT.getInt32(1), "vm.c64.t1");
			Value* T8 = BT.CreateAnd(Lo32, BT.getInt32(0xFF), "vm.c64.t8");
			Value* T16 = BT.CreateAnd(Lo32, BT.getInt32(0xFFFF), "vm.c64.t16");
			Value* T32 = Lo32;

			Value* R = T32; // default
			R = BT.CreateSelect(BT.CreateICmpEQ(Kind, BT.getInt32((uint32_t)C64_TRUNC1)), T1, R, "vm.c64.tr");
			R = BT.CreateSelect(BT.CreateICmpEQ(Kind, BT.getInt32((uint32_t)C64_TRUNC8)), T8, R, "vm.c64.tr");
			R = BT.CreateSelect(BT.CreateICmpEQ(Kind, BT.getInt32((uint32_t)C64_TRUNC16)), T16, R, "vm.c64.tr");
			R = BT.CreateSelect(BT.CreateICmpEQ(Kind, BT.getInt32((uint32_t)C64_TRUNC32)), T32, R, "vm.c64.tr");

			stVR(BT, Dst, R);
			nextInsn(BT);
		}
	}


	//  OP_PTRTOINT64 -- [dst64:u8 srcp:u8] 
	{
		auto B = mkOpc(OP_PTRTOINT64, "ptrtoint64");
		Value* IP = advIP(B, 2);
		Value* Dst = rdVR64(B, IP, 0, "vm.pi64.d"), * SP = rdPR(B, IP, 1, "vm.pi64.s");
		stVR64(B, Dst, B.CreatePtrToInt(ldPR(B, SP), I64Ty, "vm.pi64.v")); nextInsn(B);
	}


	//  OP_INTTOPTR -- [dstp:u8 src:u8] 
	{
		auto B = mkOpc(OP_INTTOPTR, "inttoptr");
		Value* IP = advIP(B, 2);
		Value* DP = rdPR(B, IP, 0, "vm.pp.d"), * Src = rdVR(B, IP, 1, "vm.pp.s");
		stPR(B, DP, B.CreateIntToPtr(ldVR(B, Src), PtrTy, "vm.pp.v")); nextInsn(B);
	}

}

void VMImpl::buildHandlersMem() {
	//  OP_LOAD32 -- [dst:u8 ptrreg:u8] 
	{
		auto B = mkOpc(OP_LOAD32, "load32");
		Value* IP = advIP(B, 2);
		Value* Dst = rdVR(B, IP, 0, "vm.ld.d"), * PP = rdPR(B, IP, 1, "vm.ld.p");
		stVR(B, Dst, B.CreateLoad(I32Ty, ldPR(B, PP), "vm.ld.v")); nextInsn(B);
	}

	//  OP_LOAD64 -- [dst64:u8 ptrreg:u8] 
	{
		auto B = mkOpc(OP_LOAD64, "load64");
		Value* IP = advIP(B, 2);
		Value* Dst = rdVR64(B, IP, 0, "vm.ld64.d"), * PP = rdPR(B, IP, 1, "vm.ld64.p");
		stVR64(B, Dst, B.CreateLoad(I64Ty, ldPR(B, PP), "vm.ld64.v")); nextInsn(B);
	}

	//  OP_STORE32 -- [val:u8 ptrreg:u8] 
	{
		auto B = mkOpc(OP_STORE32, "store32");
		Value* IP = advIP(B, 2);
		Value* VR = rdVR(B, IP, 0, "vm.st.v"), * PP = rdPR(B, IP, 1, "vm.st.p");
		B.CreateStore(ldVR(B, VR), ldPR(B, PP)); nextInsn(B);
	}

	//  OP_STORE64 -- [val64:u8 ptrreg:u8] 
	{
		auto B = mkOpc(OP_STORE64, "store64");
		Value* IP = advIP(B, 2);
		Value* VIdx = rdVR64(B, IP, 0, "vm.st64.v"), * PP = rdPR(B, IP, 1, "vm.st64.p");
		B.CreateStore(ldVR64(B, VIdx), ldPR(B, PP)); nextInsn(B);
	}

	//  OP_GEP -- [dstp:u8 basep:u8 idx:u8 elemsz:u16le] 
	// Byte offset = vreg[idx] * elemsz.  Interpreter always operates in bytes.
	{
		auto B = mkOpc(OP_GEP, "gep");
		Value* IP = advIP(B, 5);   // 3 reg bytes + 2 elemsz bytes
		Value* DP = rdPR(B, IP, 0, "vm.gp.d"), * BP = rdPR(B, IP, 1, "vm.gp.b"), * Idx = rdVR(B, IP, 2, "vm.gp.i");
		// Reconstruct elemsz (plain u16le, not obfuscated ├ö├ç├Â it's a stride constant)
		Value* ELo = B.CreateZExt(loadBC(B, IP, 3, "vm.gp.el"), I64Ty, "vm.gp.elo");
		Value* EHi = B.CreateZExt(loadBC(B, IP, 4, "vm.gp.eh"), I64Ty, "vm.gp.ehi");
		Value* ESz = B.CreateOr(ELo, B.CreateShl(EHi, B.getInt64(8), "vm.gp.es"), "vm.gp.esz");
		// Byte offset = (i64)idx_value * elemsz
		Value* IdxVal = B.CreateSExt(ldVR(B, Idx), I64Ty, "vm.gp.iv");
		Value* ByteOff = B.CreateMul(IdxVal, ESz, "vm.gp.bo");
		stPR(B, DP, B.CreateGEP(I8Ty, ldPR(B, BP), ByteOff, "vm.gp.v")); nextInsn(B);
	}

	//  OP_GEP64 -- [dstp:u8 basep:u8 idx64:u8 elemsz:u16le] 
	{
		auto B = mkOpc(OP_GEP64, "gep64");
		Value* IP = advIP(B, 5);
		Value* DP = rdPR(B, IP, 0, "vm.gp64.d"), * BP = rdPR(B, IP, 1, "vm.gp64.b");
		Value* Idx = rdVR64(B, IP, 2, "vm.gp64.i");
		Value* ELo = B.CreateZExt(loadBC(B, IP, 3, "vm.gp64.el"), I64Ty, "vm.gp64.elo");
		Value* EHi = B.CreateZExt(loadBC(B, IP, 4, "vm.gp64.eh"), I64Ty, "vm.gp64.ehi");
		Value* ESz = B.CreateOr(ELo, B.CreateShl(EHi, B.getInt64(8), "vm.gp64.es"), "vm.gp64.esz");
		Value* IdxVal = ldVR64(B, Idx);
		Value* ByteOff = B.CreateMul(IdxVal, ESz, "vm.gp64.bo");
		stPR(B, DP, B.CreateGEP(I8Ty, ldPR(B, BP), ByteOff, "vm.gp64.v")); nextInsn(B);
	}



	// LOAD/STORE -- 8/16:
	{
		auto B = mkOpc(OP_LOAD8, "load8");
		Value* IP = advIP(B, 2);
		Value* Dst = rdVR(B, IP, 0, "vm.ld8.d");
		Value* PP = rdPR(B, IP, 1, "vm.ld8.p");
		Value* V8 = B.CreateLoad(I8Ty, ldPR(B, PP), "vm.ld8.v");
		stVR(B, Dst, B.CreateZExt(V8, I32Ty, "vm.ld8.z"));
		nextInsn(B);
	}
	{
		auto B = mkOpc(OP_STORE8, "store8");
		Value* IP = advIP(B, 2);
		Value* VIdx = rdVR(B, IP, 0, "vm.st8.v");
		Value* PP = rdPR(B, IP, 1, "vm.st8.p");
		Value* V8 = B.CreateTrunc(ldVR(B, VIdx), I8Ty, "vm.st8.t");
		B.CreateStore(V8, ldPR(B, PP));
		nextInsn(B);
	}
	{
		auto B = mkOpc(OP_LOAD16, "load16");
		Value* IP = advIP(B, 2);
		Value* Dst = rdVR(B, IP, 0, "vm.ld16.d");
		Value* PP = rdPR(B, IP, 1, "vm.ld16.p");
		Value* V16 = B.CreateLoad(I16Ty, ldPR(B, PP), "vm.ld16.v");
		stVR(B, Dst, B.CreateZExt(V16, I32Ty, "vm.ld16.z"));
		nextInsn(B);
	}
	{
		auto B = mkOpc(OP_STORE16, "store16");
		Value* IP = advIP(B, 2);
		Value* VIdx = rdVR(B, IP, 0, "vm.st16.v");
		Value* PP = rdPR(B, IP, 1, "vm.st16.p");
		Value* V16 = B.CreateTrunc(ldVR(B, VIdx), I16Ty, "vm.st16.t");
		B.CreateStore(V16, ldPR(B, PP));
		nextInsn(B);
	}


	// LOAD/STORE -- PTR:
	{
		auto B = mkOpc(OP_LOADPTR, "loadptr");
		Value* IP = advIP(B, 2);
		Value* Dst = rdPR(B, IP, 0, "vm.lp.d");
		Value* PP = rdPR(B, IP, 1, "vm.lp.p");
		Value* V = B.CreateLoad(PtrTy, ldPR(B, PP), "vm.lp.v");
		stPR(B, Dst, V);
		nextInsn(B);
	}
	{
		auto B = mkOpc(OP_STOREPTR, "storeptr");
		Value* IP = advIP(B, 2);
		Value* VIdx = rdPR(B, IP, 0, "vm.sp.v");
		Value* PP = rdPR(B, IP, 1, "vm.sp.p");
		B.CreateStore(ldPR(B, VIdx), ldPR(B, PP));
		nextInsn(B);
	}


}

void VMImpl::buildHandlersControl() {
	//  OP_JMP -- [target:u32le] 
	{
		auto B = mkOpc(OP_JMP, "jmp");
		Value* IP = advIP(B, 4);
		Value* JT = rdU32(B, IP, 0, "vm.jm.t");
		if (BlindTargets) JT = B.CreateXor(JT, tgtKeyIR(B, "vm.jm"), "vm.jm.ub");
		B.CreateStore(JT, VMIP)->setVolatile(true);
		nextInsn(B);
	}

	//  OP_JMPC -- [cond:u8 tgt_t:u32 tgt_f:u32] 
	{
		auto B = mkOpc(OP_JMPC, "jmpc");
		Value* IP = advIP(B, 9);
		Value* Cond = rdVR(B, IP, 0, "vm.jc.c"), * Tt = rdU32(B, IP, 1, "vm.jc.t"), * Tf = rdU32(B, IP, 5, "vm.jc.f");
		Value* Bool = B.CreateICmpNE(ldVR(B, Cond), B.getInt32(0), "vm.jc.b");
		Value* Sel = B.CreateSelect(Bool, Tt, Tf, "vm.jc.s");
		if (BlindTargets) Sel = B.CreateXor(Sel, tgtKeyIR(B, "vm.jc"), "vm.jc.ub");
		B.CreateStore(Sel, VMIP)->setVolatile(true);
		nextInsn(B);
	}


	//  OP_SWITCH -- [cond:u8 ncases:u16le def:u32le [case:u32le tgt:u32le]*ncases] 
	// Linear scan at runtime using a compact table; no per-case IR bloat.
	{
		auto B = mkOpc(OP_SWITCH, "switch");
		// CurIP points at first operand byte (fetch already consumed opcode)
		auto* CurIP = B.CreateLoad(I32Ty, VMIP, "vm.sw.ip");
		CurIP->setVolatile(true);

		Value* CondIdx = rdVR(B, CurIP, 0, "vm.sw.ci");
		Value* CondVal = ldVR(B, CondIdx);

		// ncases = u16le at offsets 1..2 (plain)
		Value* NLo = B.CreateZExt(loadBC(B, CurIP, 1, "vm.sw.nl"), I32Ty, "vm.sw.nlo");
		Value* NHi = B.CreateZExt(loadBC(B, CurIP, 2, "vm.sw.nh"), I32Ty, "vm.sw.nhi");
		Value* NCases = B.CreateOr(NLo, B.CreateShl(NHi, B.getInt32(8), "vm.sw.ns"), "vm.sw.nc");

		Value* DefT = rdU32(B, CurIP, 3, "vm.sw.df");

		// Advance IP past the whole switch payload: 7 + 8*ncases bytes
		Value* Adv = B.CreateAdd(B.getInt32(7),
			B.CreateMul(NCases, B.getInt32(8), "vm.sw.mul"),
			"vm.sw.adv");
		B.CreateStore(B.CreateAdd(CurIP, Adv, "vm.sw.nip"), VMIP)->setVolatile(true);

		BasicBlock* EntryBB = B.GetInsertBlock();
		BasicBlock* LoopBB = BasicBlock::Create(Ctx, "vm.sw.loop", HFn);
		BasicBlock* BodyBB = BasicBlock::Create(Ctx, "vm.sw.body", HFn);
		BasicBlock* DoneBB = BasicBlock::Create(Ctx, "vm.sw.done", HFn);
		B.CreateBr(LoopBB);

		// loop: i from 0..NCases-1, R accumulates selected target (default by default)
		IRBuilder<> LB(LoopBB);
		PHINode* I = LB.CreatePHI(I32Ty, 2, "vm.sw.i");
		PHINode* R = LB.CreatePHI(I32Ty, 2, "vm.sw.r");
		I->addIncoming(LB.getInt32(0), EntryBB);
		R->addIncoming(DefT, EntryBB);

		Value* More = LB.CreateICmpULT(I, NCases, "vm.sw.more");
		LB.CreateCondBr(More, BodyBB, DoneBB);

		IRBuilder<> BB(BodyBB);
		// Off = 7 + i*8
		Value* Off = BB.CreateAdd(BB.getInt32(7),
			BB.CreateMul(I, BB.getInt32(8), "vm.sw.os"),
			"vm.sw.off");
		Value* CaseV = rdU32Dyn(BB, CurIP, Off, "vm.sw.cv");
		Value* Off4 = BB.CreateAdd(Off, BB.getInt32(4), "vm.sw.of4");
		Value* Tgt = rdU32Dyn(BB, CurIP, Off4, "vm.sw.tg");

		Value* Eq = BB.CreateICmpEQ(CondVal, CaseV, "vm.sw.eq");
		Value* NewR = BB.CreateSelect(Eq, Tgt, R, "vm.sw.nr");
		Value* NextI = BB.CreateAdd(I, BB.getInt32(1), "vm.sw.ni");
		BB.CreateBr(LoopBB);

		I->addIncoming(NextI, BodyBB);
		R->addIncoming(NewR, BodyBB);

		IRBuilder<> DB(DoneBB);
		Value* SR = R;
		if (BlindTargets) SR = DB.CreateXor(R, tgtKeyIR(DB, "vm.sw"), "vm.sw.ub");
		DB.CreateStore(SR, VMIP)->setVolatile(true);
		nextInsn(DB);
	}


	// OP_RET_VOID 
	{
		auto B = mkOpc(OP_RET_VOID, "ret_void");
		advIP(B, 0);
		if (SharedEngineMode) {
			B.CreateRetVoid();
		}
		else if (F.getReturnType()->isVoidTy()) {
			B.CreateRetVoid();
		}
		else {
			B.CreateUnreachable();
		}
	}


	{
		auto B = mkOpc(OP_RET_INT, "ret_int");
		Value* IP = advIP(B, 1);
		if (SharedEngineMode) {
			rdVR(B, IP, 0, "vm.ri.s");  // consume operand
			B.CreateRetVoid();

		}
		else {
			Type* RT = F.getReturnType();
			if (RT->isIntegerTy() && RT->getIntegerBitWidth() <= 32) {
				Value* Src = rdVR(B, IP, 0, "vm.ri.s");
				Value* V = ldVR(B, Src);
				if (RT != I32Ty) V = B.CreateTrunc(V, RT, "vm.ri.tr");
				B.CreateRet(V);
			}
			else if (RT->isIntegerTy(64)) {  // i64 return via vreg64
				Value* Src = rdVR64(B, IP, 0, "vm.ri64.s");
				B.CreateRet(ldVR64(B, Src));
			}
			else {
				B.CreateUnreachable();
			}
		}
	}


	{
		auto B = mkOpc(OP_RET_PTR, "ret_ptr");
		Value* IP = advIP(B, 1);
		if (SharedEngineMode) {
			rdPR(B, IP, 0, "vm.rp.s");
			B.CreateRetVoid();

		}
		else {
			Type* RT = F.getReturnType();
			if (RT->isPointerTy()) {
				Value* SP = rdPR(B, IP, 0, "vm.rp.s");
				Value* P = ldPR(B, SP);
				if (P->getType() != RT && P->getType()->isPointerTy())
					P = B.CreateBitCast(P, RT, "vm.rp.bc");
				B.CreateRet(P);
			}
			else {
				B.CreateUnreachable();
			}
		}
	}





}

void VMImpl::buildHandlersFloat() {
	// OP_LOADI_F -- [dst_fr:u8 imm:f64le]    freg[dst] = imm 
	{
		auto B = mkOpc(OP_LOADI_F, "loadi_f");
		Value* IP = advIP(B, 9);  // 1 dst + 8 bytes of f64
		Value* Dst = rdFR(B, IP, 0, "vm.lif.d");
		// Reconstruct f64 from 8 LE bytes
		Value* Bits = B.getInt64(0);
		for (unsigned i = 0; i < 8; ++i) {
			Value* ByteV = B.CreateZExt(loadBC(B, IP, 1 + i, "vm.lif.b"), I64Ty, "vm.lif.bz");
			if (i) ByteV = B.CreateShl(ByteV, B.getInt64(i * 8), "vm.lif.bs");
			Bits = B.CreateOr(Bits, ByteV, "vm.lif.or");
		}
		Value* FV = B.CreateBitCast(Bits, DoubleTy, "vm.lif.v");
		stFR(B, Dst, FV);
		nextInsn(B);
	}

	// OP_MOVR_F -- [dst_fr:u8 src_fr:u8]  freg[dst] = freg[src] 
	{
		auto B = mkOpc(OP_MOVR_F, "movr_f");
		Value* IP = advIP(B, 2);
		stFR(B, rdFR(B, IP, 0, "vm.mrf.d"), ldFR(B, rdFR(B, IP, 1, "vm.mrf.s")));
		nextInsn(B);
	}

	// OP_BINOP_F -- [dst_fr:u8 a_fr:u8 b_fr:u8 subop:u8] 
	// subop layout: bits[6:0] = FBinSubop,  bit[7] = f32-mode flag.
	// When bit 7 is set the f64 result is rounded back to f32 precision
	// (fptruncf32 then fpextf64) so float arithmetic matches native
	// semantics exactly.
	{
		auto B = mkOpc(OP_BINOP_F, "binop_f");
		Value* IP = advIP(B, 4);
		Value* Dst = rdFR(B, IP, 0, "vm.bof.d");
		Value* AIdx = rdFR(B, IP, 1, "vm.bof.a");
		Value* BIdx = rdFR(B, IP, 2, "vm.bof.b");
		Value* Sub8 = rdByte(B, IP, 3, "vm.bof.op");   // raw byte incl. bit7
		Value* AV = ldFR(B, AIdx), * BV = ldFR(B, BIdx);

		if (NestedVM && opcodeNests(OP_BINOP_F)) {
			// Compute via the pure helper (separately inner-virtualized). The
			// helper takes the full subop byte and applies the f32 rounding
			// itself, so the result is final.
			Function* HelperFn = M.getFunction(kNestedBinopFHelperName);
			Value* Sub8b = B.CreateTrunc(Sub8, I8Ty, "vm.bof.sub8");
			Value* Rv = B.CreateCall(HelperFn, { AV, BV, Sub8b }, "vm.bof.nested");
			stFR(B, Dst, Rv);
			nextInsn(B);
		} else {
		Value* Sub = B.CreateAnd(Sub8, B.getInt32(0x7F), "vm.bof.sub"); // op only
		Value* IsF32 = B.CreateICmpNE(
			B.CreateAnd(Sub8, B.getInt32(0x80)), B.getInt32(0), "vm.bof.f32");

		// Carry IsF32 (i1) into the merge block via alloca so every incoming
		// edge can read it without duplicating the comparison.
		auto* IsF32Slot = new AllocaInst(Type::getInt1Ty(Ctx), 0, "vm.bof.f32.sl",
			&*HFn->getEntryBlock().getFirstInsertionPt());
		B.CreateStore(IsF32, IsF32Slot);

		BasicBlock* FMergeBB = BasicBlock::Create(Ctx, "vm.bof.merge", HFn);
		BasicBlock* FDefBB = BasicBlock::Create(Ctx, "vm.bof.def", HFn);
		SwitchInst* FSW = B.CreateSwitch(Sub, FDefBB, 5);

		IRBuilder<> FBM(FMergeBB);
		auto* FPhi = FBM.CreatePHI(DoubleTy, 6, "vm.bof.r");
		// Round to f32 precision when bit 7 was set in subop.
		Value* IsF32M = FBM.CreateLoad(Type::getInt1Ty(Ctx), IsF32Slot, "vm.bof.f32.m");
		Value* Narrow = FBM.CreateFPExt(
			FBM.CreateFPTrunc(FPhi, Type::getFloatTy(Ctx), "vm.bof.nt"),
			DoubleTy, "vm.bof.ne");
		Value* Final = FBM.CreateSelect(IsF32M, Narrow, FPhi, "vm.bof.fin");
		stFR(FBM, Dst, Final);
		nextInsn(FBM);

		{
			IRBuilder<> BD(FDefBB); Value* R = BD.CreateFAdd(AV, BV, "vm.fadd");
			FPhi->addIncoming(R, FDefBB); BD.CreateBr(FMergeBB);
		}

		auto addFCase = [&](uint32_t C, const Twine& N, auto Emit) {
			BasicBlock* CB = BasicBlock::Create(Ctx, N, HFn);
			IRBuilder<> BC(CB); Value* R = Emit(BC);
			FPhi->addIncoming(R, CB); BC.CreateBr(FMergeBB);
			FSW->addCase(B.getInt32(IsaEnc.encFBinSubop((uint8_t)C)), CB); };

		addFCase(FBS_FSUB, "vm.bof.sub", [&](IRBuilder<>& BC) { return BC.CreateFSub(AV, BV, "vm.fsub"); });
		addFCase(FBS_FMUL, "vm.bof.mul", [&](IRBuilder<>& BC) { return BC.CreateFMul(AV, BV, "vm.fmul"); });
		addFCase(FBS_FDIV, "vm.bof.div", [&](IRBuilder<>& BC) { return BC.CreateFDiv(AV, BV, "vm.fdiv"); });
		addFCase(FBS_FREM, "vm.bof.rem", [&](IRBuilder<>& BC) { return BC.CreateFRem(AV, BV, "vm.frem"); });
		}
	}

	// OP_FCMP -- [dst_vr:u8 a_fr:u8 b_fr:u8 pred:u8] 
	// pred = raw CmpInst::Predicate value (FCMP_OEQ=1 .. FCMP_UNO=14).
	// Result is i1 zero-extended to i32 and stored in vreg.
	// Switch+PHI pattern identical to OP_BINOP: only the matching predicate's
	// fcmp executes per dispatch.  No speculative evaluation of all 14 branches.
	{
		auto B = mkOpc(OP_FCMP, "fcmp");
		Value* IP = advIP(B, 4);
		Value* Dst = rdVR(B, IP, 0, "vm.fcp.d");
		Value* AIdx = rdFR(B, IP, 1, "vm.fcp.a");
		Value* BIdx = rdFR(B, IP, 2, "vm.fcp.b");
		Value* Pred = rdByte(B, IP, 3, "vm.fcp.p");
		Value* AV = ldFR(B, AIdx);
		Value* BV = ldFR(B, BIdx);

		if (NestedVM && opcodeNests(OP_FCMP)) {
			Function* HelperFn = M.getFunction(kNestedFcmpHelperName);
			Value* Pred8 = B.CreateTrunc(Pred, I8Ty, "vm.fcp.pred8");
			Value* Rv = B.CreateCall(HelperFn, { AV, BV, Pred8 }, "vm.fcp.nested");
			stVR(B, Dst, Rv);
			nextInsn(B);
		} else {
			using FP = CmpInst::Predicate;

			BasicBlock* MergeBB = BasicBlock::Create(Ctx, "vm.fcp.merge", HFn);
			BasicBlock* DefBB = BasicBlock::Create(Ctx, "vm.fcp.def", HFn);

			// Default: FCMP_FALSE (pred=0) — result always 0.
			SwitchInst* SW = B.CreateSwitch(Pred, DefBB, 14);

			// MergeBB: PHI first, then stVR, then br — same order as OP_BINOP.
			IRBuilder<> BM(MergeBB);
			auto* Phi = BM.CreatePHI(I32Ty, 15, "vm.fcp.r");
			stVR(BM, Dst, Phi);
			nextInsn(BM);

			// Default block handles FCMP_FALSE (pred==0): result is always 0.
			{
				IRBuilder<> BD(DefBB);
				Phi->addIncoming(BD.getInt32(0), DefBB);
				BD.CreateBr(MergeBB);
			}

			auto addCase = [&](FP pred, const Twine& BBName, auto Emit) {
				BasicBlock* CBB = BasicBlock::Create(Ctx, BBName, HFn);
				IRBuilder<> BC(CBB);
				Value* R = BC.CreateZExt(Emit(BC), I32Ty, "vm.fcp.z");
				Phi->addIncoming(R, CBB);
				BC.CreateBr(MergeBB);
				SW->addCase(B.getInt32(IsaEnc.encFcmpPred((uint8_t)pred)), CBB);
				};

			addCase(FP::FCMP_OEQ, "vm.fcp.oeq", [&](IRBuilder<>& BC) { return BC.CreateFCmpOEQ(AV, BV, "vm.fcp.v"); });
			addCase(FP::FCMP_OGT, "vm.fcp.ogt", [&](IRBuilder<>& BC) { return BC.CreateFCmpOGT(AV, BV, "vm.fcp.v"); });
			addCase(FP::FCMP_OGE, "vm.fcp.oge", [&](IRBuilder<>& BC) { return BC.CreateFCmpOGE(AV, BV, "vm.fcp.v"); });
			addCase(FP::FCMP_OLT, "vm.fcp.olt", [&](IRBuilder<>& BC) { return BC.CreateFCmpOLT(AV, BV, "vm.fcp.v"); });
			addCase(FP::FCMP_OLE, "vm.fcp.ole", [&](IRBuilder<>& BC) { return BC.CreateFCmpOLE(AV, BV, "vm.fcp.v"); });
			addCase(FP::FCMP_ONE, "vm.fcp.one", [&](IRBuilder<>& BC) { return BC.CreateFCmpONE(AV, BV, "vm.fcp.v"); });
			addCase(FP::FCMP_ORD, "vm.fcp.ord", [&](IRBuilder<>& BC) { return BC.CreateFCmpORD(AV, BV, "vm.fcp.v"); });
			addCase(FP::FCMP_UEQ, "vm.fcp.ueq", [&](IRBuilder<>& BC) { return BC.CreateFCmpUEQ(AV, BV, "vm.fcp.v"); });
			addCase(FP::FCMP_UGT, "vm.fcp.ugt", [&](IRBuilder<>& BC) { return BC.CreateFCmpUGT(AV, BV, "vm.fcp.v"); });
			addCase(FP::FCMP_UGE, "vm.fcp.uge", [&](IRBuilder<>& BC) { return BC.CreateFCmpUGE(AV, BV, "vm.fcp.v"); });
			addCase(FP::FCMP_ULT, "vm.fcp.ult", [&](IRBuilder<>& BC) { return BC.CreateFCmpULT(AV, BV, "vm.fcp.v"); });
			addCase(FP::FCMP_ULE, "vm.fcp.ule", [&](IRBuilder<>& BC) { return BC.CreateFCmpULE(AV, BV, "vm.fcp.v"); });
			addCase(FP::FCMP_UNE, "vm.fcp.une", [&](IRBuilder<>& BC) { return BC.CreateFCmpUNE(AV, BV, "vm.fcp.v"); });
			addCase(FP::FCMP_UNO, "vm.fcp.uno", [&](IRBuilder<>& BC) { return BC.CreateFCmpUNO(AV, BV, "vm.fcp.v"); });
		}
	}



	// OP_FCAST_FF --  [dst_fr:u8 src_fr:u8 kind:u8]  freg→freg  (fpext / fptrunc) 
	// FK_FPEXT:  -- freg already stores f64; value is already widened — select returns SV unchanged.
	// FK_FPTRUNC: -- round to f32 precision via fptrunc+fpext.
	{
		auto B = mkOpc(OP_FCAST_FF, "fcast_ff");
		Value* IP = advIP(B, 3);
		Value* Dst = rdFR(B, IP, 0, "vm.cff.d");
		Value* SV = ldFR(B, rdFR(B, IP, 1, "vm.cff.s"));
		Value* Kind = rdByte(B, IP, 2, "vm.cff.k");
		Value* Narrow = B.CreateFPExt(
			B.CreateFPTrunc(SV, Type::getFloatTy(Ctx), "vm.cff.nt"), DoubleTy, "vm.cff.ne");
		Value* IsExt = B.CreateICmpEQ(Kind, B.getInt32(FK_FPEXT), "vm.cff.ie");
		stFR(B, Dst, B.CreateSelect(IsExt, SV, Narrow, "vm.cff.r"));
		nextInsn(B);
	}

	//  OP_FCAST_FV --  [dst_vr:u8 src_fr:u8 kind:u8]  freg→vreg i32  (fptosi / fptoui) 
	{
		auto B = mkOpc(OP_FCAST_FV, "fcast_fv");
		Value* IP = advIP(B, 3);
		Value* Dst = rdVR(B, IP, 0, "vm.cfv.d");
		Value* SV = ldFR(B, rdFR(B, IP, 1, "vm.cfv.s"));
		Value* Kind = rdByte(B, IP, 2, "vm.cfv.k");
		Value* SI = B.CreateFPToSI(SV, I32Ty, "vm.cfv.si");
		Value* UI = B.CreateFPToUI(SV, I32Ty, "vm.cfv.ui");
		Value* IsS = B.CreateICmpEQ(Kind, B.getInt32(FK_FPTOSI), "vm.cfv.is");
		stVR(B, Dst, B.CreateSelect(IsS, SI, UI, "vm.cfv.r"));
		nextInsn(B);
	}

	// OP_FCAST_FV64 -- [dst_vr64:u8 src_fr:u8 kind:u8]  freg→vreg64 i64 
	{
		auto B = mkOpc(OP_FCAST_FV64, "fcast_fv64");
		Value* IP = advIP(B, 3);
		Value* Dst = rdVR64(B, IP, 0, "vm.cfv64.d");
		Value* SV = ldFR(B, rdFR(B, IP, 1, "vm.cfv64.s"));
		Value* Kind = rdByte(B, IP, 2, "vm.cfv64.k");
		Value* SI = B.CreateFPToSI(SV, I64Ty, "vm.cfv64.si");
		Value* UI = B.CreateFPToUI(SV, I64Ty, "vm.cfv64.ui");
		Value* IsS = B.CreateICmpEQ(Kind, B.getInt32(FK_FPTOSI64), "vm.cfv64.is");
		stVR64(B, Dst, B.CreateSelect(IsS, SI, UI, "vm.cfv64.r"));
		nextInsn(B);
	}

	//  OP_FCAST_VF -- [dst_fr:u8 src_vr:u8 kind:u8]  vreg i32→freg  (sitofp / uitofp)
	//  kind bit 7 = FCAST_F32_FLAG: round f64 result to f32 precision.
	{
		auto B = mkOpc(OP_FCAST_VF, "fcast_vf");
		Value* IP = advIP(B, 3);
		Value* Dst = rdFR(B, IP, 0, "vm.cvf.d");
		Value* SV = ldVR(B, rdVR(B, IP, 1, "vm.cvf.s"));
		Value* Kind = rdByte(B, IP, 2, "vm.cvf.k");
		Value * KindOp = B.CreateAnd(Kind, B.getInt32(0x7F), "vm.cvf.kop");
		Value * IsF32 = B.CreateICmpNE(
			B.CreateAnd(Kind, B.getInt32(0x80)), B.getInt32(0), "vm.cvf.f32");
		Value* SI = B.CreateSIToFP(SV, DoubleTy, "vm.cvf.si");
		Value* UI = B.CreateUIToFP(SV, DoubleTy, "vm.cvf.ui");
		Value * IsS = B.CreateICmpEQ(KindOp, B.getInt32(FK_SITOFP), "vm.cvf.is");
		Value * Result = B.CreateSelect(IsS, SI, UI, "vm.cvf.r");
		Value * Narrow = B.CreateFPExt(
			B.CreateFPTrunc(Result, Type::getFloatTy(Ctx), "vm.cvf.nt"),
			DoubleTy, "vm.cvf.ne");
		stFR(B, Dst, B.CreateSelect(IsF32, Narrow, Result, "vm.cvf.fin"));
		nextInsn(B);
	}

	//  OP_FCAST_V64F -- [dst_fr:u8 src_vr64:u8 kind:u8]  vreg64 i64→freg
	//  kind bit 7 = FCAST_F32_FLAG: round f64 result to f32 precision.
	{
		auto B = mkOpc(OP_FCAST_V64F, "fcast_v64f");
		Value* IP = advIP(B, 3);
		Value* Dst = rdFR(B, IP, 0, "vm.cv64f.d");
		Value* SV = ldVR64(B, rdVR64(B, IP, 1, "vm.cv64f.s"));
		Value* Kind = rdByte(B, IP, 2, "vm.cv64f.k");
		Value * KindOp = B.CreateAnd(Kind, B.getInt32(0x7F), "vm.cv64f.kop");
		Value * IsF32 = B.CreateICmpNE(
			B.CreateAnd(Kind, B.getInt32(0x80)), B.getInt32(0), "vm.cv64f.f32");
		Value* SI = B.CreateSIToFP(SV, DoubleTy, "vm.cv64f.si");
		Value* UI = B.CreateUIToFP(SV, DoubleTy, "vm.cv64f.ui");
		Value * IsS = B.CreateICmpEQ(KindOp, B.getInt32(FK_SI64TOFP), "vm.cv64f.is");
		Value * Result = B.CreateSelect(IsS, SI, UI, "vm.cv64f.r");
		Value * Narrow = B.CreateFPExt(
			B.CreateFPTrunc(Result, Type::getFloatTy(Ctx), "vm.cv64f.nt"),
			DoubleTy, "vm.cv64f.ne");
		stFR(B, Dst, B.CreateSelect(IsF32, Narrow, Result, "vm.cv64f.fin"));
		nextInsn(B);
	}



	// OP_LOAD_F  [dst_fr:u8 ptrreg:u8]    freg[dst] = *ptr (f64) 
	// NOTE: always loads 8 bytes as f64. f32 memory pointers will produce incorrect
	// results (reads 8 bytes from a 4-byte slot). Use double in IR for correct behaviour.
	{
		auto B = mkOpc(OP_LOAD_F, "load_f");
		Value* IP = advIP(B, 2);
		Value* Dst = rdFR(B, IP, 0, "vm.ldf.d");
		Value* PP = rdPR(B, IP, 1, "vm.ldf.p");
		stFR(B, Dst, B.CreateLoad(DoubleTy, ldPR(B, PP), "vm.ldf.v"));
		nextInsn(B);
	}

	//  OP_STORE_F  [src_fr:u8 ptrreg:u8]    *ptr = freg[src] (f64) 
	{
		auto B = mkOpc(OP_STORE_F, "store_f");
		Value* IP = advIP(B, 2);
		Value* Src = rdFR(B, IP, 0, "vm.stf.s");
		Value* PP = rdPR(B, IP, 1, "vm.stf.p");
		B.CreateStore(ldFR(B, Src), ldPR(B, PP));
		nextInsn(B);
	}


	// OP_LOAD_F32  [dst_fr:u8 ptrreg:u8]  →  freg[dst] = fpext(*ptr as float) 
	// Loads 4 bytes from a float* slot, fpext to f64, stores in freg.
	// Used when the source IR has type float (not double) — e.g. float* function parameter.
	{
		auto B = mkOpc(OP_LOAD_F32, "load_f32");
		Value* IP = advIP(B, 2);
		Value* Dst = rdFR(B, IP, 0, "vm.ldf32.d");
		Value* PP = rdPR(B, IP, 1, "vm.ldf32.p");
		Value* F32V = B.CreateLoad(Type::getFloatTy(Ctx), ldPR(B, PP), "vm.ldf32.v");
		stFR(B, Dst, B.CreateFPExt(F32V, DoubleTy, "vm.ldf32.ext"));
		nextInsn(B);
	}

	// OP_STORE_F32  [val_fr:u8 ptrreg:u8]  →  *ptr (float*) = fptrunc(freg[val]) 
	// fptrunc f64 freg value to float, stores 4 bytes.
	// Used when the destination IR type is float — e.g. float* function parameter.
	{
		auto B = mkOpc(OP_STORE_F32, "store_f32");
		Value* IP = advIP(B, 2);
		Value* Src = rdFR(B, IP, 0, "vm.stf32.s");
		Value* PP = rdPR(B, IP, 1, "vm.stf32.p");
		Value* F32V = B.CreateFPTrunc(ldFR(B, Src), Type::getFloatTy(Ctx), "vm.stf32.tr");
		B.CreateStore(F32V, ldPR(B, PP));
		nextInsn(B);
	}

	//  OP_RET_F  [src_fr:u8]    return freg[src] 
	{
		auto B = mkOpc(OP_RET_F, "ret_f");
		Value* IP = advIP(B, 1);
		if (SharedEngineMode) {
			rdFR(B, IP, 0, "vm.rf.s");
			B.CreateRetVoid();

		}
		else {
			Type* RT = F.getReturnType();
			Value* Src = rdFR(B, IP, 0, "vm.rf.s");
			Value* FV = ldFR(B, Src);
			if (RT->isDoubleTy()) {
				B.CreateRet(FV);
			}
			else if (RT->isFloatTy()) {
				B.CreateRet(B.CreateFPTrunc(FV, RT, "vm.rf.tr"));
			}
			else {
				B.CreateUnreachable();
			}
		}
	}

	// OP_SELECT_F  [dst_fr:u8 cond_vr:u8 t_fr:u8 f_fr:u8] 
	{
		auto B = mkOpc(OP_SELECT_F, "select_f");
		Value* IP = advIP(B, 4);
		Value* Dst = rdFR(B, IP, 0, "vm.slf.d");
		Value* Cond = rdVR(B, IP, 1, "vm.slf.c");
		Value* TV = ldFR(B, rdFR(B, IP, 2, "vm.slf.t"));
		Value* FV = ldFR(B, rdFR(B, IP, 3, "vm.slf.f"));
		Value* Bool = B.CreateICmpNE(ldVR(B, Cond), B.getInt32(0), "vm.slf.b");
		stFR(B, Dst, B.CreateSelect(Bool, TV, FV, "vm.slf.r"));
		nextInsn(B);
	}



	//  OP_FNEG  [dst_fr:u8 src_fr:u8]  
	{
		auto B = mkOpc(OP_FNEG, "fneg");
		Value* IP = advIP(B, 2);
		Value* Dst = rdFR(B, IP, 0, "vm.neg.d");
		Value* SV = ldFR(B, rdFR(B, IP, 1, "vm.neg.s"));
		stFR(B, Dst, B.CreateFNeg(SV, "vm.neg.r"));
		nextInsn(B);
	}



}

void VMImpl::buildHandlersCall() {
	buildCall2(OP_CALL_VOID, "call_void", RK2_VOID);
	buildCall2(OP_CALL_INT, "call_int", RK2_I32);
	buildCall2(OP_CALL_PTR, "call_ptr", RK2_PTR);
	buildCall2(OP_CALL_INT64, "call_int64", RK2_I64);
	buildCall2(OP_CALL_F, "call_f", RK2_F64);
}

void VMImpl::buildCall2(VMOp Opc, const Twine& Name, llvm::VMEngine::RetKind2 RK) {
	auto B = mkOpc(Opc, Name);

	auto* CurIP = B.CreateLoad(I32Ty, VMIP, "vm.cl.ip"); CurIP->setVolatile(true);

	const bool IsVoid = (RK == RK2_VOID);
	const unsigned Base = IsVoid ? 0u : 1u;

	Value* DstSlot = nullptr;
	if (!IsVoid) {
		Value* DR = loadBC(B, CurIP, 0, "vm.cl.dr");
		Value* DMask = (RK == RK2_PTR) ? MaskPR
			: (RK == RK2_I64) ? MaskVR64
			: (RK == RK2_F64) ? MaskFR : MaskVR;
		DstSlot = deobf(B, DR, DMask, "vm.cl.ds");
	}

	// fn(Base+0), nargs(Base+1), flags(Base+2), types_lo(Base+3), types_hi(Base+4)
	Value* FnIdx = B.CreateZExt(loadBC(B, CurIP, Base + 0, "vm.cl.fi"), I32Ty, "vm.cl.fx");
	Value* NArgs = B.CreateZExt(loadBC(B, CurIP, Base + 1, "vm.cl.na"), I32Ty, "vm.cl.nx");
	// fn(Base+0), nargs(Base+1) -- flags/types removed, now in GVFTyIndices.


	Value* Callee = ConstantPointerNull::get(cast<PointerType>(PtrTy));
	if (EffCallees) {
		Value* FnIdx64 = B.CreateZExt(FnIdx, I64Ty, "vm.cl.fi64");
		Callee = B.CreateLoad(PtrTy,
			B.CreateGEP(PtrTy, EffCallees, FnIdx64, "vm.cl.cg"),
			"vm.cl.fn");

		// XOR-decode callee pointer when mask is active
		if (EffCalleeMask) {
			Value* CalInt = B.CreatePtrToInt(Callee, I64Ty, "vm.cl.ci");
			Value* Decoded = B.CreateXor(CalInt, EffCalleeMask, "vm.cl.dec");
			Callee = B.CreateIntToPtr(Decoded, PtrTy, "vm.cl.dp");
		}

	}


	// Load FTyIdx from GVFTyIndices[FnIdx].
	Value* FTyIdx = B.getInt32(0);
	if (EffFTyIndices && !UniqueFTys.empty()) {
		Value* FnIdx64b = B.CreateZExt(FnIdx, I64Ty, "vm.cl.fi64b");
		Value* FTyIdxByte = B.CreateLoad(I8Ty,
			B.CreateGEP(I8Ty, EffFTyIndices, FnIdx64b, "vm.cl.fig"),
			"vm.cl.ftyi");
		FTyIdx = B.CreateZExt(FTyIdxByte, I32Ty, "vm.cl.ftyx");
	}

	// Pre-load all MaxArgs arg slots.  The per-FTy case BBs select the right
	// register file for each argument statically (no runtime Cat switch needed).
	SmallVector<Value*, MaxArgs> PVals, IVals, I64Vs, FregVals;
	for (unsigned i = 0; i < MaxArgs; ++i) {
		// arg bytes now start at Base+2 (was Base+5).
		Value* AB = loadBC(B, CurIP, Base + 2 + i, "vm.cl.ab");
		Value* PIdx = deobf(B, AB, MaskPR, "vm.cl.pi");
		Value* VIdx = deobf(B, AB, MaskVR, "vm.cl.vi");
		Value* V64I = deobf(B, AB, MaskVR64, "vm.cl.v64i");

		Value* FIdx = deobf(B, AB, MaskFR, "vm.cl.fxi");
		PVals.push_back(ldPR(B, PIdx));
		IVals.push_back(B.CreateIntToPtr(ldVR(B, VIdx), PtrTy, "vm.cl.ivp"));
		I64Vs.push_back(B.CreateIntToPtr(ldVR64(B, V64I), PtrTy, "vm.cl.i64p"));

		FregVals.push_back(ldFR(B, FIdx));
	}





	// Advance IP: Base + 2 header bytes + nargs arg bytes  (was Base + 5).
	Value* Adv = B.CreateAdd(B.getInt32(Base + 2), NArgs, "vm.cl.adv");
	B.CreateStore(B.CreateAdd(CurIP, Adv, "vm.cl.nb"), VMIP)->setVolatile(true);


	Type* RetTy = (RK == RK2_PTR) ? (Type*)PtrTy
		: (RK == RK2_I64) ? (Type*)I64Ty
		: (RK == RK2_F64) ? (Type*)DoubleTy
		: (RK == RK2_I32) ? (Type*)I32Ty
		: (Type*)Type::getVoidTy(Ctx);

	BasicBlock* MergeBB = BasicBlock::Create(Ctx, "vm.cl.merge", HFn);

	// switch on FTyIdx -- one case per unique FunctionType.
	unsigned NFTy = (unsigned)UniqueFTys.size();
	PHINode* RetPHI = nullptr;


	// In shared engine mode, always create the PHI and switch even if
	// NFTy==0 — ensureCallFTyCases() will add cases later when subsequent
	// functions register new FunctionTypes.
	if (!IsVoid)
		RetPHI = PHINode::Create(RetTy, std::max(NFTy, 1u), "vm.cl.phi", MergeBB);

	// Default (unreachable): FTyIdx out of range.
	auto* UnreachBB = BasicBlock::Create(Ctx, "vm.cl.ur", HFn);
	IRBuilder<>(UnreachBB).CreateUnreachable();

	// Always create the switch (even with 0 cases in shared mode).
	auto* FTySW = B.CreateSwitch(FTyIdx, UnreachBB, std::max(NFTy, 1u));
	for (unsigned TIdx = 0; TIdx < NFTy; ++TIdx) {
		FunctionType* SrcFTy = UniqueFTys[TIdx];
		unsigned N = SrcFTy->getNumParams();
		bool     isVA = SrcFTy->isVarArg();

		auto* CaseBB = BasicBlock::Create(Ctx, "vm.cl.fty" + Twine(TIdx), HFn);
		FTySW->addCase(B.getInt32(TIdx), CaseBB);
		IRBuilder<> CB(CaseBB);

		SmallVector<Type*, MaxArgs> ATys;
		SmallVector<Value*, MaxArgs> CA;
		for (unsigned i = 0; i < N && i < MaxArgs; ++i) {
			Type* PT = SrcFTy->getParamType(i);
			if (PT->isFloatTy() || PT->isDoubleTy()) {
				ATys.push_back(DoubleTy);
				CA.push_back(FregVals[i]);
			}
			else {
				ATys.push_back(PtrTy);
				if (PT->isPointerTy())
					CA.push_back(PVals[i]);
				else if (PT->isIntegerTy(64))
					CA.push_back(I64Vs[i]);
				else
					CA.push_back(IVals[i]);

			}

		}


		auto* CallFTy = FunctionType::get(RetTy, ATys, isVA);
		auto* CI = CB.CreateCall(CallFTy, Callee, CA, IsVoid ? "" : "vm.cl.rv");
		if (!IsVoid && RetPHI) RetPHI->addIncoming(CI, CB.GetInsertBlock());
		CB.CreateBr(MergeBB);
	}

	// Store switch info for ensureCallFTyCases() to extend later.
	if (SharedEngineMode) {
		auto* SS = VMEngine::getSharedState(M, EngineId);
		auto& CSW = SS->CallSW[(unsigned)RK];
		CSW.SW = FTySW;
		CSW.MergeBB = MergeBB;
		CSW.RetPHI = RetPHI;
		CSW.Callee = Callee;
		CSW.RK = RK;
		CSW.PVals.assign(PVals.begin(), PVals.end());
		CSW.IVals.assign(IVals.begin(), IVals.end());
		CSW.I64Vs.assign(I64Vs.begin(), I64Vs.end());
		CSW.FregVals.assign(FregVals.begin(), FregVals.end());
	}

	IRBuilder<> MB(MergeBB);
	if (!IsVoid && DstSlot && RetPHI) {
		switch (RK) {
		case RK2_PTR: stPR(MB, DstSlot, RetPHI);  break;
		case RK2_I64: stVR64(MB, DstSlot, RetPHI); break;
		case RK2_F64: stFR(MB, DstSlot, RetPHI);  break;
		default:      stVR(MB, DstSlot, RetPHI);  break;
		}
	}
	nextInsn(MB);
}
