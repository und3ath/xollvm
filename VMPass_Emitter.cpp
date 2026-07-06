// ============================================================================
// VMPass_Emitter.cpp — Code Virtualisation pass: Bytecode Emitter impl
// ============================================================================

#include "llvm/Transforms/Obfuscator/VMPass_Emitter.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/Transforms/Obfuscator/VMPass_ISA.h"

using namespace llvm;

#define DEBUG_TYPE "vm"

STATISTIC(VMBytecodeBytes, "Total bytecode bytes emitted (v7)");
STATISTIC(VMVirtRegs, "Virtual register slots allocated (v7)");

// isize / bsize / emit(Instruction) / emit(BasicBlock) / run() 

uint32_t BytecodeEmitter::isize(Instruction* I) {
	if (isa<AllocaInst>(I) || isa<UnreachableInst>(I)) return 0;
	unsigned Op = I->getOpcode(); Type* Ty = I->getType();
	// i32/i64 binops (separate opcodes for i32 vs i64)
	if (Op == Instruction::Add || Op == Instruction::Sub || Op == Instruction::Mul ||
		Op == Instruction::And || Op == Instruction::Or || Op == Instruction::Xor ||
		Op == Instruction::Shl || Op == Instruction::LShr || Op == Instruction::AShr ||
		Op == Instruction::SDiv || Op == Instruction::UDiv ||
		Op == Instruction::SRem || Op == Instruction::URem) {
		if (Ty->isIntegerTy(32) || Ty->isIntegerTy(64)) return 5;
		markUnsupported(I); return 0;
	}
	// float binary ops
	if (Op == Instruction::FAdd || Op == Instruction::FSub ||
		Op == Instruction::FMul || Op == Instruction::FDiv || Op == Instruction::FRem) {
		if (Ty->isFloatTy() || Ty->isDoubleTy()) return 5;
		markUnsupported(I); return 0;
	}

	// fneg operator
	if (Op == Instruction::FNeg)
	{
		if (Ty->isFloatTy() || Ty->isDoubleTy()) return 3;
		markUnsupported(I); return 0;
	}

	// FCmp
	if (Op == Instruction::FCmp) {
		Type* T0 = I->getOperand(0)->getType();
		if (T0->isFloatTy() || T0->isDoubleTy()) return 5;
		markUnsupported(I); return 0;
	}
	// float casts
	if (Op == Instruction::FPExt || Op == Instruction::FPTrunc) {
		Type* ST = I->getOperand(0)->getType();
		if ((ST->isFloatTy() || ST->isDoubleTy()) && (Ty->isFloatTy() || Ty->isDoubleTy())) return 4;
		markUnsupported(I); return 0;
	}
	if (Op == Instruction::FPToSI || Op == Instruction::FPToUI) {
		Type* ST = I->getOperand(0)->getType();
		if (!(ST->isFloatTy() || ST->isDoubleTy())) { markUnsupported(I); return 0; }
		if (Ty->isIntegerTy(32) || Ty->isIntegerTy(64)) return 4;
		markUnsupported(I); return 0;
	}
	if (Op == Instruction::SIToFP || Op == Instruction::UIToFP) {
		Type* ST = I->getOperand(0)->getType();
		if (!(Ty->isFloatTy() || Ty->isDoubleTy())) { markUnsupported(I); return 0; }
		if (ST->isIntegerTy(32) || ST->isIntegerTy(64)) return 4;
		markUnsupported(I); return 0;
	}

	if (Op == Instruction::ICmp) {
		auto* CI = cast<ICmpInst>(I);
		Type* T0 = CI->getOperand(0)->getType();
		Type* T1 = CI->getOperand(1)->getType();
		if (T0->isIntegerTy(32) && T1->isIntegerTy(32)) return 5;
		if (T0->isIntegerTy(64) && T1->isIntegerTy(64)) return 5;
		markUnsupported(I); return 0;
	}

	if (Op == Instruction::ZExt) {
		unsigned W = I->getOperand(0)->getType()->getIntegerBitWidth();
		if (Ty->isIntegerTy(32) && (W == 1 || W == 8 || W == 16)) return 4;
		if (Ty->isIntegerTy(64) && (W == 1 || W == 8 || W == 16 || W == 32)) return 4;
		markUnsupported(I); return 0;
	}
	if (Op == Instruction::SExt) {
		unsigned W = I->getOperand(0)->getType()->getIntegerBitWidth();
		if (Ty->isIntegerTy(32) && (W == 8 || W == 16)) return 4;
		if (Ty->isIntegerTy(64) && (W == 8 || W == 16 || W == 32)) return 4;
		markUnsupported(I); return 0;
	}
	if (Op == Instruction::Trunc) {
		unsigned W = Ty->getIntegerBitWidth();
		Type* STy = I->getOperand(0)->getType();
		if (STy->isIntegerTy(32) && (W == 1 || W == 8 || W == 16)) return 4;
		if (STy->isIntegerTy(64) && (W == 1 || W == 8 || W == 16 || W == 32)) return 4;
		markUnsupported(I); return 0;
	}
	if (Op == Instruction::Select) {
		auto* SI = cast<SelectInst>(I);
		Type* RT = SI->getType();
		Type* CT = SI->getCondition()->getType();
		if (!CT->isIntegerTy() || CT->getIntegerBitWidth() > 32) { markUnsupported(I); return 0; }

		// Integer select (<=32) -> vreg file
		if (RT->isIntegerTy() && RT->getIntegerBitWidth() <= 32) {
			if (!SI->getTrueValue()->getType()->isIntegerTy() ||
				!SI->getFalseValue()->getType()->isIntegerTy()) {
				markUnsupported(I); return 0;
			}
			if (SI->getTrueValue()->getType()->getIntegerBitWidth() != RT->getIntegerBitWidth() ||
				SI->getFalseValue()->getType()->getIntegerBitWidth() != RT->getIntegerBitWidth()) {
				markUnsupported(I); return 0;
			}
			return 6; // opcode + kind + dst + cond + t + f
		}

		// i64 select -> vreg64 file
		if (RT->isIntegerTy(64)) {
			if (!SI->getTrueValue()->getType()->isIntegerTy(64) ||
				!SI->getFalseValue()->getType()->isIntegerTy(64)) {
				markUnsupported(I); return 0;
			}
			return 6;
		}

		// float select
		if (RT->isFloatTy() || RT->isDoubleTy()) return 5;


		// Pointer select -> preg file
		if (RT->isPointerTy()) {
			if (!SI->getTrueValue()->getType()->isPointerTy() ||
				!SI->getFalseValue()->getType()->isPointerTy()) {
				markUnsupported(I); return 0;
			}
			return 6;
		}

		markUnsupported(I);
		return 0;
	}

	if (Op == Instruction::PtrToInt) {
		if (Ty->isIntegerTy(32) || Ty->isIntegerTy(64)) return 3;
		markUnsupported(I); return 0;
	}
	if (Op == Instruction::IntToPtr) {
		if (Ty->isPointerTy() && I->getOperand(0)->getType()->isIntegerTy(32)) return 3;
		markUnsupported(I); return 0;
	}
	if (Op == Instruction::Load) {
		if (Ty->isIntegerTy(8) || Ty->isIntegerTy(16) ||
			Ty->isIntegerTy(32) || Ty->isIntegerTy(64) ||
			Ty->isPointerTy() ||
			Ty->isDoubleTy())
			return 3;
		if (Ty->isFloatTy()) return 3;  // OP_LOAD_F32 — same encoding, different width semantics
		markUnsupported(I);
		return 0;
	}
	if (Op == Instruction::Store) {
		auto* SI = cast<StoreInst>(I);
		Type* VT = SI->getValueOperand()->getType();
		if (VT->isIntegerTy(8) || VT->isIntegerTy(16) ||
			VT->isIntegerTy(32) || VT->isIntegerTy(64) ||
			VT->isPointerTy())
			return 3;
		if (VT->isDoubleTy()) return 3;        // OP_STORE_F  — 8-byte	
		if (VT->isFloatTy())  return 3;        // OP_STORE_F32 — 4-byte  
		markUnsupported(I);
		return 0;
	}
	if (Op == Instruction::GetElementPtr) {
		auto* GEP = cast<GetElementPtrInst>(I);
		if (!Ty->isPointerTy()) { markUnsupported(I); return 0; }

		// Accept:
		//  (1) gep ..., base, idx
		//  (2) gep ..., base, 0, idx   (array decay pattern)
		Value* IdxV = nullptr;
		if (GEP->getNumIndices() == 1) {
			IdxV = *GEP->idx_begin();

		}
		else if (GEP->getNumIndices() == 2) {
			auto It = GEP->idx_begin();
			Value* I0 = *It++;
			Value* I1 = *It++;
			auto* C0 = dyn_cast<ConstantInt>(I0);
			if (!C0 || !C0->isZero()) { markUnsupported(I); return 0; }
			IdxV = I1;

		}
		else {
			markUnsupported(I); return 0;

		}

		Type* IT = IdxV->getType();
		if (!(IT->isIntegerTy(32) || IT->isIntegerTy(64))) { markUnsupported(I); return 0; }
		return 6;
	}
	if (Op == Instruction::Call) {
		auto* CI = cast<CallInst>(I); unsigned NA = CI->arg_size();

		if (auto* F = CI->getCalledFunction())
			if (F->isIntrinsic()) { markUnsupported(I); return 0; }


		if (auto* CF = CI->getCalledFunction()) {
			StringRef FName = CF->getName();
			Type* RT = CI->getType();
			if (NA == 2 && (FName == "fmodf" || FName == "fmod") &&
				(RT->isFloatTy() || RT->isDoubleTy())) return 5;
		}


		// accept i32, ptr, i64, and f64 args (freg path reserved for future)
		for (unsigned A = 0; A < NA; ++A) {
			Type* AT = CI->getArgOperand(A)->getType();
			if (AT->isPointerTy()) continue;
			if (AT->isIntegerTy() && AT->getIntegerBitWidth() <= 32) continue;
			if (AT->isIntegerTy(64)) continue;             // vreg64
			if (AT->isFloatTy() || AT->isDoubleTy()) continue;  // freg
			markUnsupported(I); return 0;
		}
		if (NA > 16) { markUnsupported(I, "CALL arg count exceeds MaxArgs (16)"); return 0; }
		// encoding: [dst?] fn:u8 nargs:u8 flags:u8 types:u16le [arg:u8 * nargs]
		// flags(1) + types(2) = 3 header bytes (was 2: nargs + types_u8)
		const unsigned Hdr = 3 + NA;  // fn + nargs + flags + types_lo + types_hi + args... wait
		// Actually: fn(1) + nargs(1) + flags(1) + types_lo(1) + types_hi(1) + args(NA) = 5+NA
		(void)Hdr;
		if (Ty->isVoidTy())         return 6 + NA;  // opc + fn + nargs + flags + tylo + tyhi + args
		if (Ty->isIntegerTy(32) || Ty->isPointerTy()) return 7 + NA;  // dst + above
		if (Ty->isIntegerTy(64))    return 7 + NA;  // OP_CALL_INT64
		if (Ty->isFloatTy() || Ty->isDoubleTy()) return 7 + NA;  // OP_CALL_F
		markUnsupported(I); return 0;
	}
	if (Op == Instruction::Br)
		return cast<BranchInst>(I)->isUnconditional() ? 5 : 10;

	if (Op == Instruction::Switch) {
		auto* SI = cast<SwitchInst>(I);
		// i32 switches only (condition lives in i32 vreg file)
		if (!SI->getCondition()->getType()->isIntegerTy(32)) { markUnsupported(I); return 0; }
		unsigned NC = SI->getNumCases();
		if (NC > 0xFFFFu) { markUnsupported(I); return 0; }
		// Encoding size = 1(opc) + 1(cond) + 2(ncases) + 4(def) + NC*(4+4)
		return 8u + (uint32_t)NC * 8u;
	}


	if (Op == Instruction::Ret) {
		auto* RI = cast<ReturnInst>(I);
		Value* RV = RI->getReturnValue();
		if (!RV) return 1;
		Type* RT = RV->getType();
		if (RT->isPointerTy()) return 2;
		if (RT->isIntegerTy() && RT->getIntegerBitWidth() <= 32) return 2;
		if (RT->isIntegerTy(64)) return 2;                    // OP_RET_INT vreg64 
		if (RT->isFloatTy() || RT->isDoubleTy()) return 2;    // OP_RET_F freg

		markUnsupported(I); return 0;
	}
	markUnsupported(I);
	return 0;

}

uint32_t BytecodeEmitter::bsize(BasicBlock* BB) {
	uint32_t S = 0; for (Instruction& I : *BB) S += isize(&I); return S;
}


void BytecodeEmitter::emit(Instruction* I) {
	if (isa<AllocaInst>(I) || isa<UnreachableInst>(I))
		return;


	unsigned Op = I->getOpcode();
	Type* Ty = I->getType();


	if (Op == Instruction::Add || Op == Instruction::Sub || Op == Instruction::Mul ||
		Op == Instruction::And || Op == Instruction::Or || Op == Instruction::Xor ||
		Op == Instruction::Shl || Op == Instruction::LShr || Op == Instruction::AShr ||
		Op == Instruction::SDiv || Op == Instruction::UDiv ||
		Op == Instruction::SRem || Op == Instruction::URem) {
		if (!(Ty->isIntegerTy(32) || Ty->isIntegerTy(64))) { markUnsupported(I); return; }
		const bool Is64 = Ty->isIntegerTy(64);
		static const unsigned OL[] = { Instruction::Add,Instruction::Sub,Instruction::Mul,
			Instruction::And,Instruction::Or,Instruction::Xor,
			Instruction::Shl,Instruction::LShr,Instruction::AShr,
			Instruction::SDiv,Instruction::UDiv,Instruction::SRem,Instruction::URem };
		static const BinSubop SL[] = { BS_ADD,BS_SUB,BS_MUL,BS_AND,
										BS_OR,BS_XOR,BS_SHL,BS_LSHR,BS_ASHR,
										BS_SDIV,BS_UDIV,BS_SREM,BS_UREM };
		BinSubop Sub = BS_ADD;
		for (int i = 0; i < 13; i++) {
			if (OL[i] == Op)
			{
				Sub = SL[i]; break;
			}
		}

		bop(Is64 ? OP_BINOP64 : OP_BINOP);
		b8(xorSalt(Is64 ? newVR64(I) : newVR(I)));
		b8(xorSalt(Is64 ? vr64(I->getOperand(0)) : vr(I->getOperand(0))));
		b8(xorSalt(Is64 ? vr64(I->getOperand(1)) : vr(I->getOperand(1))));
		b8(Sub); return;
	}



	// SUPPORT FOR FNEG
	if (Op == Instruction::FNeg) {
		if (!(Ty->isFloatTy() || Ty->isDoubleTy())) {
			markUnsupported(I);
			return;
		}
		bop(OP_FNEG);
		b8(xorSalt(newFR(I)));             // Encrypted destination freg index
		b8(xorSalt(fr(I->getOperand(0)))); // Encrypted source freg index
		return;
	}


	// float binary ops
	if (Op == Instruction::FAdd || Op == Instruction::FSub ||
		Op == Instruction::FMul || Op == Instruction::FDiv || Op == Instruction::FRem) {
		if (!(Ty->isFloatTy() || Ty->isDoubleTy())) { markUnsupported(I); return; }
		const unsigned FOL[] = { Instruction::FAdd, Instruction::FSub,
			Instruction::FMul, Instruction::FDiv, Instruction::FRem };
		const FBinSubop FSL[] = { FBS_FADD, FBS_FSUB, FBS_FMUL, FBS_FDIV, FBS_FREM };
		FBinSubop FSub = FBS_FADD;
		for (int i = 0; i < 5; i++) if (FOL[i] == Op) { FSub = FSL[i]; break; }
		// Bit 7 (FBS_F32_FLAG): round f64 result to f32 precision.
		// Set when the source instruction has float (not double) type.
		uint8_t FSubByte = (uint8_t)FSub;
		if (Ty->isFloatTy()) FSubByte |= (uint8_t)FBS_F32_FLAG;
		bop(OP_BINOP_F);
		b8(xorSalt(newFR(I))); b8(xorSalt(fr(I->getOperand(0)))); b8(xorSalt(fr(I->getOperand(1)))); b8(FSubByte); return;
	}



	// FCmp
	if (Op == Instruction::FCmp) {
		auto* FCI = cast<FCmpInst>(I);
		Type* T0 = FCI->getOperand(0)->getType();
		if (!(T0->isFloatTy() || T0->isDoubleTy())) { markUnsupported(I); return; }
		bop(OP_FCMP);
		b8(xorSalt(newVR(I))); b8(xorSalt(fr(FCI->getOperand(0)))); b8(xorSalt(fr(FCI->getOperand(1)))); b8((uint8_t)FCI->getPredicate()); return;
	}


	// float casts
	if (Op == Instruction::FPExt) {
		Type* ST = I->getOperand(0)->getType();
		if (!((ST->isFloatTy() || ST->isDoubleTy()) && (Ty->isFloatTy() || Ty->isDoubleTy()))) { markUnsupported(I); return; }
		bop(OP_FCAST_FF); b8(xorSalt(newFR(I))); b8(xorSalt(fr(I->getOperand(0)))); b8(FK_FPEXT); return;
	}
	if (Op == Instruction::FPTrunc) {
		Type* ST = I->getOperand(0)->getType();
		if (!((ST->isFloatTy() || ST->isDoubleTy()) && (Ty->isFloatTy() || Ty->isDoubleTy()))) { markUnsupported(I); return; }
		bop(OP_FCAST_FF); b8(xorSalt(newFR(I))); b8(xorSalt(fr(I->getOperand(0)))); b8(FK_FPTRUNC); return;
	}
	if (Op == Instruction::FPToSI) {
		Type* ST = I->getOperand(0)->getType();
		if (!(ST->isFloatTy() || ST->isDoubleTy())) { markUnsupported(I); return; }
		if (Ty->isIntegerTy(32)) { bop(OP_FCAST_FV);   b8(xorSalt(newVR(I)));   b8(xorSalt(fr(I->getOperand(0)))); b8(FK_FPTOSI);   return; }
		if (Ty->isIntegerTy(64)) { bop(OP_FCAST_FV64); b8(xorSalt(newVR64(I))); b8(xorSalt(fr(I->getOperand(0)))); b8(FK_FPTOSI64); return; }
		markUnsupported(I); return;
	}
	if (Op == Instruction::FPToUI) {
		Type* ST = I->getOperand(0)->getType();
		if (!(ST->isFloatTy() || ST->isDoubleTy())) { markUnsupported(I); return; }
		if (Ty->isIntegerTy(32)) { bop(OP_FCAST_FV);   b8(xorSalt(newVR(I)));   b8(xorSalt(fr(I->getOperand(0)))); b8(FK_FPTOUI);   return; }
		if (Ty->isIntegerTy(64)) { bop(OP_FCAST_FV64); b8(xorSalt(newVR64(I))); b8(xorSalt(fr(I->getOperand(0)))); b8(FK_FPTOUI64); return; }
		markUnsupported(I); return;
	}
	if (Op == Instruction::SIToFP) {
		if (!(Ty->isFloatTy() || Ty->isDoubleTy())) { markUnsupported(I); return; }
		Type* ST = I->getOperand(0)->getType();
		if (ST->isIntegerTy(32)) { uint8_t K = FK_SITOFP;   if (Ty->isFloatTy()) K |= FCAST_F32_FLAG; bop(OP_FCAST_VF);   b8(xorSalt(newFR(I))); b8(xorSalt(vr(I->getOperand(0))));   b8(K); return; }
		if (ST->isIntegerTy(64)) { uint8_t K = FK_SI64TOFP; if (Ty->isFloatTy()) K |= FCAST_F32_FLAG; bop(OP_FCAST_V64F); b8(xorSalt(newFR(I))); b8(xorSalt(vr64(I->getOperand(0)))); b8(K); return; }
		markUnsupported(I); return;
	}
	if (Op == Instruction::UIToFP) {
		if (!(Ty->isFloatTy() || Ty->isDoubleTy())) { markUnsupported(I); return; }
		Type* ST = I->getOperand(0)->getType();
		if (ST->isIntegerTy(32)) { uint8_t K = FK_UITOFP;   if (Ty->isFloatTy()) K |= FCAST_F32_FLAG; bop(OP_FCAST_VF);   b8(xorSalt(newFR(I))); b8(xorSalt(vr(I->getOperand(0))));   b8(K); return; }
		if (ST->isIntegerTy(64)) { uint8_t K = FK_UI64TOFP; if (Ty->isFloatTy()) K |= FCAST_F32_FLAG; bop(OP_FCAST_V64F); b8(xorSalt(newFR(I))); b8(xorSalt(vr64(I->getOperand(0)))); b8(K); return; }
		markUnsupported(I); return;
	}


	if (Op == Instruction::ICmp) {
		auto* CI = cast<ICmpInst>(I);
		Type* T0 = CI->getOperand(0)->getType();
		Type* T1 = CI->getOperand(1)->getType();

		if (T0->isIntegerTy(32) && T1->isIntegerTy(32)) {
			bop(OP_ICMP);
			b8(xorSalt(newVR(I)));
			b8(xorSalt(vr(CI->getOperand(0))));
			b8(xorSalt(vr(CI->getOperand(1))));
			b8((uint8_t)CI->getPredicate());
			return;
		}
		if (T0->isIntegerTy(64) && T1->isIntegerTy(64)) {
			bop(OP_ICMP64);
			b8(xorSalt(newVR(I)));
			b8(xorSalt(vr64(CI->getOperand(0))));
			b8(xorSalt(vr64(CI->getOperand(1))));
			b8((uint8_t)CI->getPredicate());
			return;

		}

		markUnsupported(I);
		return;
	}


	if (Op == Instruction::ZExt) {
		unsigned W = I->getOperand(0)->getType()->getIntegerBitWidth();
		if (Ty->isIntegerTy(32)) {
			if (W != 1 && W != 8 && W != 16) { markUnsupported(I); return; }
			CastKind K = (W == 1) ? CK_ZEXT1 : (W == 8) ? CK_ZEXT8 : CK_ZEXT16;
			bop(OP_CAST); b8(xorSalt(newVR(I))); b8(xorSalt(vr(I->getOperand(0)))); b8(K); return;
		}
		if (Ty->isIntegerTy(64)) {
			Cast64Kind K =
				(W == 1) ? C64_ZEXT1 :
				(W == 8) ? C64_ZEXT8 :
				(W == 16) ? C64_ZEXT16 :
				(W == 32) ? C64_ZEXT32 : (Cast64Kind)0xFF;
			if ((uint8_t)K == 0xFF) { markUnsupported(I); return; }
			bop(OP_CAST64); b8(xorSalt(newVR64(I))); b8(xorSalt(vr(I->getOperand(0)))); b8(K); return;
		}
		markUnsupported(I); return;
	}
	if (Op == Instruction::SExt) {
		unsigned W = I->getOperand(0)->getType()->getIntegerBitWidth();
		if (Ty->isIntegerTy(32)) {
			if (W != 8 && W != 16) { markUnsupported(I); return; }
			CastKind K = (W == 8) ? CK_SEXT8 : CK_SEXT16;
			bop(OP_CAST); b8(xorSalt(newVR(I))); b8(xorSalt(vr(I->getOperand(0)))); b8(K); return;
		}
		if (Ty->isIntegerTy(64)) {
			Cast64Kind K =
				(W == 8) ? C64_SEXT8 :
				(W == 16) ? C64_SEXT16 :
				(W == 32) ? C64_SEXT32 : (Cast64Kind)0xFF;
			if ((uint8_t)K == 0xFF) { markUnsupported(I); return; }
			bop(OP_CAST64); b8(xorSalt(newVR64(I))); b8(xorSalt(vr(I->getOperand(0)))); b8(K); return;
		}
		markUnsupported(I); return;
	}
	if (Op == Instruction::Trunc) {
		unsigned W = Ty->getIntegerBitWidth();
		Type* STy = I->getOperand(0)->getType();
		if (STy->isIntegerTy(32)) {
			if (W != 1 && W != 8 && W != 16) { markUnsupported(I); return; }
			CastKind K = (W == 1) ? CK_TRUNC1 : (W == 8) ? CK_TRUNC8 : CK_TRUNC16;
			bop(OP_CAST); b8(xorSalt(newVR(I))); b8(xorSalt(vr(I->getOperand(0)))); b8(K); return;
		}
		if (STy->isIntegerTy(64)) {
			Cast64Kind K =
				(W == 1) ? C64_TRUNC1 :
				(W == 8) ? C64_TRUNC8 :
				(W == 16) ? C64_TRUNC16 :
				(W == 32) ? C64_TRUNC32 : (Cast64Kind)0xFF;
			if ((uint8_t)K == 0xFF) { markUnsupported(I); return; }
			bop(OP_CAST64); b8(xorSalt(newVR(I))); b8(xorSalt(vr64(I->getOperand(0)))); b8(K); return;
		}
		markUnsupported(I); return;
	}


	if (Op == Instruction::Select) {
		auto* SI = cast<SelectInst>(I);
		Type* RT = SI->getType();
		Type* CT = SI->getCondition()->getType();
		if (!CT->isIntegerTy() || CT->getIntegerBitWidth() > 32) { markUnsupported(I); return; }

		if (RT->isIntegerTy() && RT->getIntegerBitWidth() <= 32) {
			if (!SI->getTrueValue()->getType()->isIntegerTy() ||
				!SI->getFalseValue()->getType()->isIntegerTy()) {
				markUnsupported(I); return;
			}
			if (SI->getTrueValue()->getType()->getIntegerBitWidth() != RT->getIntegerBitWidth() ||
				SI->getFalseValue()->getType()->getIntegerBitWidth() != RT->getIntegerBitWidth()) {
				markUnsupported(I); return;
			}

			bop(OP_SELECT);
			b8(0); // kind 0 = int (vreg file)
			b8(xorSalt(newVR(I)));
			b8(xorSalt(vr(SI->getCondition())));
			b8(xorSalt(vr(SI->getTrueValue())));
			b8(xorSalt(vr(SI->getFalseValue())));
			return;
		}

		if (RT->isPointerTy()) {
			if (!SI->getTrueValue()->getType()->isPointerTy() ||
				!SI->getFalseValue()->getType()->isPointerTy()) {
				markUnsupported(I); return;
			}

			bop(OP_SELECT);
			b8(1); // kind 1 = ptr (preg file)
			b8(xorSalt(newPR(I)));
			b8(xorSalt(vr(SI->getCondition())));
			b8(xorSalt(pr(SI->getTrueValue())));
			b8(xorSalt(pr(SI->getFalseValue())));
			return;
		}

		if (RT->isIntegerTy(64)) {
			if (!SI->getTrueValue()->getType()->isIntegerTy(64) ||
				!SI->getFalseValue()->getType()->isIntegerTy(64)) {
				markUnsupported(I); return;
			}
			bop(OP_SELECT);
			b8(2); // kind 2 = i64 (vreg64 file)
			b8(xorSalt(newVR64(I)));
			b8(xorSalt(vr(SI->getCondition())));
			b8(xorSalt(vr64(SI->getTrueValue())));
			b8(xorSalt(vr64(SI->getFalseValue())));
			return;
		}

		// float select → OP_SELECT_F
		if (RT->isFloatTy() || RT->isDoubleTy()) {
			if (!(SI->getTrueValue()->getType()->isFloatTy() || SI->getTrueValue()->getType()->isDoubleTy()) ||
				!(SI->getFalseValue()->getType()->isFloatTy() || SI->getFalseValue()->getType()->isDoubleTy())) {
				markUnsupported(I); return;
			}
			bop(OP_SELECT_F);
			b8(xorSalt(newFR(I))); b8(xorSalt(vr(SI->getCondition())));
			b8(xorSalt(fr(SI->getTrueValue()))); b8(xorSalt(fr(SI->getFalseValue())));
			return;

		}


		markUnsupported(I);
		return;
	}





	if (Op == Instruction::PtrToInt && Ty->isIntegerTy(32)) {
		bop(OP_PTRTOINT); b8(xorSalt(newVR(I))); b8(xorSalt(pr(I->getOperand(0)))); return;
	}
	if (Op == Instruction::PtrToInt && Ty->isIntegerTy(64)) {
		bop(OP_PTRTOINT64); b8(xorSalt(newVR64(I))); b8(xorSalt(pr(I->getOperand(0)))); return;
	}
	if (Op == Instruction::IntToPtr && Ty->isPointerTy()) {
		if (!I->getOperand(0)->getType()->isIntegerTy(32)) { markUnsupported(I); return; }
		bop(OP_INTTOPTR); b8(xorSalt(newPR(I))); b8(xorSalt(vr(I->getOperand(0)))); return;
	}
	if (Op == Instruction::Load && Ty->isIntegerTy(8)) {
		bop(OP_LOAD8); b8(xorSalt(newVR(I))); b8(xorSalt(pr(cast<LoadInst>(I)->getPointerOperand()))); return;
	}
	if (Op == Instruction::Load && Ty->isIntegerTy(16)) {
		bop(OP_LOAD16); b8(xorSalt(newVR(I))); b8(xorSalt(pr(cast<LoadInst>(I)->getPointerOperand()))); return;
	}
	if (Op == Instruction::Load && Ty->isIntegerTy(32)) {
		bop(OP_LOAD32); b8(xorSalt(newVR(I))); b8(xorSalt(pr(cast<LoadInst>(I)->getPointerOperand()))); return;
	}
	if (Op == Instruction::Load && Ty->isIntegerTy(64)) {
		bop(OP_LOAD64); b8(xorSalt(newVR64(I))); b8(xorSalt(pr(cast<LoadInst>(I)->getPointerOperand()))); return;
	}
	if (Op == Instruction::Load && Ty->isPointerTy()) {
		bop(OP_LOADPTR); b8(xorSalt(newPR(I))); b8(xorSalt(pr(cast<LoadInst>(I)->getPointerOperand()))); return;
	}
	// load f64 → OP_LOAD_F (8-byte); load f32 → OP_LOAD_F32 (4-byte)
	// in run() widens local float allocas to double, so most float loads
	// will have been converted to double loads before reaching here.  Any surviving
	// float load (e.g. from a float* parameter) is correctly handled by OP_LOAD_F32.
	if (Op == Instruction::Load && (Ty->isFloatTy() || Ty->isDoubleTy())) {
		VMOp LoadOp = Ty->isFloatTy() ? OP_LOAD_F32 : OP_LOAD_F;
		bop(LoadOp); b8(xorSalt(newFR(I))); b8(xorSalt(pr(cast<LoadInst>(I)->getPointerOperand()))); return;
	}

	if (Op == Instruction::Store) {
		auto* SI = cast<StoreInst>(I);
		Type* VT = SI->getValueOperand()->getType();
		if (VT->isIntegerTy(8)) {
			bop(OP_STORE8); b8(xorSalt(vr(SI->getValueOperand()))); b8(xorSalt(pr(SI->getPointerOperand()))); return;
		}
		if (VT->isIntegerTy(16)) {
			bop(OP_STORE16); b8(xorSalt(vr(SI->getValueOperand()))); b8(xorSalt(pr(SI->getPointerOperand()))); return;
		}
		if (VT->isIntegerTy(32)) {
			bop(OP_STORE32); b8(xorSalt(vr(SI->getValueOperand()))); b8(xorSalt(pr(SI->getPointerOperand()))); return;
		}
		if (VT->isIntegerTy(64)) {
			bop(OP_STORE64); b8(xorSalt(vr64(SI->getValueOperand()))); b8(xorSalt(pr(SI->getPointerOperand()))); return;
		}
		if (VT->isPointerTy()) {
			bop(OP_STOREPTR); b8(xorSalt(pr(SI->getValueOperand()))); b8(xorSalt(pr(SI->getPointerOperand()))); return;
		}
		// store f64 → OP_STORE_F (8-byte); store f32 → OP_STORE_F32 (4-byte)
		if (VT->isFloatTy() || VT->isDoubleTy()) {
			VMOp StoreOp = VT->isFloatTy() ? OP_STORE_F32 : OP_STORE_F;
			bop(StoreOp); b8(xorSalt(fr(SI->getValueOperand()))); b8(xorSalt(pr(SI->getPointerOperand()))); return;
		}

		markUnsupported(I); return;
	}
	if (Op == Instruction::GetElementPtr && Ty->isPointerTy()) {
		auto* GEP = cast<GetElementPtrInst>(I);

		// Accept:
		//  (1) gep ..., base, idx
		//  (2) gep ..., base, 0, idx
		Value* IdxV = nullptr;
		if (GEP->getNumIndices() == 1) {
			IdxV = *GEP->idx_begin();
		}
		else if (GEP->getNumIndices() == 2) {
			auto It = GEP->idx_begin();
			Value* I0 = *It++;
			Value* I1 = *It++;
			auto* C0 = dyn_cast<ConstantInt>(I0);
			if (!C0 || !C0->isZero()) { markUnsupported(I); return; }
			IdxV = I1;
		}
		else {
			markUnsupported(I); return;
		}

		Type* IT = IdxV->getType();
		const bool IdxIs64 = IT->isIntegerTy(64);
		if (!(IT->isIntegerTy(32) || IdxIs64)) { markUnsupported(I); return; }

		// Encode element size as u16le so the interpreter can compute the byte offset.
		// Use result element type (works for both ptr-to-T and ptr-to-[N x T] with leading 0 index).
		Type* ElemTy = GEP->getResultElementType();
		uint64_t ESz = DL->getTypeStoreSize(ElemTy);
		uint16_t ElemSz = (ESz > 0xFFFFu) ? 0xFFFFu : (uint16_t)ESz;
		bop(IdxIs64 ? OP_GEP64 : OP_GEP);
		b8(xorSalt(newPR(I)));
		b8(xorSalt(pr(GEP->getPointerOperand())));
		b8(xorSalt(IdxIs64 ? vr64(IdxV) : vr(IdxV)));
		b8((uint8_t)(ElemSz & 0xFF));          // elemsz lo
		b8((uint8_t)(ElemSz >> 8));            // elemsz hi
		return;
	}






	if (Op == Instruction::Call) {
		auto* CI = cast<CallInst>(I);
		// validate args (i32 / ptr / i64 / f64)


		// Lower fmodf/fmod directly to OP_BINOP_F/FBS_FREM — ptr ABI is wrong for XMM args.
		if (auto* CF = CI->getCalledFunction()) {
			StringRef FName = CF->getName();
			Type* RT = CI->getType();
			if (CI->arg_size() == 2 &&
				(FName == "fmodf" || FName == "fmod") &&
				(RT->isFloatTy() || RT->isDoubleTy())) {
				uint8_t FSubByte = (uint8_t)FBS_FREM;
				if (RT->isFloatTy()) FSubByte |= (uint8_t)FBS_F32_FLAG;
				bop(OP_BINOP_F);
				b8(xorSalt(newFR(CI)));
				b8(xorSalt(fr(CI->getArgOperand(0))));
				b8(xorSalt(fr(CI->getArgOperand(1))));
				b8(FSubByte); return;
			}
		}


		if (auto* F = CI->getCalledFunction())
			if (F->isIntrinsic()) { markUnsupported(I); return; }

		for (unsigned A = 0; A < CI->arg_size(); ++A) {
			Type* AT = CI->getArgOperand(A)->getType();
			if (AT->isPointerTy() || (AT->isIntegerTy() && AT->getIntegerBitWidth() <= 32)
				|| AT->isIntegerTy(64) || AT->isFloatTy() || AT->isDoubleTy()) continue;
			markUnsupported(I); return;
		}
		Value* Fn = CI->getCalledFunction()
			? static_cast<Value*>(CI->getCalledFunction())
			: CI->getCalledOperand();
		// build a concrete FunctionType from the actual call args so that
		// SrcFTy->getNumParams() covers all args (fixed + vararg) at dispatch.
		// CI->getFunctionType() only has the fixed params (e.g. i32(i8*, ...)).
		SmallVector<Type*, 16> ConcreteArgTys;
		for (unsigned A = 0; A < CI->arg_size(); ++A)
			ConcreteArgTys.push_back(CI->getArgOperand(A)->getType());
		FunctionType* ConcreteFTy = FunctionType::get(
			CI->getType(), ConcreteArgTys, CI->getFunctionType()->isVarArg());
		uint8_t FI = callee(Fn, ConcreteFTy);
		unsigned NAw = CI->arg_size();
		if (NAw > 16) {
			markUnsupported(I, "CALL arg count exceeds MaxArgs (16)");
			return;
			
		}
		uint8_t NA = (uint8_t)NAw;



		// Emit opcode + optional dst slot
		if (Ty->isVoidTy()) {
			bop(OP_CALL_VOID);
		}
		else if (Ty->isIntegerTy(32)) {
			bop(OP_CALL_INT);   b8(xorSalt(newVR(I)));
		}
		else if (Ty->isPointerTy()) {
			bop(OP_CALL_PTR);   b8(xorSalt(newPR(I)));
		}
		else if (Ty->isIntegerTy(64)) {
			bop(OP_CALL_INT64); b8(xorSalt(newVR64(I)));
		}
		else if (Ty->isFloatTy() || Ty->isDoubleTy()) {
			bop(OP_CALL_F);     b8(xorSalt(newFR(I)));
		}
		else { markUnsupported(I); return; }
		// Common header: fn, nargs  (flags/argtypes removed -- now in GVFTyIndices)
		b8(FI); b8(NA);

		// Per-arg register indices
		for (unsigned A = 0; A < NA; ++A) {
			Value* Arg = CI->getArgOperand(A);
			Type* AT = Arg->getType();
			if (AT->isPointerTy())                        b8(xorSalt(pr(Arg)));
			else if (AT->isIntegerTy(64))                 b8(xorSalt(vr64(Arg)));
			else if (AT->isFloatTy() || AT->isDoubleTy()) b8(xorSalt(fr(Arg)));
			else										  b8(xorSalt(vr(Arg)));
		}
		return;
	}


	if (Op == Instruction::Br) {
		auto* BI = cast<BranchInst>(I);
		if (BI->isUnconditional()) {
			bop(OP_JMP); fixup_u32(BI->getSuccessor(0));
		}
		else {
			bop(OP_JMPC); b8(xorSalt(vr(BI->getCondition())));
			fixup_u32(BI->getSuccessor(0));
			fixup_u32(BI->getSuccessor(1));
		}
		return;
	}


	if (Op == Instruction::Switch) {
		auto* SI = cast<SwitchInst>(I);
		if (!SI->getCondition()->getType()->isIntegerTy(32)) { markUnsupported(I); return; }
		unsigned NC = SI->getNumCases();
		if (NC > 0xFFFFu) { markUnsupported(I); return; }

		bop(OP_SWITCH);
		b8(xorSalt(vr(SI->getCondition())));
		u16((uint16_t)NC);
		fixup_u32(SI->getDefaultDest());
		for (auto& C : SI->cases()) {
			auto* CV = C.getCaseValue();
			// i32 only here, so case value is always <=32b
			u32((uint32_t)CV->getZExtValue());
			fixup_u32(C.getCaseSuccessor());
		}
		return;
	}



	if (Op == Instruction::Ret) {
		auto* RI = cast<ReturnInst>(I);
		Value* RV = RI->getReturnValue();
		if (!RV) { bop(OP_RET_VOID); return; }
		if (RV->getType()->isPointerTy()) { bop(OP_RET_PTR); b8(xorSalt(pr(RV)));   return; }
		if (RV->getType()->isIntegerTy(64)) { bop(OP_RET_INT); b8(xorSalt(vr64(RV))); return; }
		if (RV->getType()->isFloatTy() || RV->getType()->isDoubleTy()) { bop(OP_RET_F);   b8(xorSalt(fr(RV)));   return; }
		bop(OP_RET_INT); b8(xorSalt(vr(RV)));

		return;
	}


	markUnsupported(I);
}

void BytecodeEmitter::emit(BasicBlock* BB) {
	if (Unsupported) return;
	BlockIP[BB] = ip();   // record this block's start IP during emission
	for (Instruction& I : *BB) {
		if (Unsupported) return;
		emit(&I);
	}
}

bool BytecodeEmitter::run(Function& F, uint8_t S, const DataLayout& D) {

	// Reset per-run state
	BC.clear();
	BlockIP.clear();
	VR.clear();
	VR64.clear();
	PR.clear();
	CalleeTab.clear();
	CalleeFTyTab.clear();
	PHIAllocas.clear();
	ImmLoads.clear();
	ImmLoads64.clear();
	PtrLoads.clear();
	FR.clear();
	ImmLoadsF.clear();
	Fixups.clear();
	NVR = NVR64 = NPR = NFR = 0;

	Unsupported = false;
	FirstUnsupportedInst = nullptr;
	FirstUnsupportedVal = nullptr;
	FirstUnsupportedWhy.clear();
	FailReason.clear();


	Salt = S;
	DL = &D;


	// (+i64 regfile plumbing): allow pointers, <=32-bit ints (i32 vregs), and i64 ints (i64 vregs).
	for (Argument& A : F.args()) {
		Type* AT = A.getType();
		if (AT->isPointerTy()) continue;
		if (AT->isIntegerTy()) {
			unsigned BW = AT->getIntegerBitWidth();
			if (BW <= 32 || BW == 64) continue;
		}
		if (AT->isFloatTy() || AT->isDoubleTy()) continue;
		markUnsupportedValue(&A);
	}

	if (Unsupported) { setFail(describeUnsupported()); return false; }


	// Assign slots for args
	for (Argument& A : F.args()) {
		Type* AT = A.getType();
		if (AT->isPointerTy()) newPR(&A);
		else if (AT->isIntegerTy(64)) newVR64(&A);
		else if (AT->isIntegerTy()) newVR(&A);
		else if (AT->isFloatTy() || AT->isDoubleTy()) newFR(&A);
		else { markUnsupportedValue(&A); }
	}

	// Assign preg slots for every alloca in the entry block.
	//
	// Originally this loop terminated at the first non-alloca instruction on
	// the assumption that all entry-block allocas form a contiguous prefix
	// (true for PHI-demoted IR coming straight out of clang -O0). Earlier
	// passes can break that invariant — vcall inserts
	//     %vcall.slot = alloca i32
	//     %vcall.slot.p2i = ptrtoint ptr %vcall.slot to i64
	//     %vcall.slot.p2i32 = trunc i64 ... to i32
	//     %vcall.slot.init = xor i32 ...
	//     store i32 ..., ptr %vcall.slot
	// at the top of entry, sandwiching the user allocas behind non-alloca
	// init code. With `break`, the user allocas (%x.addr, %y.addr, ...) were
	// silently dropped from slot assignment, and the bytecode emitter then
	// asserted "pr(): untracked non-const ptr" on the first store that
	// referenced one. Scan the whole entry block instead and register every
	// alloca we find.
	for (Instruction& I : F.getEntryBlock()) {
		auto* AI = dyn_cast<AllocaInst>(&I);
		if (!AI) continue;
		PhiAllocaDesc D;
		D.Slot = newPR(AI);
		D.AllocTy = AI->getAllocatedType();
		D.A = AI->getAlign();
		D.Name = AI->getName().str();
		PHIAllocas.push_back(std::move(D));
	}

	// Pre-assign slots for *all* instruction results (except allocas/unreachable).
	// This removes any reliance on basic-block iteration order for vr()/pr() lookups,
	// and makes constants/pointer-const pools naturally allocate "above" all SSA results.
	for (BasicBlock& BB : F) {
		for (Instruction& I : BB) {
			if (isa<AllocaInst>(&I) || isa<UnreachableInst>(&I)) continue;
			Type* Ty = I.getType();
			if (Ty->isVoidTy()) continue;

			if (Ty->isPointerTy()) {
				newPR(&I);
				continue;
			}

			if (Ty->isIntegerTy(64)) {
				newVR64(&I);
				continue;
			}

			if (Ty->isIntegerTy()) {
				unsigned BW = Ty->getIntegerBitWidth();
				if (BW <= 32) { newVR(&I); continue; }
			}

			// float/double → freg file
			if (Ty->isFloatTy() || Ty->isDoubleTy()) { newFR(&I); continue; }


			// Any other result type is not representable in the current VM ISA.
			markUnsupportedValue(&I);
		}
	}

	if (Unsupported) { setFail(describeUnsupported()); return false; }



	// Single pass: emit all blocks; emit(BasicBlock*) populates BlockIP as it goes.
	// Forward branch targets are recorded as Fixups with a 0x00000000 placeholder.
	for (BasicBlock& BB : F) emit(&BB);

	// Patch all forward-branch placeholders now that every BlockIP is known.
	for (const Fixup& FX : Fixups) {
		uint32_t V = BlockIP.lookup(FX.Target);
		if (BlindTargets) V ^= tgtKeyCT(SaltFull);
		BC[FX.Offset + 0] = (uint8_t)(V);
		BC[FX.Offset + 1] = (uint8_t)(V >> 8);
		BC[FX.Offset + 2] = (uint8_t)(V >> 16);
		BC[FX.Offset + 3] = (uint8_t)(V >> 24);
	}

	if (Unsupported) { setFail(describeUnsupported()); return false; }

	if (NVR > 250 || NVR64 > 250 || NPR > 250 || NFR > 250) {
		setFail("register file size overflow");
		return false;
	}
	if (BC.empty()) {
		setFail("empty bytecode");
		return false;
	}
	VMBytecodeBytes += BC.size(); VMVirtRegs += NVR; VMVirtRegs += NVR64; VMVirtRegs += NPR; VMVirtRegs += NFR;

	return true;
}