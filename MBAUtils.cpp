// ============================================================================
// MbaUtils.cpp — MBA factory implementation
//
// All per-opcode transforms, advanced inflation helpers, and STATISTIC counters
// previously living inside the anonymous namespace of MBAObfuscation.cpp are
// collected here so that both MBAPass and VMPass can share them without
// duplication.
// ============================================================================

#include "llvm/Transforms/Obfuscator/MBAUtils.h"
#include "llvm/Transforms/Obfuscator/Rng.h"
#include "llvm/Transforms/Obfuscator/Utils.h"

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <string>

using namespace llvm;
using namespace llvm::obf;

#define DEBUG_TYPE "mba"

// ============================================================================
// Statistics  (moved from MBAObfuscation.cpp)
// ============================================================================

STATISTIC(MBAAdd, "Add instructions transformed with MBA");
STATISTIC(MBASub, "Sub instructions transformed with MBA");
STATISTIC(MBAAnd, "And instructions transformed with MBA");
STATISTIC(MBAOr, "Or  instructions transformed with MBA");
STATISTIC(MBAXor, "Xor instructions transformed with MBA");

// ============================================================================
// Construction
// ============================================================================


MbaUtils::MbaUtils(Module& M, Rng& R, StringRef SlotName)
	: MbaUtils(M, R, SlotName, Options{}) {
}


MbaUtils::MbaUtils(Module& M, Rng& R, StringRef SlotName, Options Opts)
	: M(M), R(R), SlotName(SlotName), Opts(Opts) {
}

// ============================================================================
// Opcode filter
// ============================================================================

bool MbaUtils::isTargetOpcode(unsigned Op) {
	return Op == Instruction::Add || Op == Instruction::Sub ||
		Op == Instruction::Xor || Op == Instruction::And ||
		Op == Instruction::Or;
}

// ============================================================================
// Per-function noise slot management
// ============================================================================

AllocaInst* MbaUtils::ensureNoiseSlot(IRBuilder<>& B) {
	Function* Fn = B.GetInsertBlock()->getParent();
	if (CachedFn == Fn && NoiseSlot)
		return NoiseSlot;

	// Switch to the new function — reset cached state.
	CachedFn = Fn;
	NoiseSlot = nullptr;

	// Pin the entropy anchor first (must precede the noise slot in entry block).
	(void)llvm::obf::ensureEntropyAllocaAtEntryBegin(*Fn);

	NoiseSlot = llvm::obf::getOrCreateVolatileI32Slot(*Fn, SlotName, R);
	return NoiseSlot;
}

AllocaInst* MbaUtils::getOrCreateNoiseSlot(IRBuilder<>& B) {
	return ensureNoiseSlot(B);
}

// ============================================================================
// Poison-sensitive flag check
// ============================================================================

bool MbaUtils::hasPoisonSensitiveFlags(const BinaryOperator& BO)
{
	// For correctness: don't change poison behavior of flagged ops.
	// Add/Sub can carry nuw/nsw; skip those sites.
	switch (BO.getOpcode()) {
	case Instruction::Add:
	case Instruction::Sub:
		return BO.hasNoSignedWrap() || BO.hasNoUnsignedWrap();
	default:
		return false;

	}
}

// ============================================================================
// Core Value-level transforms — Add
// ============================================================================

// x + y  =>  (x ^ y) + 2*(x & y)
Value* MbaUtils::add(IRBuilder<>& B, Value* A, Value* V) {
	Value* Xor = B.CreateXor(A, V, "mba.xor");
	Value* And = B.CreateAnd(A, V, "mba.and");
	Value* Shl = B.CreateShl(And, ConstantInt::get(A->getType(), 1), "mba.shl");
	return B.CreateAdd(Xor, Shl, "mba.add");
}

// x + y  =>  (x | y) + (x & y)
Value* MbaUtils::addAlt(IRBuilder<>& B, Value* A, Value* V) {
	Value* Or = B.CreateOr(A, V, "mba.or");
	Value* And = B.CreateAnd(A, V, "mba.and");
	return B.CreateAdd(Or, And, "mba.add.alt");
}

// x + y  =>  2*(x | y) - (x ^ y)    [used by VM pass hardener]
Value* MbaUtils::addAlt2(IRBuilder<>& B, Value* A, Value* V) {
	Value* Or = B.CreateOr(A, V, "mba.or");
	Value* Shl = B.CreateShl(Or, ConstantInt::get(A->getType(), 1), "mba.shl");
	Value* Xor = B.CreateXor(A, V, "mba.xor");
	return B.CreateSub(Shl, Xor, "mba.add.alt2");
}

// ============================================================================
// Core Value-level transforms — Sub
// ============================================================================

// x - y  =>  (x ^ y) - 2*(~x & y)
Value* MbaUtils::sub(IRBuilder<>& B, Value* A, Value* V) {
	Value* Xor = B.CreateXor(A, V, "mba.xor");
	Value* NotA = B.CreateNot(A, "mba.not");
	Value* And = B.CreateAnd(NotA, V, "mba.and");
	Value* Shl = B.CreateShl(And, ConstantInt::get(A->getType(), 1), "mba.shl");
	return B.CreateSub(Xor, Shl, "mba.sub");
}

// x - y  =>  (x & ~y) - (~x & y)
Value* MbaUtils::subAlt(IRBuilder<>& B, Value* A, Value* V) {
	Value* NotA = B.CreateNot(A, "mba.notx");
	Value* NotV = B.CreateNot(V, "mba.noty");
	Value* And1 = B.CreateAnd(A, NotV, "mba.and1");
	Value* And2 = B.CreateAnd(NotA, V, "mba.and2");
	return B.CreateSub(And1, And2, "mba.sub.alt");
}

// x - y  =>  x + ~y + 1    (two's complement identity)  [used by VM pass hardener]
Value* MbaUtils::subAlt2(IRBuilder<>& B, Value* A, Value* V) {
	Value* NotV = B.CreateNot(V, "mba.not");
	Value* Add1 = B.CreateAdd(A, NotV, "mba.anb");
	return B.CreateAdd(Add1, ConstantInt::get(A->getType(), 1), "mba.sub.alt2");
}

// ============================================================================
// Core Value-level transforms — And
// ============================================================================

// x & y  =>  (x + y) - (x | y)
Value* MbaUtils::bitwiseAnd(IRBuilder<>& B, Value* A, Value* V) {
	Value* Add = B.CreateAdd(A, V, "mba.add");
	Value* Or = B.CreateOr(A, V, "mba.or");
	return B.CreateSub(Add, Or, "mba.and");
}

// x & y  =>  ~(~x | ~y)    (De Morgan)
Value* MbaUtils::bitwiseAndAlt(IRBuilder<>& B, Value* A, Value* V) {
	Value* Na = B.CreateNot(A, "mba.na");
	Value* Nb = B.CreateNot(V, "mba.nb");
	Value* Or = B.CreateOr(Na, Nb, "mba.nor");
	return B.CreateNot(Or, "mba.and");
}

// ============================================================================
// Core Value-level transforms — Or
// ============================================================================

// x | y  =>  (x & y) + (x ^ y)
Value* MbaUtils::bitwiseOr(IRBuilder<>& B, Value* A, Value* V) {
	Value* And = B.CreateAnd(A, V, "mba.and");
	Value* Xor = B.CreateXor(A, V, "mba.xor");
	return B.CreateAdd(And, Xor, "mba.or");
}

// x | y  =>  (x + y) - (x & y)
Value* MbaUtils::bitwiseOrAlt(IRBuilder<>& B, Value* A, Value* V) {
	Value* Add = B.CreateAdd(A, V, "mba.add");
	Value* And = B.CreateAnd(A, V, "mba.and");
	return B.CreateSub(Add, And, "mba.or.alt");
}

// x | y  =>  (x ^ y) | (x & y)   [bitwise-OR form; disjoint bits => same result]
// Used by VM pass hardener to match its original IR pattern.
Value* MbaUtils::bitwiseOrAlt2(IRBuilder<>& B, Value* A, Value* V) {
	Value* Xor = B.CreateXor(A, V, "mba.xor");
	Value* And = B.CreateAnd(A, V, "mba.and");
	return B.CreateOr(Xor, And, "mba.or.alt2");
}

// ============================================================================
// Core Value-level transforms — Xor
// ============================================================================

// x ^ y  =>  (x | y) - (x & y)
Value* MbaUtils::bitwiseXor(IRBuilder<>& B, Value* A, Value* V) {
	Value* Or = B.CreateOr(A, V, "mba.or");
	Value* And = B.CreateAnd(A, V, "mba.and");
	return B.CreateSub(Or, And, "mba.xor");
}

// x ^ y  =>  (~x & y) | (x & ~y)
Value* MbaUtils::bitwiseXorAlt(IRBuilder<>& B, Value* A, Value* V) {
	Value* NotA = B.CreateNot(A, "mba.notx");
	Value* NotV = B.CreateNot(V, "mba.noty");
	Value* And1 = B.CreateAnd(NotA, V, "mba.and1");
	Value* And2 = B.CreateAnd(A, NotV, "mba.and2");
	return B.CreateOr(And1, And2, "mba.xor.alt");
}

// ============================================================================
// BinaryOperator-level wrappers (bump STATISTIC counters)
// ============================================================================

Value* MbaUtils::applyPrimary(IRBuilder<>& B, BinaryOperator* BO) {
	if (!BO) return nullptr;
	Value* A = BO->getOperand(0);
	Value* V = BO->getOperand(1);
	switch (BO->getOpcode()) {
	case Instruction::Add: ++MBAAdd; return add(B, A, V);
	case Instruction::Sub: ++MBASub; return sub(B, A, V);
	case Instruction::And: ++MBAAnd; return bitwiseAnd(B, A, V);
	case Instruction::Or:  ++MBAOr;  return bitwiseOr(B, A, V);
	case Instruction::Xor: ++MBAXor; return bitwiseXor(B, A, V);
	default:               return nullptr;
	}
}

Value* MbaUtils::applyAlternate(IRBuilder<>& B, BinaryOperator* BO) {
	if (!BO) return nullptr;
	Value* A = BO->getOperand(0);
	Value* V = BO->getOperand(1);
	switch (BO->getOpcode()) {
	case Instruction::Add: ++MBAAdd; return addAlt(B, A, V);
	case Instruction::Sub: ++MBASub; return subAlt(B, A, V);
	case Instruction::And: ++MBAAnd; return bitwiseAndAlt(B, A, V);
	case Instruction::Or:  ++MBAOr;  return bitwiseOrAlt(B, A, V);
	case Instruction::Xor: ++MBAXor; return bitwiseXorAlt(B, A, V);
	default:               return nullptr;
	}
}

// Recursive MBA: picks primary vs alternate per level using RecRng,
// recurses into newly produced BinaryOperators.
// RecRng is passed explicitly so MbaCtx::RecRng sequence is preserved 1:1.
Value* MbaUtils::applyMBARecursive(IRBuilder<>& B, BinaryOperator* BO,
	unsigned depth, Rng& RecRng) {
	if (depth == 0 || !BO)
		return BO;

	bool useAlt = (RecRng.range(2) != 0);
	Value* NewV = useAlt ? applyAlternate(B, BO) : applyPrimary(B, BO);

	if (!NewV || NewV == BO)
		return BO;

	// 60 % chance to recurse into the new BinaryOperator.
	if (RecRng.range(100) < 60) {
		if (auto* NewBO = dyn_cast<BinaryOperator>(NewV)) {
			IRBuilder<> NB(NewBO);
			return applyMBARecursive(NB, NewBO, depth - 1, RecRng);
		}
	}

	return NewV;
}

// ============================================================================
// Advanced inflation: inflateLinear
// ============================================================================

Value* MbaUtils::inflateLinear(IRBuilder<>& B, Value* Base, unsigned DepthHint) {
	if (!Base || !Base->getType()->isIntegerTy())
		return Base;

	AllocaInst* Slot = ensureNoiseSlot(B);
	if (!Slot)
		return Base;

	unsigned BW = cast<IntegerType>(Base->getType())->getBitWidth();
	if (BW < 2)
		return Base;

	// Depth-aware term count: halve the range when already deep to limit IR growth.
	unsigned MinT = Opts.LinearTermsMin;
	unsigned MaxT = Opts.LinearTermsMax;
	if (DepthHint >= 2) {
		MinT = std::max(4u, MinT / 2);
		MaxT = std::max(MinT, MaxT / 2);
	}

	unsigned Terms = MinT;
	if (MaxT > MinT)
		Terms = MinT + (unsigned)R.range(MaxT - MinT + 1);

	Type* Ty = Base->getType();
	Value* Cur = Base;

	// Mask RNG constants to BW bits so ConstantInt::get does not assert when
	// Ty is narrower than 32 bits (e.g. i8/i16).
	const uint64_t BWMask = (BW < 64) ? ((uint64_t(1) << BW) - 1) : ~uint64_t(0);

	for (unsigned i = 0; i < Terms; ++i) {
		Value* Z = llvm::obf::makeRuntimeZero(B, Slot, BW, R, "mba.lin0");

		// Build a term that is 0 at runtime but structurally non-trivial.
		Value* T = Z;
		switch (R.range(6)) {
		default:
		case 0: {
			// (Z | (Z << k)) -> 0 at runtime
			unsigned k = 1u + (unsigned)R.range(
				std::min(7u, BW > 1 ? BW - 1 : 1u));
			Value* Sh = B.CreateShl(Z, ConstantInt::get(Ty, k), "mba.lin.shl");
			T = B.CreateOr(Z, Sh, "mba.lin.or");
			break;
		}
		case 1: {
			// (Z & (Z + C)) -> 0 at runtime (Z == 0, so result is 0)
			uint64_t Cst = ((uint64_t)R.u32() | 1ull) & BWMask;
			Value* Add = B.CreateAdd(Z, ConstantInt::get(Ty, Cst), "mba.lin.addc");
			T = B.CreateAnd(Z, Add, "mba.lin.and");
			break;
		}
		case 2: {
			// ((Z ^ K) ^ K) -> Z -> 0 at runtime
			uint64_t K = (uint64_t)R.u32() & BWMask;
			Value* Kc = ConstantInt::get(Ty, K);
			Value* X1 = B.CreateXor(Z, Kc, "mba.lin.x1");
			T = B.CreateXor(X1, Kc, "mba.lin.x2");
			break;
		}
		case 3: {
			// (Z * oddC) -> 0 at runtime (Z == 0)
			uint64_t Cst = ((uint64_t)R.u32() | 1ull) & BWMask;
			T = B.CreateMul(Z, ConstantInt::get(Ty, Cst), "mba.lin.mulc");
			break;
		}
		case 4: {
			// ((Z + K) & Z) -> 0 at runtime
			uint64_t K = (uint64_t)R.u32() & BWMask;
			Value* Add = B.CreateAdd(Z, ConstantInt::get(Ty, K), "mba.lin.addk");
			T = B.CreateAnd(Add, Z, "mba.lin.and2");
			break;
		}
		case 5: {
			// (Z & (Z | K)) -> Z -> 0 at runtime
			uint64_t K = (uint64_t)R.u32() & BWMask;
			Value* Or = B.CreateOr(Z, ConstantInt::get(Ty, K), "mba.lin.orK");
			T = B.CreateAnd(Z, Or, "mba.lin.and3");
			break;
		}
		}

		// Accumulate using + or - (both preserve semantics since T == 0 at runtime).
		if (R.range(2))
			Cur = B.CreateAdd(Cur, T, "mba.lin.sum");
		else
			Cur = B.CreateSub(Cur, T, "mba.lin.sub");
	}

	return Cur;
}

// ============================================================================
// Advanced inflation: addNonLinearZero
// ============================================================================

// Add a nonlinear (mul / urem-based) runtime-zero to Cur.
// Uses identities where the result is exactly 0 because Z == 0 at runtime,
// but the expression is opaque to SMT solvers / instcombine.
Value* MbaUtils::addNonLinearZero(IRBuilder<>& B, BinaryOperator& Orig, Value* Cur) {
	if (!Cur || !Cur->getType()->isIntegerTy())
		return Cur;

	AllocaInst* Slot = ensureNoiseSlot(B);
	if (!Slot)
		return Cur;

	unsigned BW = cast<IntegerType>(Cur->getType())->getBitWidth();
	Type* Ty = Cur->getType();

	Value* x = Orig.getOperand(0);
	Value* y = Orig.getOperand(1);
	if (!x || !y || x->getType() != Ty || y->getType() != Ty)
		return Cur;

	Value* Z = llvm::obf::makeRuntimeZero(B, Slot, BW, R, "mba.nonlin0");

	Value* NZ = nullptr;
	switch (R.range(2)) {
	default:
	case 0: {
		// mul(x, y) - mul(x, y + Z) == 0 at runtime  (Z == 0)
		Value* t1 = B.CreateMul(x, y, "mba.nl.mul1");
		Value* y2 = B.CreateAdd(y, Z, "mba.nl.y2");
		Value* t2 = B.CreateMul(x, y2, "mba.nl.mul2");
		NZ = B.CreateSub(t1, t2, "mba.nl.zero");
		break;
	}
	case 1: {
		// urem(x*C, M) - urem((x+Z)*C, M) == 0 at runtime  (Z == 0)
		static constexpr uint32_t Mods[] = { 251u, 509u, 1009u, 4093u };
		uint32_t M = Mods[(size_t)R.range(
			(uint32_t)(sizeof(Mods) / sizeof(Mods[0])))];
		uint32_t C = (R.u32() | 1u);

		// Mask to BW so ConstantInt::get does not assert on narrow Ty (i1/i8).
		const uint64_t BWMask = (BW < 64) ? ((uint64_t(1) << BW) - 1) : ~uint64_t(0);
		uint64_t Mm = (uint64_t)M & BWMask;
		if (Mm == 0) Mm = 1; // urem by 0 is UB
		uint64_t Cm = ((uint64_t)C | 1ull) & BWMask;
		if (Cm == 0) Cm = 1;

		Value* Mc = ConstantInt::get(Ty, Mm);
		Value* Cc = ConstantInt::get(Ty, Cm);

		Value* t1 = B.CreateURem(B.CreateMul(x, Cc, "mba.nl.m1"), Mc, "mba.nl.r1");
		Value* x2 = B.CreateAdd(x, Z, "mba.nl.x2");
		Value* t2 = B.CreateURem(B.CreateMul(x2, Cc, "mba.nl.m2"), Mc, "mba.nl.r2");
		NZ = B.CreateSub(t1, t2, "mba.nl.zero2");
		break;
	}
	}

	if (!NZ)
		return Cur;

	return B.CreateAdd(Cur, NZ, "mba.nl.add");
}

// ============================================================================
// Advanced inflation: addHighDegreeZero
// ============================================================================

// Add degree-4 or degree-5 polynomial runtime-zero: f(v+Z) - f(v) == 0 (Z == 0).
Value* MbaUtils::addHighDegreeZero(IRBuilder<>& B, BinaryOperator& Orig,
	Value* Cur, unsigned DepthHint) {
	if (!Cur || !Cur->getType()->isIntegerTy())
		return Cur;

	AllocaInst* Slot = ensureNoiseSlot(B);
	if (!Slot)
		return Cur;

	unsigned BW = cast<IntegerType>(Cur->getType())->getBitWidth();
	// Restrict to 32/64-bit where analysis tools typically focus.
	if (BW < 2 || (BW != 32 && BW != 64))
		return Cur;

	Type* Ty = Cur->getType();

	Value* x = Orig.getOperand(0);
	if (!x || x->getType() != Ty)
		return Cur;

	Value* Z = llvm::obf::makeRuntimeZero(B, Slot, BW, R, "mba.hd0");

	auto pow2 = [&](Value* v) { return B.CreateMul(v, v, "mba.hd.p2"); };
	auto pow3 = [&](Value* v) { return B.CreateMul(pow2(v), v, "mba.hd.p3"); };
	auto pow4 = [&](Value* v) {
		Value* v2 = pow2(v);
		return B.CreateMul(v2, v2, "mba.hd.p4");
		};
	auto pow5 = [&](Value* v) { return B.CreateMul(pow4(v), v, "mba.hd.p5"); };
	(void)pow3; // suppress unused-lambda warning; only pow4/pow5 used below

	// Base: optionally mix both operands to vary signatures across sites.
	Value* base = x;
	if (R.range(2))
		base = B.CreateAdd(x, Orig.getOperand(1), "mba.hd.base");

	Value* b0 = B.CreateFreeze(base, "mba.hd.b0");
	Value* b1 = B.CreateAdd(b0, Z, "mba.hd.b1");

	Value* f0;
	Value* f1;
	if (DepthHint >= 3 && R.range(2)) {
		f0 = pow5(b0);
		f1 = pow5(b1);
	}
	else {
		f0 = pow4(b0);
		f1 = pow4(b1);
	}

	Value* diff = B.CreateSub(f1, f0, "mba.hd.diff");
	return B.CreateAdd(Cur, diff, "mba.hd.add");
}

// ============================================================================
// Advanced inflation: addMixedModeZero
// ============================================================================

// Add a rotation + mixing + polynomial runtime-zero to Cur.
// The mixing function is non-linear over integers, increasing SMT hardness.
Value* MbaUtils::addMixedModeZero(IRBuilder<>& B, BinaryOperator& Orig,
	Value* Cur, unsigned DepthHint) {
	if (!Cur || !Cur->getType()->isIntegerTy())
		return Cur;

	AllocaInst* Slot = ensureNoiseSlot(B);
	if (!Slot)
		return Cur;

	unsigned BW = cast<IntegerType>(Cur->getType())->getBitWidth();
	if (BW < 2 || (BW != 32 && BW != 64))
		return Cur;

	Type* Ty = Cur->getType();

	Value* x = Orig.getOperand(0);
	Value* y = Orig.getOperand(1);
	if (!x || !y || x->getType() != Ty || y->getType() != Ty)
		return Cur;

	Value* Z = llvm::obf::makeRuntimeZero(B, Slot, BW, R, "mba.mm0");

	// Rotation amount: masked to 0..BW-1 to avoid poison on shift.
	Value* Amt = llvm::obf::xorWithRuntimeZero(
		B, llvm::obf::getObfEntropyI32(B), Slot, R, "mba.mm.amt", 50);
	if (Amt->getType() != Ty)
		Amt = B.CreateZExtOrTrunc(Amt, Ty, "mba.mm.amt.cast");
	Value* BWMask = ConstantInt::get(Ty, BW - 1);
	Amt = B.CreateAnd(B.CreateFreeze(Amt, "mba.mm.amt.fr"), BWMask, "mba.mm.amt.m");

	// Left-rotation helper.
	auto rotl = [&](Value* v) -> Value* {
		Value* Rv = B.CreateSub(ConstantInt::get(Ty, BW), Amt, "mba.mm.r");
		Rv = B.CreateAnd(Rv, BWMask, "mba.mm.rm");
		Value* shl = B.CreateShl(v, Amt, "mba.mm.shl");
		Value* shr = B.CreateLShr(v, Rv, "mba.mm.shr");
		return B.CreateOr(shl, shr, "mba.mm.rot");
		};

	uint64_t MixOdd = (R.u32() | 1u);

	// Mixing function: rotl(v) XOR lshr(v,13), then multiply by odd constant.
	auto mix = [&](Value* v, const char* tag) -> Value* {
		Value* r = rotl(v);
		Value* s = B.CreateLShr(v, ConstantInt::get(Ty, 13),
			(std::string(tag) + ".shr").c_str());
		Value* m = B.CreateXor(r, s, (std::string(tag) + ".x1").c_str());
		return B.CreateMul(m, ConstantInt::get(Ty, MixOdd),
			(std::string(tag) + ".mul").c_str());
		};

	Value* base = B.CreateXor(x, y, "mba.mm.base");
	Value* b0 = B.CreateFreeze(base, "mba.mm.b0");
	Value* b1 = B.CreateAdd(b0, Z, "mba.mm.b1");    // b1 == b0 at runtime (Z==0)

	Value* f0 = mix(b0, "mba.mm.f0");
	Value* f1 = mix(b1, "mba.mm.f1");

	// Optional nonlinear lift: multiply to increase polynomial degree.
	if (DepthHint >= 3) {
		f0 = B.CreateMul(f0, b0, "mba.mm.l0");
		f1 = B.CreateMul(f1, b1, "mba.mm.l1");
	}

	Value* diff = B.CreateSub(f1, f0, "mba.mm.diff");
	return B.CreateAdd(Cur, diff, "mba.mm.add");
}

// ============================================================================
// Layered MBA window
// ============================================================================

void MbaUtils::applyLayeredWindow(Instruction* Anchor, Instruction* Skip,
	unsigned DepthHint, Rng& RecRng) {
	if (!Opts.EnableLayered || Opts.LayeredBudget == 0 || Opts.LayeredWindow == 0)
		return;
	if (!Anchor)
		return;

	BasicBlock* BB = Anchor->getParent();
	if (!BB)
		return;

	// Collect eligible BinaryOperators in reverse instruction order
	// (newest-first, i.e. from Anchor backward).
	SmallVector<BinaryOperator*, 64> Cands;
	unsigned Seen = 0;
	for (Instruction* I = Anchor->getPrevNode();
		I && Seen < Opts.LayeredWindow;
		I = I->getPrevNode(), ++Seen) {
		if (I == Skip)
			continue;
		auto* BO = dyn_cast<BinaryOperator>(I);
		if (!BO)
			continue;
		if (!isTargetOpcode(BO->getOpcode()))
			continue;
		if (hasPoisonSensitiveFlags(*BO))
			continue;
		if (!BO->getType()->isIntegerTy())
			continue;
		// Avoid aggressively exploding deeper layers.
		Cands.push_back(BO);
	}

	if (Cands.empty())
		return;

	unsigned Budget = std::min<unsigned>(Opts.LayeredBudget,
		(unsigned)Cands.size());

	for (unsigned i = 0; i < Budget; ++i) {
		BinaryOperator* BO = Cands[i];
		if (!BO || BO->getParent() != BB)
			continue;

		IRBuilder<> B(BO);
		// One-step recursive rewrite (DepthHint influences inflation).
		Value* V = applyMBARecursive(B, BO, /*depth=*/1, RecRng);
		if (!V || V == BO)
			continue;

		V = inflateLinear(B, V, DepthHint + 1);
		BO->replaceAllUsesWith(V);
		BO->eraseFromParent();
		// B's insert point is now invalid; the next iteration creates a fresh one.
	}
}