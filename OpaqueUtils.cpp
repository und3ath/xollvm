#include "llvm/Transforms/Obfuscator/OpaqueUtils.h"
#include "llvm/Transforms/Obfuscator/Utils.h" 

#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/Support/Alignment.h"

#include <algorithm>
#include <string>

using namespace llvm;

namespace llvm::obf {

	namespace {

		static Value* obf_maskShiftAmt32(IRBuilder<>& B, Value* Amt) {
			Type* I32 = Type::getInt32Ty(B.getContext());
			// Ensure 0..31 to avoid shift poison.
			Value* A = B.CreateAnd(B.CreateFreeze(Amt, "obf.amt.fr"), ConstantInt::get(I32, 31), "obf.amt.m");
			return B.CreateFreeze(A, "obf.amt.mfr");
		}

		static Value* obf_rotl32(IRBuilder<>& B, Value* V, Value* Amt) {
			Type* I32 = Type::getInt32Ty(B.getContext());
			Value* S = obf_maskShiftAmt32(B, Amt);
			Value* R = B.CreateSub(ConstantInt::get(I32, 32), S, "obf.rot.r");
			// Mask again to keep 0..31.
			R = B.CreateAnd(R, ConstantInt::get(I32, 31), "obf.rot.rm");
			Value* Shl = B.CreateShl(V, S, "obf.rot.shl");
			Value* Shr = B.CreateLShr(V, R, "obf.rot.shr");
			return B.CreateOr(Shl, Shr, "obf.rot");
		}

		static Value* obf_zextI64(IRBuilder<>& B, Value* V) {
			Type* I64 = Type::getInt64Ty(B.getContext());
			if (V->getType()->isIntegerTy(64))
				return V;
			return B.CreateZExt(V, I64, "obf.zext64");
		}

	} // end anonymous namespace

	OpaqueUtils::OpaqueUtils(Module& M, Rng& R, StringRef SlotName)
		: OpaqueUtils(M, R, SlotName, Options{}) {
	}

	OpaqueUtils::OpaqueUtils(Module& M, Rng& R, StringRef SlotName, Options Opts)
		: M(M), R(R), SlotName(SlotName), Opts(Opts) {
	}

	Value* OpaqueUtils::loadEntropyI32(IRBuilder<>& B) {
		// Your project helper; assumed non-constant.
		return llvm::obf::getObfEntropyI32(B);
	}




	AllocaInst* OpaqueUtils::getOrCreateVolatileI32Slot(IRBuilder<>& B) {
		BasicBlock* BB = B.GetInsertBlock();
		Function* F = BB ? BB->getParent() : nullptr;
		if (!F)
			return nullptr;

		if (CachedSlot && CachedFn == F)
			return CachedSlot;

		LLVMContext& C = B.getContext();
		Type* I32 = Type::getInt32Ty(C);

		BasicBlock& Entry = F->getEntryBlock();

		// Reuse if present in entry.
		for (Instruction& I : Entry) {
			if (auto* AI = dyn_cast<AllocaInst>(&I)) {
				if (AI->getName() == SlotName && AI->getAllocatedType()->isIntegerTy(32)) {
					CachedFn = F;
					CachedSlot = AI;
					return AI;
				}
			}
		}

		// Create per-function volatile anchor.
		Instruction* AllocaIP = llvm::obf::getAllocaIP(*F);
		if (!AllocaIP) AllocaIP = Entry.getTerminator();
		IRBuilder<> EB(AllocaIP);

		AllocaInst* Slot = EB.CreateAlloca(I32, nullptr, SlotName);
		Slot->setAlignment(Align(4));


		// Init depends on entropy; store volatile to pin it.
		Value* E = loadEntropyI32(EB);
		uint32_t K = R.u32();
		Value* Init = EB.CreateXor(E, ConstantInt::get(I32, K), "obf.salt.init");

		auto* St = EB.CreateStore(Init, Slot);
		St->setVolatile(true);
		St->setAlignment(Align(4));

		CachedFn = F;
		CachedSlot = Slot;
		return Slot;
	}

	Value* OpaqueUtils::loadVolatileI32(IRBuilder<>& B) {
		LLVMContext& C = B.getContext();
		Type* I32 = Type::getInt32Ty(C);

		AllocaInst* Slot = getOrCreateVolatileI32Slot(B);
		if (!Slot)
			return ConstantInt::get(I32, 0xC0FFEEu);

		auto* L = B.CreateLoad(I32, Slot, "obf.salt");
		// Always volatile: several opaque families rely on *independent* loads
		// not being merged/hoisted/CSE'd.
		L->setVolatile(true);
		L->setAlignment(Align(4));

		return B.CreateFreeze(L, "obf.salt.fr");
	}

	// -------- mix variants (UB-safe: constant shifts, odd multipliers, freeze) -----

	Value* OpaqueUtils::mix32_v1(IRBuilder<>& B, Value* V, uint32_t K0, uint32_t K1) {
		Type* I32 = Type::getInt32Ty(B.getContext());
		Value* X = B.CreateFreeze(V, "obf.m1.in");

		X = B.CreateXor(X, ConstantInt::get(I32, K0), "obf.m1.x0");
		X = B.CreateMul(X, ConstantInt::get(I32, (K1 | 1u)), "obf.m1.mul");

		Value* L = B.CreateShl(X, ConstantInt::get(I32, 7), "obf.m1.shl");
		Value* R = B.CreateLShr(X, ConstantInt::get(I32, 13), "obf.m1.shr");
		X = B.CreateXor(L, R, "obf.m1.x1");

		return B.CreateFreeze(X, "obf.m1.fr");
	}

	Value* OpaqueUtils::mix32_v2(IRBuilder<>& B, Value* V, uint32_t K0, uint32_t K1) {
		Type* I32 = Type::getInt32Ty(B.getContext());
		Value* X = B.CreateFreeze(V, "obf.m2.in");

		// Different shape: add, xor, mul, rotate-ish
		X = B.CreateAdd(X, ConstantInt::get(I32, K0), "obf.m2.add");
		X = B.CreateXor(X, ConstantInt::get(I32, K1), "obf.m2.x0");
		X = B.CreateMul(X, ConstantInt::get(I32, ((K0 ^ K1) | 1u)), "obf.m2.mul");

		// “rotate” using constants (no UB)
		Value* L = B.CreateShl(X, ConstantInt::get(I32, 11), "obf.m2.shl");
		Value* R = B.CreateLShr(X, ConstantInt::get(I32, 21), "obf.m2.shr");
		X = B.CreateOr(L, R, "obf.m2.rot");

		return B.CreateFreeze(X, "obf.m2.fr");
	}

	Value* OpaqueUtils::mix32_v3(IRBuilder<>& B, Value* V, uint32_t K0, uint32_t K1) {
		Type* I32 = Type::getInt32Ty(B.getContext());
		Value* X = B.CreateFreeze(V, "obf.m3.in");

		// Use two-step mixing + self-cancel noise
		X = B.CreateXor(X, ConstantInt::get(I32, K0), "obf.m3.x0");
		Value* Y = B.CreateAdd(X, ConstantInt::get(I32, K1), "obf.m3.add");

		// Delta = (X^Y) is not a compile-time constant; keep it in the graph
		Value* Delta = B.CreateXor(X, Y, "obf.m3.d0");
		Delta = B.CreateMul(Delta, ConstantInt::get(I32, (K1 | 1u)), "obf.m3.dmul");

		X = B.CreateAdd(Y, Delta, "obf.m3.out");
		return B.CreateFreeze(X, "obf.m3.fr");
	}

	Value* OpaqueUtils::pickMix(IRBuilder<>& B, Value* V, uint32_t K0, uint32_t K1, unsigned Variant) {
		switch (Variant % 3) {
		case 0: return mix32_v1(B, V, K0, K1);
		case 1: return mix32_v2(B, V, K0, K1);
		default: return mix32_v3(B, V, K0, K1);
		}
	}

	// -------------------- hardened predicates ------------------------------------

	Value* OpaqueUtils::hardTrue(IRBuilder<>& B) {
		if (!Opts.EnableHardPreds)
			return ConstantInt::getTrue(B.getContext());

		// Two volatile loads from same per-function slot (not assumably equal).
		Value* A = loadVolatileI32(B);
		Value* D = loadVolatileI32(B);

		uint32_t K0 = R.u32();
		uint32_t K1 = R.u32();
		unsigned V = (unsigned)R.range(3);

		Value* MA = pickMix(B, A, K0, K1, V);
		Value* MD = pickMix(B, D, K0, K1, V);

		return B.CreateICmpEQ(MA, MD, "obf.hard.true");
	}

	Value* OpaqueUtils::hardFalse(IRBuilder<>& B) {
		if (!Opts.EnableHardPreds)
			return ConstantInt::getFalse(B.getContext());

		LLVMContext& C = B.getContext();
		Type* I32 = Type::getInt32Ty(C);

		Value* A = loadVolatileI32(B);
		Value* D = loadVolatileI32(B);

		uint32_t K0 = R.u32();
		uint32_t K1 = R.u32();
		unsigned V = (unsigned)R.range(3);

		Value* MA = pickMix(B, A, K0, K1, V);
		Value* MD = pickMix(B, D, K0, K1, V);

		Value* MD1 = B.CreateAdd(MD, ConstantInt::get(I32, 1), "obf.hf.add");
		return B.CreateICmpEQ(MA, MD1, "obf.hard.false");
	}


	// -------------------- context-sensitive sources ------------------------------

	Value* OpaqueUtils::pickI32FromContext(IRBuilder<>& B) {
		LLVMContext& C = B.getContext();
		Type* I32 = Type::getInt32Ty(C);

		SmallVector<Value*, 16> Cands;

		// Prefer existing i32 args (context-sensitive).
		if (BasicBlock* BB = B.GetInsertBlock()) {
			if (Function* F = BB->getParent()) {
				for (Argument& A : F->args())
					if (A.getType() == I32)
						Cands.push_back(&A);
			}
		}

		// Prefer nearby i32-producing instructions before insertion point.
		if (BasicBlock* BB = B.GetInsertBlock()) {
			Instruction* IP = nullptr;
			if (B.GetInsertPoint() != BB->end())
				IP = &*B.GetInsertPoint();
			else
				IP = BB->getTerminator();

			unsigned Seen = 0;
			for (Instruction* Cur = IP ? IP->getPrevNode() : nullptr;
				Cur && Seen < 20; Cur = Cur->getPrevNode(), ++Seen) {
				if (Cur->getType() == I32 && !Cur->mayHaveSideEffects())
					Cands.push_back(Cur);
			}
		}

		// Fallbacks (always available).
		Cands.push_back(loadVolatileI32(B));
		Cands.push_back(loadEntropyI32(B));

		if (Cands.empty())
			return loadVolatileI32(B);

		return Cands[(size_t)R.range((uint32_t)Cands.size())];
	}

	// Legacy “salt^entropy” shapes (kept as families so randomHardTrue/False can mix)
	Value* OpaqueUtils::legacySaltEntropyTrue(IRBuilder<>& B) {
		Value* S0 = loadVolatileI32(B);
		Value* S1 = loadVolatileI32(B);
		Value* E = loadEntropyI32(B);
		uint32_t K0 = R.u32(), K1 = R.u32();
		unsigned V = (unsigned)R.range(3);
		Value* X0 = B.CreateXor(S0, E, "obf.leg.t.x0");
		Value* X1 = B.CreateXor(S1, E, "obf.leg.t.x1");
		X0 = pickMix(B, X0, K0, K1, V);
		X1 = pickMix(B, X1, K0, K1, V);
		return B.CreateICmpEQ(X0, X1, "obf.leg.true");
	}

	Value* OpaqueUtils::legacySaltEntropyFalse(IRBuilder<>& B) {
		LLVMContext& C = B.getContext();
		Type* I32 = Type::getInt32Ty(C);
		Value* S0 = loadVolatileI32(B);
		Value* S1 = loadVolatileI32(B);
		uint32_t K0 = R.u32(), K1 = R.u32();
		unsigned V = (unsigned)R.range(3);
		Value* X0 = pickMix(B, S0, K0, K1, V);
		Value* X1 = pickMix(B, S1, K0, K1, V);
		X1 = B.CreateAdd(X1, ConstantInt::get(I32, 1), "obf.leg.f.add1");
		return B.CreateICmpEQ(X0, X1, "obf.leg.false");
	}

	// -------------------- Enhanced predicate families ----------------------------

	// MBA identity:
	//   (x^y) + 2*(x&y) == x + y    (bitvector identity)
	Value* OpaqueUtils::predMBATrue(IRBuilder<>& B) {
		LLVMContext& C = B.getContext();
		Type* I32 = Type::getInt32Ty(C);

		Value* x = B.CreateFreeze(pickI32FromContext(B), "obf.mba.x.fr");
		Value* y = B.CreateFreeze(pickI32FromContext(B), "obf.mba.y.fr");

		// Add canceling noise z to both sides to increase SMT complexity.
		uint32_t K0 = R.u32(), K1 = R.u32();
		unsigned V = (unsigned)R.range(3);
		Value* z = pickMix(B, loadVolatileI32(B), K0, K1, V);

		Value* lhs0 = nullptr;
		Value* rhs0 = nullptr;

		switch ((unsigned)R.range(3)) {
		default:
		case 0: {
			// (x^y) + 2*(x&y) == x + y
			Value* xy = B.CreateXor(x, y, "obf.mba.xy");
			Value* ab = B.CreateAnd(x, y, "obf.mba.ab");
			Value* tw = B.CreateShl(ab, ConstantInt::get(I32, 1), "obf.mba.tw");
			lhs0 = B.CreateAdd(xy, tw, "obf.mba.lhs0");
			rhs0 = B.CreateAdd(x, y, "obf.mba.rhs0");
			break;
		}
		case 1: {
			// (x|y) + (x&y) == x + y
			Value* o = B.CreateOr(x, y, "obf.mba.or");
			Value* a = B.CreateAnd(x, y, "obf.mba.and");
			lhs0 = B.CreateAdd(o, a, "obf.mba.lhs1");
			rhs0 = B.CreateAdd(x, y, "obf.mba.rhs1");
			break;
		}
		case 2: {
			// (x+y)^2 == x^2 + y^2 + 2xy (ring identity)
			Value* s = B.CreateAdd(x, y, "obf.mba.sum");
			rhs0 = B.CreateMul(s, s, "obf.mba.sq.rhs");

			Value* x2 = B.CreateMul(x, x, "obf.mba.x2");
			Value* y2 = B.CreateMul(y, y, "obf.mba.y2");
			Value* xy = B.CreateMul(x, y, "obf.mba.xy2");
			Value* tw = B.CreateShl(xy, ConstantInt::get(I32, 1), "obf.mba.tw2");
			lhs0 = B.CreateAdd(B.CreateAdd(x2, y2, "obf.mba.xy.a"), tw, "obf.mba.sq.lhs");
			break;
		}
		}

		Value* lhs = B.CreateAdd(lhs0, z, "obf.mba.lhs");
		Value* rhs = B.CreateAdd(rhs0, z, "obf.mba.rhs");
		return B.CreateICmpEQ(lhs, rhs, "obf.mba.true");
	}

	Value* OpaqueUtils::predMBAFalse(IRBuilder<>& B) {
		Value* T = predMBATrue(B); // builds graph; but we need a false variant from same sources
		// Rebuild a related false by forcing mismatch through hardFalse masking:
		//   false = (mba_true) && hardFalse  (runtime false, but not obviously constant)
		return B.CreateAnd(T, hardFalse(B), "obf.mba.false");
	}

	// Modular arithmetic family (use urem):
	//   (((7*x)%6 + (7*y)%6) % 6) == (7*(x+y))%6
	Value* OpaqueUtils::predModTrue(IRBuilder<>& B) {
		LLVMContext& C = B.getContext();
		Type* I32 = Type::getInt32Ty(C);
		Type* I64 = Type::getInt64Ty(C);

		// IMPORTANT: do modular identities in i64 to avoid i32 wrap-before-urem pitfalls.
		Value* x32 = B.CreateFreeze(pickI32FromContext(B), "obf.mod.x.fr");
		Value* y32 = B.CreateFreeze(pickI32FromContext(B), "obf.mod.y.fr");
		Value* x = B.CreateZExt(x32, I64, "obf.mod.x64");
		Value* y = B.CreateZExt(y32, I64, "obf.mod.y64");

		static constexpr uint32_t Primes[] = { 251u, 509u, 1009u, 4093u, 8191u, 12289u };
		uint32_t P = Primes[(size_t)R.range((uint32_t)(sizeof(Primes) / sizeof(Primes[0])))];
		uint32_t A = 1u + (uint32_t)R.range(31);
		uint32_t D = 1u + (uint32_t)R.range(31);

		Value* p = ConstantInt::get(I64, (uint64_t)P);
		Value* aC = ConstantInt::get(I64, (uint64_t)A);
		Value* dC = ConstantInt::get(I64, (uint64_t)D);

		// Add multiples of p to deepen the graph without changing residues.
		Value* k0 = B.CreateZExt(opaqueU32InRange(B, 1u << 10), I64, "obf.mod.k0");
		Value* k1 = B.CreateZExt(opaqueU32InRange(B, 1u << 10), I64, "obf.mod.k1");
		Value* x1 = B.CreateAdd(x, B.CreateMul(k0, p, "obf.mod.xp"), "obf.mod.x1");
		Value* y1 = B.CreateAdd(y, B.CreateMul(k1, p, "obf.mod.yp"), "obf.mod.y1");

		// (a*x + d*y) % p == ((a*x)%p + (d*y)%p) % p
		Value* ax = B.CreateMul(x1, aC, "obf.mod.ax");
		Value* dy = B.CreateMul(y1, dC, "obf.mod.dy");
		Value* lhs = B.CreateURem(B.CreateAdd(ax, dy, "obf.mod.sum"), p, "obf.mod.lhs");
		Value* rhs = B.CreateURem(
			B.CreateAdd(B.CreateURem(ax, p, "obf.mod.axm"),
				B.CreateURem(dy, p, "obf.mod.dym"),
				"obf.mod.rs"),
			p, "obf.mod.rhs");

		// Fold back to i32 equality to keep predicate shape consistent.
		Value* l32 = B.CreateTrunc(lhs, I32, "obf.mod.l32");
		Value* r32 = B.CreateTrunc(rhs, I32, "obf.mod.r32");
		return B.CreateICmpEQ(l32, r32, "obf.mod.true");
	}

	Value* OpaqueUtils::predModFalse(IRBuilder<>& B) {
		// false = mod_true && hardFalse (keeps “false at runtime”, adds complexity)
		return B.CreateAnd(predModTrue(B), hardFalse(B), "obf.mod.false");
	}

	// Hash collision family (crafted):
	// Let hash(v) = v & 0xFFFF (equiv to v mod 2^16).
	// Choose y = x + 65536 * (entropy|1), then hash(x) == hash(y) always.
	Value* OpaqueUtils::predHashTrue(IRBuilder<>& B) {
		LLVMContext& C = B.getContext();
		Type* I32 = Type::getInt32Ty(C);

		Value* x = B.CreateFreeze(pickI32FromContext(B), "obf.hash.x.fr");
		Value* e = B.CreateFreeze(loadEntropyI32(B), "obf.hash.e.fr");
		Value* e1 = B.CreateOr(e, ConstantInt::get(I32, 1), "obf.hash.e1");

		// y = x + 2^16 * k => low16(y) == low16(x)
		Value* mul = B.CreateMul(e1, ConstantInt::get(I32, 1u << 16), "obf.hash.mul16");
		Value* y = B.CreateAdd(x, mul, "obf.hash.y");

		auto h16 = [&](Value* v, const char* tag) -> Value* {
			Value* mask = ConstantInt::get(I32, 0xFFFFu);
			Value* t = B.CreateAnd(v, mask, (std::string(tag) + ".m0").c_str());
			// Multi-round low16 mixing; each round masks back to 16 bits so result depends only on low16.
			uint32_t p1 = 40503u; // odd
			uint32_t p2 = 62209u; // odd
			uint32_t k1 = R.u32() & 0xFFFFu;
			uint32_t k2 = R.u32() & 0xFFFFu;
			t = B.CreateAdd(B.CreateMul(t, ConstantInt::get(I32, p1), (std::string(tag) + ".mul1").c_str()),
				ConstantInt::get(I32, k1), (std::string(tag) + ".add1").c_str());
			t = B.CreateAnd(t, mask, (std::string(tag) + ".m1").c_str());
			Value* sh = B.CreateLShr(t, ConstantInt::get(I32, 7), (std::string(tag) + ".shr").c_str());
			t = B.CreateXor(t, sh, (std::string(tag) + ".x1").c_str());
			t = B.CreateAnd(t, mask, (std::string(tag) + ".m2").c_str());
			t = B.CreateAdd(B.CreateMul(t, ConstantInt::get(I32, p2), (std::string(tag) + ".mul2").c_str()),
				ConstantInt::get(I32, k2), (std::string(tag) + ".add2").c_str());
			t = B.CreateAnd(t, mask, (std::string(tag) + ".m3").c_str());
			return B.CreateFreeze(t, (std::string(tag) + ".fr").c_str());
			};

		Value* hx = h16(x, "obf.hash.hx");
		Value* hy = h16(y, "obf.hash.hy");

		return B.CreateICmpEQ(hx, hy, "obf.hash.true");
	}

	Value* OpaqueUtils::predHashFalse(IRBuilder<>& B) {
		Value* T = predHashTrue(B);
		// Make it false via conjunction with a hardFalse (runtime false, still non-trivial)
		return B.CreateAnd(T, hardFalse(B), "obf.hash.false");
	}

	// Pointer aliasing family (UB-safe):
	//   p == gep(p, opaqueZero)  (always true at runtime)
	// and false variant:
	//   p == gep(p, opaqueZero + 1) (always false at runtime)
	Value* OpaqueUtils::predPtrEqTrue(IRBuilder<>& B) {
		LLVMContext& C = B.getContext();
		Type* I8 = Type::getInt8Ty(C);

		AllocaInst* Slot = getOrCreateVolatileI32Slot(B);
		if (!Slot)
			return hardTrue(B);

		// Opaque pointers: alloca already yields `ptr`; no bitcast needed.
		Value* p0 = Slot;
		Value* off0 = opaqueZero64(B); // runtime 0, not provably constant
		Value* p1 = B.CreateGEP(I8, p0, off0, "obf.ptr.p1"); // non-inbounds to avoid UB assumptions
		return B.CreateICmpEQ(p0, p1, "obf.ptr.true");
	}

	Value* OpaqueUtils::predPtrEqFalse(IRBuilder<>& B) {
		LLVMContext& C = B.getContext();
		Type* I8 = Type::getInt8Ty(C);
		Type* I64 = Type::getInt64Ty(C);

		AllocaInst* Slot = getOrCreateVolatileI32Slot(B);
		if (!Slot)
			return hardFalse(B);

		// Opaque pointers: alloca already yields `ptr`; no bitcast needed.
		Value* p0 = Slot;
		Value* off0 = opaqueZero64(B);
		Value* off1 = B.CreateAdd(off0, ConstantInt::get(I64, 1), "obf.ptrf.off1");
		Value* p1 = B.CreateGEP(I8, p0, off1, "obf.ptrf.p1");
		return B.CreateICmpEQ(p0, p1, "obf.ptr.false");
	}

	// -------------------- Enhanced composition -----------------------------------

	Value* OpaqueUtils::getStateI32(IRBuilder<>& B) {
		Type* I32 = Type::getInt32Ty(B.getContext());
		GlobalVariable* GV = M.getNamedGlobal("obf.state.i32");
		if (!GV) {
			GV = new GlobalVariable(M, I32, /*isConstant*/false,
				GlobalValue::InternalLinkage, ConstantInt::get(I32, 0), "obf.state.i32");
			GV->setAlignment(Align(4));
		}
		auto* L = B.CreateLoad(I32, GV, "obf.st.ld");
		L->setVolatile(true);
		L->setAlignment(Align(4));
		Value* S = B.CreateFreeze(L, "obf.st.fr");

		uint32_t K0 = R.u32(), K1 = R.u32();
		unsigned V = (unsigned)R.range(3);
		Value* Mix = pickMix(B, B.CreateXor(loadVolatileI32(B), loadEntropyI32(B), "obf.st.xe"), K0, K1, V);
		Value* NewS = B.CreateAdd(S, Mix, "obf.st.new");
		auto* St = B.CreateStore(NewS, GV);
		St->setVolatile(true);
		St->setAlignment(Align(4));
		return S;
	}

	Value* OpaqueUtils::generateTrueFamily(IRBuilder<>& B, unsigned FamilyIdx, unsigned Strength) {
		LLVMContext& C = B.getContext();
		Type* I32 = Type::getInt32Ty(C);
		Type* I64 = Type::getInt64Ty(C);

		unsigned Idx = 0;

		if (FamilyIdx == Idx++) return hardTrue(B);
		if (FamilyIdx == Idx++) return legacySaltEntropyTrue(B);

		if (Opts.EnableMBAFamily) {
			if (FamilyIdx == Idx++) return predMBATrue(B);
		}
		if (Opts.EnablePtrFamily) {
			if (FamilyIdx == Idx++) return predPtrEqTrue(B);
		}
		if (Opts.EnableModArithFamily) {
			if (FamilyIdx == Idx++) return predModTrue(B);
		}
		if (Opts.EnableHashFamily) {
			if (FamilyIdx == Idx++) return predHashTrue(B);
		}

		// mkRotTrue
		if (FamilyIdx == Idx++) {
			Value* x = B.CreateFreeze(pickI32FromContext(B), "obf.rot.x");
			Value* y = B.CreateFreeze(pickI32FromContext(B), "obf.rot.y");
			Value* amt = B.CreateXor(getStateI32(B), loadEntropyI32(B), "obf.rot.a0");
			amt = B.CreateAnd(amt, ConstantInt::get(I32, 31), "obf.rot.a1");
			Value* rx = obf_rotl32(B, x, amt);
			Value* ry = obf_rotl32(B, y, amt);
			Value* lhs = B.CreateXor(rx, ry, "obf.rot.lhs");
			Value* rhs = obf_rotl32(B, B.CreateXor(x, y, "obf.rot.xy"), amt);
			uint32_t P = 65521u;
			Value* p = ConstantInt::get(I64, P);
			uint32_t C1 = (R.u32() | 1u);
			Value* c1 = ConstantInt::get(I64, (uint64_t)C1);
			Value* l64 = B.CreateURem(B.CreateMul(obf_zextI64(B, lhs), c1, "obf.rot.m1"), p, "obf.rot.r1");
			Value* r64 = B.CreateURem(B.CreateMul(obf_zextI64(B, rhs), c1, "obf.rot.m2"), p, "obf.rot.r2");
			return B.CreateICmpEQ(l64, r64, "obf.rot.true");
		}

		// mkPolyTrue
		if (FamilyIdx == Idx++) {
			Value* x = B.CreateFreeze(pickI32FromContext(B), "obf.poly.x");
			Value* y = B.CreateFreeze(pickI32FromContext(B), "obf.poly.y");
			Value* s = B.CreateAdd(x, y, "obf.poly.s");
			if (Strength >= 3) {
				Value* x2 = B.CreateMul(x, x, "obf.poly.x2");
				Value* x3 = B.CreateMul(x2, x, "obf.poly.x3");
				Value* x4 = B.CreateMul(x2, x2, "obf.poly.x4");
				Value* x5 = B.CreateMul(x4, x, "obf.poly.x5");
				Value* y2 = B.CreateMul(y, y, "obf.poly.y2");
				Value* y3 = B.CreateMul(y2, y, "obf.poly.y3");
				Value* y4 = B.CreateMul(y2, y2, "obf.poly.y4");
				Value* y5 = B.CreateMul(y4, y, "obf.poly.y5");
				Value* s2 = B.CreateMul(s, s, "obf.poly.s2");
				Value* s4 = B.CreateMul(s2, s2, "obf.poly.s4");
				Value* s5 = B.CreateMul(s4, s, "obf.poly.s5");
				Value* five = ConstantInt::get(I32, 5);
				Value* ten = ConstantInt::get(I32, 10);
				Value* t1 = B.CreateMul(five, B.CreateMul(x4, y, "obf.poly.x4y"), "obf.poly.5x4y");
				Value* t2 = B.CreateMul(ten, B.CreateMul(x3, y2, "obf.poly.x3y2"), "obf.poly.10x3y2");
				Value* t3 = B.CreateMul(ten, B.CreateMul(x2, y3, "obf.poly.x2y3"), "obf.poly.10x2y3");
				Value* t4 = B.CreateMul(five, B.CreateMul(x, y4, "obf.poly.xy4"), "obf.poly.5xy4");
				Value* rhs = B.CreateAdd(x5, y5, "obf.poly.r0");
				rhs = B.CreateAdd(rhs, t1, "obf.poly.r1");
				rhs = B.CreateAdd(rhs, t2, "obf.poly.r2");
				rhs = B.CreateAdd(rhs, t3, "obf.poly.r3");
				rhs = B.CreateAdd(rhs, t4, "obf.poly.r4");
				return B.CreateICmpEQ(s5, rhs, "obf.poly.true");
			}
			Value* s2 = B.CreateMul(s, s, "obf.poly.s2");
			Value* s3 = B.CreateMul(s2, s, "obf.poly.s3");
			Value* x2 = B.CreateMul(x, x, "obf.poly.x2");
			Value* y2 = B.CreateMul(y, y, "obf.poly.y2");
			Value* x3 = B.CreateMul(x2, x, "obf.poly.x3");
			Value* y3 = B.CreateMul(y2, y, "obf.poly.y3");
			Value* three = ConstantInt::get(I32, 3);
			Value* t1 = B.CreateMul(three, B.CreateMul(x2, y, "obf.poly.x2y"), "obf.poly.3x2y");
			Value* t2 = B.CreateMul(three, B.CreateMul(x, y2, "obf.poly.xy2"), "obf.poly.3xy2");
			Value* rhs = B.CreateAdd(B.CreateAdd(x3, y3, "obf.poly.r0"), B.CreateAdd(t1, t2, "obf.poly.r1"), "obf.poly.rhs");
			return B.CreateICmpEQ(s3, rhs, "obf.poly.true");
		}

		// mkMixedRadixTrue
		if (Strength >= 2) {
			if (FamilyIdx == Idx++) {
				Value* x = obf_zextI64(B, B.CreateFreeze(pickI32FromContext(B), "obf.mr.x"));
				Value* y = obf_zextI64(B, B.CreateFreeze(pickI32FromContext(B), "obf.mr.y"));
				Value* sv = obf_zextI64(B, getStateI32(B));
				static constexpr uint32_t P1 = 251u, P2 = 509u;
				Value* p1 = ConstantInt::get(I64, P1);
				Value* p2 = ConstantInt::get(I64, P2);
				uint32_t a = 1u + (uint32_t)R.range(63);
				uint32_t b = 1u + (uint32_t)R.range(63);
				uint32_t c = 1u + (uint32_t)R.range(63);
				Value* A = ConstantInt::get(I64, a);
				Value* Bc = ConstantInt::get(I64, b);
				Value* Cc = ConstantInt::get(I64, c);
				auto modEq = [&](Value* mod, const char* tag) -> Value* {
					Value* ax = B.CreateMul(A, x, (std::string(tag) + ".ax").c_str());
					Value* by = B.CreateMul(Bc, y, (std::string(tag) + ".by").c_str());
					Value* cs = B.CreateMul(Cc, sv, (std::string(tag) + ".cs").c_str());
					Value* sum = B.CreateAdd(B.CreateAdd(ax, by, (std::string(tag) + ".s0").c_str()), cs, (std::string(tag) + ".s1").c_str());
					Value* lhs = B.CreateURem(sum, mod, (std::string(tag) + ".lhs").c_str());
					Value* rhs = B.CreateURem(
						B.CreateAdd(
							B.CreateAdd(B.CreateURem(ax, mod, (std::string(tag) + ".axm").c_str()),
								B.CreateURem(by, mod, (std::string(tag) + ".bym").c_str()),
								(std::string(tag) + ".rs0").c_str()),
							B.CreateURem(cs, mod, (std::string(tag) + ".csm").c_str()),
							(std::string(tag) + ".rs1").c_str()),
						mod, (std::string(tag) + ".rhs").c_str());
					return B.CreateXor(lhs, rhs, (std::string(tag) + ".dx").c_str());
					};
				Value* d1 = modEq(p1, "obf.mr.p1");
				Value* d2 = modEq(p2, "obf.mr.p2");
				Value* comb = B.CreateOr(d1, B.CreateShl(d2, ConstantInt::get(I64, 16), "obf.mr.sh"), "obf.mr.comb");
				return B.CreateICmpEQ(comb, ConstantInt::get(I64, 0), "obf.mr.true");
			}
		}

		// mkCompositeTrue
		if (Strength >= 3) {
			if (FamilyIdx == Idx++) {
				Value* v = B.CreateFreeze(pickI32FromContext(B), "obf.comp.v");
				Value* Av = loadVolatileI32(B);
				Value* Dv = loadVolatileI32(B);
				Value* Z = B.CreateXor(Av, Dv, "obf.comp.z");
				Value* v2 = B.CreateAdd(v, Z, "obf.comp.vz");
				Value* amt = B.CreateAnd(B.CreateXor(getStateI32(B), loadEntropyI32(B), "obf.comp.a0"), ConstantInt::get(I32, 31), "obf.comp.a1");
				auto f = [&](Value* t, const char* tag) -> Value* {
					Value* r = obf_rotl32(B, t, amt);
					Value* sh = B.CreateLShr(t, ConstantInt::get(I32, 13), (std::string(tag) + ".shr").c_str());
					Value* m = B.CreateXor(r, sh, (std::string(tag) + ".x1").c_str());
					uint32_t odd = (R.u32() | 1u);
					Value* mm = B.CreateMul(m, ConstantInt::get(I32, odd), (std::string(tag) + ".mul").c_str());
					Value* mm64 = obf_zextI64(B, mm);
					Value* p = ConstantInt::get(I64, 4093u);
					return B.CreateURem(mm64, p, (std::string(tag) + ".rem").c_str());
					};
				Value* f1 = f(v, "obf.comp.f1");
				Value* f2 = f(v2, "obf.comp.f2");
				return B.CreateICmpEQ(f1, f2, "obf.comp.true");
			}
		}

		return hardTrue(B);
	}

	Value* OpaqueUtils::generateFalseFamily(IRBuilder<>& B, unsigned FamilyIdx, unsigned Strength) {
		LLVMContext& C = B.getContext();
		Type* I32 = Type::getInt32Ty(C);
		Type* I64 = Type::getInt64Ty(C);

		unsigned Idx = 0;

		if (FamilyIdx == Idx++) return hardFalse(B);
		if (FamilyIdx == Idx++) return legacySaltEntropyFalse(B);

		if (Opts.EnableMBAFamily) {
			if (FamilyIdx == Idx++) return predMBAFalse(B);
		}
		if (Opts.EnablePtrFamily) {
			if (FamilyIdx == Idx++) return predPtrEqFalse(B);
		}
		if (Opts.EnableModArithFamily) {
			if (FamilyIdx == Idx++) return predModFalse(B);
		}
		if (Opts.EnableHashFamily) {
			if (FamilyIdx == Idx++) return predHashFalse(B);
		}

		// mkRotFalse
		if (FamilyIdx == Idx++) {
			Value* x = B.CreateFreeze(pickI32FromContext(B), "obf.rotf.x");
			Value* y = B.CreateFreeze(pickI32FromContext(B), "obf.rotf.y");
			Value* amt = B.CreateAnd(B.CreateXor(getStateI32(B), loadEntropyI32(B), "obf.rotf.a0"), ConstantInt::get(I32, 31), "obf.rotf.a1");
			Value* rx = obf_rotl32(B, x, amt);
			Value* ry = obf_rotl32(B, y, amt);
			Value* lhs = B.CreateXor(rx, ry, "obf.rotf.lhs");
			Value* rhs = obf_rotl32(B, B.CreateXor(x, y, "obf.rotf.xy"), amt);
			uint32_t P = 65521u;
			Value* p = ConstantInt::get(I64, P);
			uint32_t C1 = (R.u32() | 1u);
			Value* c1 = ConstantInt::get(I64, (uint64_t)C1);
			Value* l64 = B.CreateURem(B.CreateMul(obf_zextI64(B, lhs), c1, "obf.rotf.m1"), p, "obf.rotf.r1");
			Value* r64 = B.CreateURem(B.CreateMul(obf_zextI64(B, rhs), c1, "obf.rotf.m2"), p, "obf.rotf.r2");
			Value* T = B.CreateICmpEQ(l64, r64, "obf.rotf.t");
			return B.CreateAnd(T, hardFalse(B), "obf.rot.false");
		}

		// mkPolyFalse
		if (FamilyIdx == Idx++) {
			Value* x = B.CreateFreeze(pickI32FromContext(B), "obf.polyf.x");
			Value* y = B.CreateFreeze(pickI32FromContext(B), "obf.polyf.y");
			Value* s = B.CreateAdd(x, y, "obf.polyf.s");
			Value* s2 = B.CreateMul(s, s, "obf.polyf.s2");
			Value* s3 = B.CreateMul(s2, s, "obf.polyf.s3");
			Value* x2 = B.CreateMul(x, x, "obf.polyf.x2");
			Value* y2 = B.CreateMul(y, y, "obf.polyf.y2");
			Value* x3 = B.CreateMul(x2, x, "obf.polyf.x3");
			Value* y3 = B.CreateMul(y2, y, "obf.polyf.y3");
			Value* three = ConstantInt::get(I32, 3);
			Value* t1 = B.CreateMul(three, B.CreateMul(x2, y, "obf.polyf.x2y"), "obf.polyf.3x2y");
			Value* t2 = B.CreateMul(three, B.CreateMul(x, y2, "obf.polyf.xy2"), "obf.polyf.3xy2");
			Value* rhs = B.CreateAdd(B.CreateAdd(x3, y3, "obf.polyf.r0"), B.CreateAdd(t1, t2, "obf.polyf.r1"), "obf.polyf.rhs");
			Value* T = B.CreateICmpEQ(s3, rhs, "obf.polyf.t");
			return B.CreateAnd(T, hardFalse(B), "obf.poly.false");
		}

		// mkMixedRadixFalse
		if (Strength >= 2) {
			if (FamilyIdx == Idx++) {
				Value* x = obf_zextI64(B, B.CreateFreeze(pickI32FromContext(B), "obf.mrf.x"));
				Value* y = obf_zextI64(B, B.CreateFreeze(pickI32FromContext(B), "obf.mrf.y"));
				Value* s0 = obf_zextI64(B, getStateI32(B));
				static constexpr uint32_t P1 = 251u, P2 = 509u;
				Value* p1 = ConstantInt::get(I64, P1);
				Value* p2 = ConstantInt::get(I64, P2);
				uint32_t a = 1u + (uint32_t)R.range(63);
				uint32_t b = 1u + (uint32_t)R.range(63);
				uint32_t c = 1u + (uint32_t)R.range(63);
				Value* A = ConstantInt::get(I64, a);
				Value* Bc = ConstantInt::get(I64, b);
				Value* Cc = ConstantInt::get(I64, c);
				auto modEq = [&](Value* mod, const char* tag) -> Value* {
					Value* ax = B.CreateMul(A, x, (std::string(tag) + ".ax").c_str());
					Value* by = B.CreateMul(Bc, y, (std::string(tag) + ".by").c_str());
					Value* cs = B.CreateMul(Cc, s0, (std::string(tag) + ".cs").c_str());
					Value* sum = B.CreateAdd(B.CreateAdd(ax, by, (std::string(tag) + ".s0").c_str()), cs, (std::string(tag) + ".s1").c_str());
					Value* lhs = B.CreateURem(sum, mod, (std::string(tag) + ".lhs").c_str());
					Value* rhs = B.CreateURem(
						B.CreateAdd(
							B.CreateAdd(B.CreateURem(ax, mod, (std::string(tag) + ".axm").c_str()),
								B.CreateURem(by, mod, (std::string(tag) + ".bym").c_str()),
								(std::string(tag) + ".rs0").c_str()),
							B.CreateURem(cs, mod, (std::string(tag) + ".csm").c_str()),
							(std::string(tag) + ".rs1").c_str()),
						mod, (std::string(tag) + ".rhs").c_str());
					return B.CreateXor(lhs, rhs, (std::string(tag) + ".dx").c_str());
					};
				Value* d1 = modEq(p1, "obf.mrf.p1");
				Value* d2 = modEq(p2, "obf.mrf.p2");
				Value* comb = B.CreateOr(d1, B.CreateShl(d2, ConstantInt::get(I64, 16), "obf.mrf.sh"), "obf.mrf.comb");
				Value* T = B.CreateICmpEQ(comb, ConstantInt::get(I64, 0), "obf.mrf.t");
				return B.CreateAnd(T, hardFalse(B), "obf.mr.false");
			}
		}

		// mkCompositeFalse
		if (Strength >= 3) {
			if (FamilyIdx == Idx++) {
				Value* v = B.CreateFreeze(pickI32FromContext(B), "obf.compf.v");
				Value* Av = loadVolatileI32(B);
				Value* Dv = loadVolatileI32(B);
				Value* Z = B.CreateXor(Av, Dv, "obf.compf.z");
				Value* v2 = B.CreateAdd(v, Z, "obf.compf.vz");
				Value* amt = B.CreateAnd(B.CreateXor(getStateI32(B), loadEntropyI32(B), "obf.compf.a0"), ConstantInt::get(I32, 31), "obf.compf.a1");
				auto f = [&](Value* t, const char* tag) -> Value* {
					Value* r = obf_rotl32(B, t, amt);
					Value* sh = B.CreateLShr(t, ConstantInt::get(I32, 13), (std::string(tag) + ".shr").c_str());
					Value* m = B.CreateXor(r, sh, (std::string(tag) + ".x1").c_str());
					uint32_t odd = (R.u32() | 1u);
					Value* mm = B.CreateMul(m, ConstantInt::get(I32, odd), (std::string(tag) + ".mul").c_str());
					Value* mm64 = obf_zextI64(B, mm);
					Value* p = ConstantInt::get(I64, 4093u);
					return B.CreateURem(mm64, p, (std::string(tag) + ".rem").c_str());
					};
				Value* f1 = f(v, "obf.compf.f1");
				Value* f2 = f(v2, "obf.compf.f2");
				Value* T = B.CreateICmpEQ(f1, f2, "obf.compf.t");
				return B.CreateAnd(T, hardFalse(B), "obf.comp.false");
			}
		}

		return hardFalse(B);
	}



	Value* OpaqueUtils::enhancedTrue(IRBuilder<>& B, unsigned StrengthHint) {
		if (!Opts.EnableHardPreds)
			return ConstantInt::getTrue(B.getContext());

		unsigned Strength = std::max(Opts.PredStrength, StrengthHint);
		if (Strength == 0)
			return hardTrue(B);

		// Count available families without generating any IR
		unsigned FamilyCount = 2; // hardTrue + legacySaltEntropyTrue
		if (Opts.EnableMBAFamily)      ++FamilyCount;
		if (Opts.EnablePtrFamily)      ++FamilyCount;
		if (Opts.EnableModArithFamily) ++FamilyCount;
		if (Opts.EnableHashFamily)     ++FamilyCount;
		FamilyCount += 2; // mkRotTrue + mkPolyTrue
		if (Strength >= 2) ++FamilyCount; // mkMixedRadixTrue
		if (Strength >= 3) ++FamilyCount; // mkCompositeTrue

		// LAZY: pick family index first, generate ONLY that family
		unsigned Sel = (unsigned)R.range((uint32_t)FamilyCount);
		Value* P = generateTrueFamily(B, Sel, Strength);

		// Composition: 1 lightweight layer (was 2-4 heavy layers)
		if (Strength >= 2) {
			Value* Q = hardTrue(B);
			Value* Cnd = opaqueBool(B);
			Value* PQ = B.CreateAnd(P, Q, "obf.true.and");
			P = B.CreateSelect(Cnd, PQ, P, "obf.true.sel");
		}

		if (Strength >= 3) {
			Value* Fv = hardFalse(B);
			Value* Tv = hardTrue(B);
			Value* a = B.CreateOr(P, Fv, "obf.true.o1");
			Value* b = B.CreateOr(P, Tv, "obf.true.o2");
			P = B.CreateAnd(a, b, "obf.true.fin");
		}

		return B.CreateFreeze(P, "obf.true.fr");
	}

	Value* OpaqueUtils::enhancedFalse(IRBuilder<>& B, unsigned StrengthHint) {
		if (!Opts.EnableHardPreds)
			return ConstantInt::getFalse(B.getContext());

		unsigned Strength = std::max(Opts.PredStrength, StrengthHint);
		if (Strength == 0)
			return hardFalse(B);

		unsigned FamilyCount = 2;
		if (Opts.EnableMBAFamily)      ++FamilyCount;
		if (Opts.EnablePtrFamily)      ++FamilyCount;
		if (Opts.EnableModArithFamily) ++FamilyCount;
		if (Opts.EnableHashFamily)     ++FamilyCount;
		FamilyCount += 2;
		if (Strength >= 2) ++FamilyCount;
		if (Strength >= 3) ++FamilyCount;

		unsigned Sel = (unsigned)R.range((uint32_t)FamilyCount);
		Value* P = generateFalseFamily(B, Sel, Strength);

		if (Strength >= 2) {
			Value* Q = hardFalse(B);
			Value* Cnd = opaqueBool(B);
			Value* PQ = B.CreateOr(P, Q, "obf.false.or");
			P = B.CreateSelect(Cnd, PQ, P, "obf.false.sel");
		}

		if (Strength >= 3) {
			Value* Fv = hardFalse(B);
			Value* Tv = hardTrue(B);
			Value* a = B.CreateAnd(P, Tv, "obf.false.a1");
			Value* b = B.CreateAnd(P, Fv, "obf.false.a2");
			P = B.CreateOr(a, b, "obf.false.fin");
		}

		return B.CreateFreeze(P, "obf.false.fr");
	}


	Value* OpaqueUtils::randomHardTrue(IRBuilder<>& B) {
		// Harmonized: include all enhanced families (MBA/mod/hash/ptr) with strength controls.
		return enhancedTrue(B);
	}

	Value* OpaqueUtils::randomHardFalse(IRBuilder<>& B) {
		switch (R.range(3)) {
		case 0: return hardFalse(B);
		case 1: {
			// hardFalse variant: force mismatch on one side
			LLVMContext& C = B.getContext();
			Type* I32 = Type::getInt32Ty(C);
			Value* S0 = loadVolatileI32(B);
			Value* S1 = loadVolatileI32(B);
			uint32_t K0 = R.u32(), K1 = R.u32();
			unsigned V = (unsigned)R.range(3);
			Value* X0 = pickMix(B, S0, K0, K1, V);
			Value* X1 = pickMix(B, S1, K0, K1, V);
			X1 = B.CreateAdd(X1, ConstantInt::get(I32, 1), "obf.rf.add1");
			return B.CreateICmpEQ(X0, X1, "obf.rand.false");
		}
		default:
			return selectHardFalse(B, legacySaltEntropyFalse(B), predMBAFalse(B));
		}
	}

	// -------------------- unpredictable opaque bool ------------------------------

	Value* OpaqueUtils::opaqueBool(IRBuilder<>& B) {
		if (!Opts.EnableOpaqueBools)
			return hardFalse(B); // deterministic fallback

		LLVMContext& C = B.getContext();
		Type* I32 = Type::getInt32Ty(C);

		Value* S = loadVolatileI32(B);
		Value* E = loadEntropyI32(B);

		// Mix salt with entropy, then extract a random bit.
		Value* X = B.CreateXor(S, E, "obf.ob.xe");
		uint32_t K0 = R.u32();
		uint32_t K1 = R.u32();
		unsigned V = (unsigned)R.range(3);
		X = pickMix(B, X, K0, K1, V);

		unsigned Sh = (unsigned)R.range(31); // 0..30
		Value* Sft = B.CreateLShr(X, ConstantInt::get(I32, Sh), "obf.ob.shr");
		Value* Bit = B.CreateAnd(Sft, ConstantInt::get(I32, 1), "obf.ob.bit");
		return B.CreateICmpEQ(Bit, ConstantInt::get(I32, 0), "obf.ob");
	}

	// -------------------- opaque constants ---------------------------------------

	Value* OpaqueUtils::opaqueI32Const(IRBuilder<>& B, uint32_t Cst) {
		Type* I32 = Type::getInt32Ty(B.getContext());
		if (!Opts.EnableOpaqueConsts || !Opts.EnableHardPreds)
			return ConstantInt::get(I32, Cst);

		// Two volatile loads from same slot; runtime equal, optimizer cannot assume.
		Value* A = loadVolatileI32(B);
		Value* D = loadVolatileI32(B);

		// (A^K)^(D^(K^C)) == C when A==D at runtime
		uint32_t K = R.u32();
		Value* X1 = B.CreateXor(A, ConstantInt::get(I32, K), "obf.oc.x1");
		Value* X2 = B.CreateXor(D, ConstantInt::get(I32, (K ^ Cst)), "obf.oc.x2");
		Value* Res = B.CreateXor(X1, X2, "obf.oc");

		// Cancelling noise based on (A^D) which is 0 at runtime.
		Value* Delta = B.CreateXor(A, D, "obf.oc.delta");
		uint32_t Mul = (R.u32() | 1u);
		Delta = B.CreateMul(Delta, ConstantInt::get(I32, Mul), "obf.oc.dmul");
		Res = B.CreateAdd(Res, Delta, "obf.oc.add");

		return B.CreateFreeze(Res, "obf.oc.fr");
	}

	Value* OpaqueUtils::opaqueZero32(IRBuilder<>& B) {
		Value* A = loadVolatileI32(B);
		Value* D = loadVolatileI32(B);
		Value* Z = B.CreateXor(A, D, "obf.z32");
		return B.CreateFreeze(Z, "obf.z32.fr");
	}

	Value* OpaqueUtils::opaqueZero64(IRBuilder<>& B) {
		LLVMContext& C = B.getContext();
		Type* I64 = Type::getInt64Ty(C);
		Value* Z32 = opaqueZero32(B);
		return B.CreateZExt(Z32, I64, "obf.z64");
	}

	Value* OpaqueUtils::opaqueU32InRange(IRBuilder<>& B, uint32_t MaxExclusive) {
		Type* I32 = Type::getInt32Ty(B.getContext());
		if (MaxExclusive == 0)
			return ConstantInt::get(I32, 0);

		if (!Opts.EnableOpaqueConsts)
			return ConstantInt::get(I32, 0); // deterministic fallback

		Value* S = loadVolatileI32(B);
		Value* E = loadEntropyI32(B);
		Value* X = B.CreateXor(S, E, "obf.rng.xe");

		uint32_t K0 = R.u32();
		uint32_t K1 = R.u32();
		unsigned V = (unsigned)R.range(3);
		X = pickMix(B, X, K0, K1, V);

		Value* Mod = B.CreateURem(X, ConstantInt::get(I32, MaxExclusive), "obf.rng.mod");
		return B.CreateFreeze(Mod, "obf.rng.fr");
	}

	// -------------------- hardened eq/ne -----------------------------------------

	Value* OpaqueUtils::hardEqI32(IRBuilder<>& B, Value* L, Value* Rhs) {
		Value* L0 = B.CreateFreeze(L, "obf.eq.l.fr");
		Value* R0 = B.CreateFreeze(Rhs, "obf.eq.r.fr");

		// Fold into anchor to make it less “local”.
		Value* S = loadVolatileI32(B);

		uint32_t K0 = R.u32();
		uint32_t K1 = R.u32();
		unsigned V = (unsigned)R.range(3);

		Value* ML = pickMix(B, B.CreateXor(L0, S, "obf.eq.ls"), K0, K1, V);
		Value* MR = pickMix(B, B.CreateXor(R0, S, "obf.eq.rs"), K0, K1, V);

		// Compare mixed values (equality preserved).
		return B.CreateICmpEQ(ML, MR, "obf.eq");
	}

	Value* OpaqueUtils::hardNeI32(IRBuilder<>& B, Value* L, Value* Rhs) {
		Value* Eq = hardEqI32(B, L, Rhs);
		return B.CreateNot(Eq, "obf.ne");
	}

	// -------------------- opaque selects -----------------------------------------

	Value* OpaqueUtils::selectHardFalse(IRBuilder<>& B, Value* AlwaysTrueSide, Value* AlwaysFalseSide) {
		Value* HF = hardFalse(B);
		return B.CreateSelect(HF, AlwaysTrueSide, AlwaysFalseSide, "obf.sel.hf");
	}

	Value* OpaqueUtils::selectHardTrue(IRBuilder<>& B, Value* AlwaysTrueSide, Value* AlwaysFalseSide) {
		Value* HT = hardTrue(B);
		return B.CreateSelect(HT, AlwaysTrueSide, AlwaysFalseSide, "obf.sel.ht");
	}

} // namespace llvm::obf