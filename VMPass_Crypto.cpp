#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Bitcode/BitcodeReader.h"
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
#include "llvm/Linker/Linker.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include "llvm/Transforms/Obfuscator/VMPass_Impl.h"
#include "llvm/Transforms/Obfuscator/VMPass_ISA.h"
#include "llvm/Transforms/Obfuscator/VMPass_Emitter.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/AESStubBitcode.h"

#include <functional>
using namespace llvm;

#define DEBUG_TYPE "vm"

STATISTIC(VMCallSites, "Call sites virtualised");

namespace llvm
{
	namespace vm_aes
	{

		const uint8_t SBOX[256] = {
			0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
			0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
			0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
			0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
			0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
			0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
			0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
			0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
			0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
			0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
			0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
			0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
			0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
			0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
			0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
			0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
		};

		const uint8_t RCON[11] = {
			0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
		};

		void keyExpand(const uint8_t key[16], uint8_t rk[176]) {
			for (int i = 0; i < 16; i++) rk[i] = key[i];
			for (int i = 4; i < 44; i++) {
				uint8_t temp[4];
				for (int j = 0; j < 4; j++) temp[j] = rk[(i - 1) * 4 + j];
				if (i % 4 == 0) {
					uint8_t t = temp[0];
					temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
					for (int j = 0; j < 4; j++) temp[j] = SBOX[temp[j]];
					temp[0] ^= RCON[i / 4];
				}
				for (int j = 0; j < 4; j++)
					rk[i * 4 + j] = rk[(i - 4) * 4 + j] ^ temp[j];
			}
		}

		static inline uint8_t xtime(uint8_t x) {
			return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1bu));
		}

		static void shiftRows(uint8_t s[16]) {
			uint8_t t;
			t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
			t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
			t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
		}

		static void mixColumns(uint8_t s[16]) {
			for (int c = 0; c < 4; c++) {
				uint8_t a = s[c * 4], b = s[c * 4 + 1], cc = s[c * 4 + 2], d = s[c * 4 + 3];
				uint8_t tmp = a ^ b ^ cc ^ d;
				s[c * 4 + 0] ^= tmp ^ xtime((uint8_t)(a ^ b));
				s[c * 4 + 1] ^= tmp ^ xtime((uint8_t)(b ^ cc));
				s[c * 4 + 2] ^= tmp ^ xtime((uint8_t)(cc ^ d));
				s[c * 4 + 3] ^= tmp ^ xtime((uint8_t)(d ^ a));
			}
		}

		void encryptBlock(const uint8_t rk[176], uint8_t blk[16]) {
			uint8_t s[16];
			for (int i = 0; i < 16; i++) s[i] = blk[i] ^ rk[i];
			for (int r = 1; r <= 9; r++) {
				for (int i = 0; i < 16; i++) s[i] = SBOX[s[i]];
				shiftRows(s);
				mixColumns(s);
				for (int i = 0; i < 16; i++) s[i] ^= rk[r * 16 + i];
			}
			for (int i = 0; i < 16; i++) s[i] = SBOX[s[i]];
			shiftRows(s);
			for (int i = 0; i < 16; i++) blk[i] = s[i] ^ rk[160 + i];
		}

		void ctr(const uint8_t rk[176], const uint8_t nonce8[8],
			uint8_t* buf, size_t len) {
			uint8_t ctrblk[16] = {};
			for (int i = 0; i < 8; i++) ctrblk[i] = nonce8[i];
			// ctrblk[8..15] = 0

			size_t off = 0;
			while (off < len) {
				uint8_t ks[16];
				for (int i = 0; i < 16; i++) ks[i] = ctrblk[i];
				encryptBlock(rk, ks);

				size_t n = std::min<size_t>(16, len - off);
				for (size_t i = 0; i < n; i++) buf[off + i] ^= ks[i];
				off += 16;

				// Increment big-endian 64-bit counter in bytes [8..15]
				for (int i = 15; i >= 8; i--)
					if (++ctrblk[i]) break;
			}
		}

	} // namespace vm_aes
} // namespace llvm





static void provideStubKeyProviderBodies(Module& M) {
	LLVMContext& C = M.getContext();
	Type* I8Ty = Type::getInt8Ty(C);
	Type* I64Ty = Type::getInt64Ty(C);

	for (const char* Name : { "__aes_key_a", "__aes_key_b" }) {
		Function* F = M.getFunction(Name);
		if (!F) continue;                    // not in module — fine
		if (!F->isDeclaration()) continue;   // strenc gave it a body — skip

		// Trivial body: memset(out, 0, 88); ret void;
		BasicBlock* BB = BasicBlock::Create(C, "entry", F);
		IRBuilder<> B(BB);
		B.CreateMemSet(F->getArg(0), ConstantInt::get(I8Ty, 0),
			ConstantInt::get(I64Ty, 88), MaybeAlign(1));
		B.CreateRetVoid();

		F->setLinkage(GlobalValue::PrivateLinkage);
		F->addFnAttr(Attribute::NoUnwind);
		F->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
	}
}


// ─ linkStubForVM 
// Link the strenc AES stub into the module (if not already present) and
// return the __obf_aes_ctr_decrypt function.  Uses the same dedup logic
// as strenc: if __strenc_decrypt already exists, skip re-linking.
// This is a thin wrapper that calls StrEncImpl::linkStubAndGetCTRDecrypt
// (defined in StringEncryption.cpp) via the same embedded bitcode.

//  buildBytecodeGlobal 

void VMImpl::buildBytecodeGlobal() {
	SmallVector<Constant*, 1024> Bytes;
	Bytes.reserve(E.BC.size());

	//  Layer 1: XOR-at-rest (salt ^ ip) — removed by loadBC() at each fetch
	//  Layer 2: AES-128-CTR keystream — removed by the global ctor before main()

	// Pre-compute AES keystream for compile-time encryption
	SmallVector<uint8_t, 1024> AESKeystream;
	if (EncBytecode) {
		// Generate the full keystream at compile time
		uint8_t nonce8[8];
		for (int i = 0; i < 8; i++)
			nonce8[i] = (uint8_t)((AESNonce >> (8 * i)) & 0xFF);

		AESKeystream.resize(E.BC.size(), 0);
		// XOR a zero buffer with the keystream = the keystream itself
		vm_aes::ctr(AESExpandedKey, nonce8, AESKeystream.data(), AESKeystream.size());
	}

	for (size_t I = 0; I < E.BC.size(); ++I) {
		uint8_t V = E.BC[I];
		if (EncBytecode) {
			// Layer 1: XOR-at-rest (removed by loadBC() at each fetch)
			uint8_t K = StrongBC ? ksByteCT(SaltConst, (uint32_t)I)
			                     : (uint8_t)((SaltConst ^ (uint32_t)I) & 0xFFu);
			V ^= K;

			// Layer 2: keystream (removed by ctor before main())
			V ^= AESKeystream[I];
		}
		Bytes.push_back(ConstantInt::get(I8Ty, V));
	}

	auto* ATy = ArrayType::get(I8Ty, Bytes.size());
	GVBytecode = new GlobalVariable(
		M, ATy,
		/*isConst=*/true,
		GlobalValue::PrivateLinkage,
		ConstantArray::get(ATy, Bytes),
		(F.getName() + ".vm.bytecode").str());
	GVBytecode->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);


	// Writable runtime buffer filled by the constructor when encBytecode=1.
	// The interpreter reads from this buffer (still XOR-at-rest) to avoid writing into .rdata.
	if (EncBytecode) {
		GVBytecodeRT = new GlobalVariable(
			M, ATy,
			/*isConst=*/false,
			GlobalValue::PrivateLinkage,
			Constant::getNullValue(ATy),
			(F.getName() + ".vm.bytecode.rt").str());
		GVBytecodeRT->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
	}
}


//  buildCalleeGlobal 

void VMImpl::buildCalleeGlobal() {
	if (E.CalleeTab.empty()) return;

	// Existing: emit GVCallees [C x ptr]
	SmallVector<Constant*, 8> Cs;
	for (Value* V : E.CalleeTab) Cs.push_back(cast<Constant>(V));
	auto* ATy = ArrayType::get(PtrTy, Cs.size());
	// writable when hardened (callee XOR ctor modifies in-place)
	GVCallees = new GlobalVariable(M, ATy,
		/*isConstant=*/!Cfg.hardened,
		GlobalValue::PrivateLinkage,
		ConstantArray::get(ATy, Cs), (F.getName() + ".vm.callees").str());
	GVCallees->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
	VMCallSites += (unsigned)Cs.size();

	// emit GVFTyIndices [C x i8] and populate shared FTy registry.
	UniqueFTys.clear();
	auto* SS = VMEngine::getSharedState(M, EngineId);
	SmallVector<uint8_t, 8> IdxBytes;
	IdxBytes.reserve(E.CalleeFTyTab.size());
	for (FunctionType* FTy : E.CalleeFTyTab) {
		auto [It, Inserted] = SS->FTyToIdx.try_emplace(
			FTy, (uint8_t)SS->SharedFTys.size());
		if (Inserted) SS->SharedFTys.push_back(FTy);
		IdxBytes.push_back(It->second);
	}
	UniqueFTys.assign(SS->SharedFTys.begin(), SS->SharedFTys.end());
	SmallVector<Constant*, 8> IdxConsts;
	IdxConsts.reserve(IdxBytes.size());
	for (uint8_t Idx : IdxBytes)
		IdxConsts.push_back(ConstantInt::get(I8Ty, Idx));
	auto* IATy = ArrayType::get(I8Ty, IdxConsts.size());
	GVFTyIndices = new GlobalVariable(M, IATy, /*isConstant=*/true,
		GlobalValue::PrivateLinkage,
		ConstantArray::get(IATy, IdxConsts),
		(F.getName() + ".vm.ftyidx").str());
	GVFTyIndices->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
}



//  buildEncryptCtor ─
// AES-128-CTR constructor.
//
// Architecture:
//   1. Store the 176-byte expanded key schedule as a XOR-masked global.
//   2. Store the 8-byte nonce as a global.
//   3. The .init_array constructor:
//      a) Copies the masked key to a stack buffer and XOR-unmasks it.
//      b) Copies the const bytecode into the writable runtime buffer.
//      c) Calls __obf_aes_ctr_decrypt(rt_buf, len, unmasked_key, nonce).
//   4. The runtime buffer now has Layer 2 stripped; Layer 1 (per-fetch XOR)
//      remains and is removed by loadBC() in the dispatch loop.
//
// When strenc is also active, the __obf_aes_ctr_decrypt function is already
// linked from the strenc pass — the dedup check prevents double-linking.

void VMImpl::buildEncryptCtor() {
	if (!EncBytecode) return;
	if (!GVBytecodeRT) return;
	if (E.BC.empty()) return;

	unsigned BCLen = (unsigned)E.BC.size();
	if (!BCLen) return;

	// Link the AES stub (shared with strenc)
	Function* CTRDecryptFn = M.getFunction("__obf_aes_ctr_decrypt");
	if (!CTRDecryptFn) {
		// If strenc already linked the stub, both functions are present.
		// If not, link from the shared embedded bitcode.
		if (!M.getFunction("__aes_decrypt")) {
			if (llvm::obf::StubBitcodeSize > 0) {
				MemoryBufferRef MBR(
					StringRef(reinterpret_cast<const char*>(llvm::obf::StubBitcode),
						llvm::obf::StubBitcodeSize),
					"aes_stub.bc");
				auto StubOrErr = parseBitcodeFile(MBR, Ctx);
				if (StubOrErr) {
					auto StubM = std::move(*StubOrErr);
					StubM->setDataLayout(M.getDataLayout());
					StubM->setTargetTriple(M.getTargetTriple());
					// aes_stub.c is fixed-width (uint8_t/uint32_t) only, so the
					// DL/triple override above is fully safe -- but leftover
					// module-flag metadata baked in from whatever host triple
					// built the embedded bitcode (e.g. wchar_size) can still
					// conflict with M's own flags and make linkModules() fail
					// on cross-target builds. Drop it; the stub needs none.
					if (auto* MDFlags = StubM->getModuleFlagsMetadata())
						MDFlags->eraseFromParent();
					if (Linker::linkModules(M, std::move(StubM), 0)) {
						errs() << "[vm] linkModules failed for AES stub\n";
					}
				}
				else {
					handleAllErrors(StubOrErr.takeError(),
						[](const ErrorInfoBase& EI) {
							errs() << "[vm] AES stub parse failed: "
								<< EI.message() << "\n";
						});
				}
			}
			else {
				errs() << "[vm] embedded AES stub bitcode is empty — "
					<< "did the CMake strenc_stub build rule run?\n";
			}
		}
		CTRDecryptFn = M.getFunction("__obf_aes_ctr_decrypt");
	}

	if (!CTRDecryptFn) {
		errs() << "[vm] ERROR: __obf_aes_ctr_decrypt not available "
			<< "(embedded AES stub missing/unlinkable); bytecode ctor skipped\n";
		return;
	}


	// Resolve dangling __strenc_key_a / __strenc_key_b declarations
	provideStubKeyProviderBodies(M);

	auto* RKTy = ArrayType::get(I8Ty, 176);

	// Masked expanded-key / nonce / mask globals: when lazyDecrypt is active,
	// buildWrapper() already created these (it runs before this ctor and
	// needs them to unmask the key into its own per-call stack context) —
	// reuse them instead of emitting duplicates. Otherwise create as before.
	if (!GVAESExpandedKey) {
		SmallVector<Constant*, 176> MaskedRK;
		for (int i = 0; i < 176; i++)
			MaskedRK.push_back(ConstantInt::get(I8Ty, AESExpandedKey[i] ^ AESRKMask[i]));

		// Writable when bindAntiDebug: buildAntiDebugKeyBindCtor() XORs the
		// first 16 bytes in place at startup. Constant otherwise.
		GVAESExpandedKey = new GlobalVariable(
			M, RKTy, /*isConst=*/!BindAntiDebug, GlobalValue::PrivateLinkage,
			ConstantArray::get(RKTy, MaskedRK),
			(F.getName() + ".vm.aes.rk").str());
		GVAESExpandedKey->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
		GVAESExpandedKey->setAlignment(Align(16));

		// Nonce global (8 bytes, little-endian)
		SmallVector<Constant*, 8> NonceBytes;
		for (int i = 0; i < 8; i++)
			NonceBytes.push_back(ConstantInt::get(I8Ty, (AESNonce >> (8 * i)) & 0xFF));
		auto* NonceTy = ArrayType::get(I8Ty, 8);
		GVAESNonce = new GlobalVariable(
			M, NonceTy, /*isConst=*/true, GlobalValue::PrivateLinkage,
			ConstantArray::get(NonceTy, NonceBytes),
			(F.getName() + ".vm.aes.nonce").str());
		GVAESNonce->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

		// Mask global (used to unmask the expanded key on the stack)
		SmallVector<Constant*, 176> MaskConsts;
		for (int i = 0; i < 176; i++)
			MaskConsts.push_back(ConstantInt::get(I8Ty, AESRKMask[i]));
		GVAESRKMask = new GlobalVariable(
			M, RKTy, /*isConst=*/true, GlobalValue::PrivateLinkage,
			ConstantArray::get(RKTy, MaskConsts),
			(F.getName() + ".vm.aes.rkmask").str());
		GVAESRKMask->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
	}

	// Build the .init_array constructor 
	std::string FnName = (F.getName() + ".vm.ctor").str();
	auto* FTy = FunctionType::get(Type::getVoidTy(Ctx), false);
	auto* CtorFn = Function::Create(FTy, GlobalValue::InternalLinkage, FnName, M);
	CtorFn->addFnAttr(Attribute::NoUnwind);

	BasicBlock* BB = BasicBlock::Create(Ctx, "vm.ctor.aes", CtorFn);
	IRBuilder<> B(BB);

	// a) Unmask the expanded key on the stack
	auto* RKAlloca = B.CreateAlloca(RKTy, nullptr, "vm.ctor.rk");
	RKAlloca->setAlignment(Align(16));
	// memcpy masked key to stack
	B.CreateMemCpy(RKAlloca, Align(16), GVAESExpandedKey, Align(16),
		ConstantInt::get(I64Ty, 176));
	// XOR with mask: rk[i] ^= mask[i] for i in 0..175
	// Emit as a simple loop
	BasicBlock* LoopHdr = BasicBlock::Create(Ctx, "vm.ctor.unmask.hdr", CtorFn);
	BasicBlock* LoopBody = BasicBlock::Create(Ctx, "vm.ctor.unmask.body", CtorFn);
	BasicBlock* AfterLoop = BasicBlock::Create(Ctx, "vm.ctor.unmask.done", CtorFn);

	B.CreateBr(LoopHdr);
	// Loop header
	IRBuilder<> LH(LoopHdr);
	PHINode* Idx = LH.CreatePHI(I32Ty, 2, "vm.ctor.idx");
	Idx->addIncoming(LH.getInt32(0), BB);
	LH.CreateCondBr(LH.CreateICmpULT(Idx, LH.getInt32(176)), LoopBody, AfterLoop);

	// Loop body: rk[i] ^= mask[i]
	IRBuilder<> LB(LoopBody);
	Value* Idx64 = LB.CreateZExt(Idx, I64Ty);
	Value* RKPtr = LB.CreateGEP(I8Ty, RKAlloca, Idx64, "vm.ctor.rkp");
	Value* MkPtr = LB.CreateGEP(I8Ty, GVAESRKMask, Idx64, "vm.ctor.mkp");
	Value* RKByte = LB.CreateLoad(I8Ty, RKPtr);
	Value* MkByte = LB.CreateLoad(I8Ty, MkPtr);
	LB.CreateStore(LB.CreateXor(RKByte, MkByte), RKPtr);
	Value* NextIdx = LB.CreateAdd(Idx, LB.getInt32(1));
	Idx->addIncoming(NextIdx, LoopBody);
	LB.CreateBr(LoopHdr);

	// b) memcpy const bytecode → writable runtime buffer
	IRBuilder<> AB(AfterLoop);
	AB.CreateMemCpy(GVBytecodeRT, Align(16), GVBytecode, Align(1),
		ConstantInt::get(I64Ty, BCLen));

	// c) Call __obf_aes_ctr_decrypt(rt_buf, len, rk_stack, nonce_ptr) — strips
	// the AES layer from the whole runtime buffer up front. Skipped when
	// LazyDecrypt: the buffer stays ciphertext and the engine's per-byte
	// fetch (loadBC/loadBCDyn) removes AES one 16-byte block at a time.
	if (!LazyDecrypt) {
		Value* RTBufPtr = AB.CreateBitCast(GVBytecodeRT, PointerType::getUnqual(Ctx));
		Value* RKPtr2 = AB.CreateBitCast(RKAlloca, PointerType::getUnqual(Ctx));
		Value* NoncePtr = AB.CreateBitCast(GVAESNonce, PointerType::getUnqual(Ctx));
		AB.CreateCall(CTRDecryptFn, {
			RTBufPtr,
			ConstantInt::get(I32Ty, BCLen),
			RKPtr2,
			NoncePtr
			});
	}
	AB.CreateRetVoid();

	appendToGlobalCtors(M, CtorFn, 65535, nullptr);

	if (ObfVerbose)
		errs() << "[vm] AES-CTR ctor built for '" << F.getName()
		<< "' [" << BCLen << "B, nonce=0x"
		<< Twine::utohexstr(AESNonce) << "]\n";
}
