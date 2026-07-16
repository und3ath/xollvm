#include "llvm/Transforms/Obfuscator/StringEncryption.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/OpaqueUtils.h"
#include "llvm/Transforms/Obfuscator/MBAUtils.h"
#include "llvm/Transforms/Obfuscator/PassCtx.h"
#include "llvm/Transforms/Obfuscator/Utils.h"

#include "llvm/Transforms/Obfuscator/AESStubBitcode.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/MapVector.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"


#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

using namespace llvm;

#define DEBUG_TYPE "strenc"

STATISTIC(EncryptedStrings, "Number of AES-encrypted strings");
STATISTIC(DecryptCallsInserted, "Number of __strenc_decrypt calls inserted");
STATISTIC(StubLinked, "Times AES stub module was linked");



namespace {

    // ============================================================================
    // Compile-time AES-128 engine
    // Used only inside the pass to encrypt strings offline.
    // None of this code appears in the emitted binary.
    // ============================================================================

    // AES forward S-box (standard FIPS-197)
    static constexpr uint8_t AES_SBOX[256] = {
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

    // AES round constants (rcon[i] = x^(i-1) in GF(2^8), 1-indexed)
    static constexpr uint8_t AES_RCON[11] = {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    // Expand a 16-byte AES-128 key into 176 bytes of round-key schedule.
    static void aes_key_expand(const uint8_t key[16], uint8_t rk[176]) {
        // Copy the original key as round 0
        for (int i = 0; i < 16; i++) rk[i] = key[i];

        for (int i = 4; i < 44; i++) {   // 44 words of 4 bytes each
            uint8_t temp[4];
            for (int j = 0; j < 4; j++) temp[j] = rk[(i - 1) * 4 + j];

            if (i % 4 == 0) {
                // RotWord
                uint8_t t = temp[0];
                temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
                // SubWord
                for (int j = 0; j < 4; j++) temp[j] = AES_SBOX[temp[j]];
                // XOR with Rcon
                temp[0] ^= AES_RCON[i / 4];
            }

            for (int j = 0; j < 4; j++)
                rk[i * 4 + j] = rk[(i - 4) * 4 + j] ^ temp[j];
        }
    }

    // GF(2^8) × 2
    static inline uint8_t xtime(uint8_t x) {
        return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1bu));
    }

    // AES ShiftRows (column-major: s[col*4+row])
    static void aes_shift_rows(uint8_t s[16]) {
        uint8_t t;
        t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
        t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
    }

    // AES MixColumns
    static void aes_mix_columns(uint8_t s[16]) {
        for (int c = 0; c < 4; c++) {
            uint8_t a = s[c * 4], b = s[c * 4 + 1], cc = s[c * 4 + 2], d = s[c * 4 + 3];
            uint8_t tmp = a ^ b ^ cc ^ d;
            s[c * 4 + 0] ^= tmp ^ xtime((uint8_t)(a ^ b));
            s[c * 4 + 1] ^= tmp ^ xtime((uint8_t)(b ^ cc));
            s[c * 4 + 2] ^= tmp ^ xtime((uint8_t)(cc ^ d));
            s[c * 4 + 3] ^= tmp ^ xtime((uint8_t)(d ^ a));
        }
    }

    // AES-128 encrypt one block (offline, in the pass, not in emitted code)
    static void aes128_encrypt_block(const uint8_t rk[176], uint8_t blk[16]) {
        uint8_t s[16];
        for (int i = 0; i < 16; i++) s[i] = blk[i] ^ rk[i];
        for (int r = 1; r <= 9; r++) {
            for (int i = 0; i < 16; i++) s[i] = AES_SBOX[s[i]];
            aes_shift_rows(s);
            aes_mix_columns(s);
            for (int i = 0; i < 16; i++) s[i] ^= rk[r * 16 + i];
        }
        for (int i = 0; i < 16; i++) s[i] = AES_SBOX[s[i]];
        aes_shift_rows(s);
        for (int i = 0; i < 16; i++) blk[i] = s[i] ^ rk[160 + i];
    }

    // AES-128-CTR encrypt/decrypt (symmetric) — used at pass time to produce
    // ciphertext that will be embedded as constant globals.
    static void aes128_ctr(const uint8_t rk[176],
        const uint8_t nonce8[8],
        uint8_t* buf, size_t len) {
        uint8_t ctr[16] = {};
        for (int i = 0; i < 8; i++) ctr[i] = nonce8[i];
        // ctr[8..15] = 0 (counter, big-endian)

        size_t off = 0;
        while (off < len) {
            uint8_t ks[16];
            for (int i = 0; i < 16; i++) ks[i] = ctr[i];
            aes128_encrypt_block(rk, ks);

            size_t n = std::min<size_t>(16, len - off);
            for (size_t i = 0; i < n; i++) buf[off + i] ^= ks[i];
            off += 16;

            // Increment big-endian 64-bit counter in bytes [8..15]
            for (int i = 15; i >= 8; i--)
                if (++ctr[i]) break;
        }
    }

    // ============================================================================
    // Compile-time ChaCha20 engine (RFC 8439, tableless ARX)
    // Used only inside the pass to encrypt strings offline. MUST produce
    // byte-for-byte identical keystream to __strenc_chacha_decrypt in
    // aes_stub.c — same constants, word layout, counter/nonce positions,
    // rotation amounts, and round count. If these disagree, runtime decrypt
    // yields garbage.
    // ============================================================================

    static inline uint32_t chacha_rotl32(uint32_t x, int n) {
        return (uint32_t)((x << n) | (x >> (32 - n)));
    }

    static inline uint32_t chacha_load32_le(const uint8_t* p) {
        return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
            ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    }

    static inline void chacha_store32_le(uint8_t* p, uint32_t v) {
        p[0] = (uint8_t)(v);
        p[1] = (uint8_t)(v >> 8);
        p[2] = (uint8_t)(v >> 16);
        p[3] = (uint8_t)(v >> 24);
    }

    static inline void chacha_qr(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = chacha_rotl32(d, 16);
        c += d; b ^= c; b = chacha_rotl32(b, 12);
        a += b; d ^= a; d = chacha_rotl32(d, 8);
        c += d; b ^= c; b = chacha_rotl32(b, 7);
    }

    // Produce one 64-byte ChaCha20 keystream block from the given state.
    static void chacha20_block(const uint32_t in[16], uint8_t out[64]) {
        uint32_t x[16];
        for (int i = 0; i < 16; i++) x[i] = in[i];

        for (int i = 0; i < 10; i++) {
            // Column rounds
            chacha_qr(x[0], x[4], x[8], x[12]);
            chacha_qr(x[1], x[5], x[9], x[13]);
            chacha_qr(x[2], x[6], x[10], x[14]);
            chacha_qr(x[3], x[7], x[11], x[15]);
            // Diagonal rounds
            chacha_qr(x[0], x[5], x[10], x[15]);
            chacha_qr(x[1], x[6], x[11], x[12]);
            chacha_qr(x[2], x[7], x[8], x[13]);
            chacha_qr(x[3], x[4], x[9], x[14]);
        }

        for (int i = 0; i < 16; i++)
            chacha_store32_le(out + 4 * i, x[i] + in[i]);
    }

    // ChaCha20 keystream XOR (symmetric encrypt/decrypt) — used at pass time
    // to produce ciphertext that will be embedded as constant globals.
    // key    : 32-byte key.
    // nonce  : 12-byte nonce.
    // counter: initial 32-bit block counter (call sites use 0).
    static void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
        uint32_t counter, uint8_t* buf, size_t len) {
        uint32_t state[16];
        state[0] = 0x61707865u;
        state[1] = 0x3320646eu;
        state[2] = 0x79622d32u;
        state[3] = 0x6b206574u;
        for (int i = 0; i < 8; i++)
            state[4 + i] = chacha_load32_le(key + 4 * i);
        state[12] = counter;
        for (int i = 0; i < 3; i++)
            state[13 + i] = chacha_load32_le(nonce + 4 * i);

        size_t off = 0;
        while (off < len) {
            uint8_t ks[64];
            chacha20_block(state, ks);

            size_t n = std::min<size_t>(64, len - off);
            for (size_t i = 0; i < n; i++) buf[off + i] ^= ks[i];
            off += 64;

            state[12]++;   // increment block counter
        }
    }

    // FNV-64 nonce derivation: unique per (string_index, content)
    static uint64_t fnv64_nonce(size_t idx, StringRef content) {
        constexpr uint64_t FNV_OFFSET = 14695981039346656037ULL;
        constexpr uint64_t FNV_PRIME = 1099511628211ULL;
        uint64_t h = FNV_OFFSET;
        // Mix the string index
        for (int i = 0; i < 8; i++) {
            h ^= (uint8_t)((idx >> (8 * i)) & 0xFF);
            h *= FNV_PRIME;
        }
        // Mix the content bytes
        for (unsigned char c : content) {
            h ^= (uint8_t)c;
            h *= FNV_PRIME;
        }
        return h;
    }

    // ============================================================================
    // StrEncCtx — per-pass context holding config + key material
    // ============================================================================
    struct StrEncCtx : llvm::obf::ModPassCtx {
        StringEncryptionConfig Cfg;
        llvm::obf::Rng         KeyRng;

        // AES-128 compile-time key material
        uint8_t MasterKey[16] = {};
        uint8_t ExpandedKeys[176] = {};

        // ChaCha20 compile-time key material
        uint8_t ChaChaKey[32] = {};
        // Phase B: pass-time-known mask words used to obfuscate the key global
        // (see @.strenc.ck below — it stores key XOR mask, never the flat key).
        uint32_t MaskWords[8] = {};

        // IR objects created once, reused for all strings
        GlobalVariable* KeyDataGV = nullptr;   // @.strenc.kd  — data half (bytes 0–87)
        Function* KeyCodeFn = nullptr;   // __strenc_key_b — code half (bytes 88–175)
        Function* KeyDataFn = nullptr;   // __strenc_key_a — wrapper memcpy
        Function* DecryptFn = nullptr;   // __strenc_decrypt (from linked stub)
        GlobalVariable* ChaChaKeyGV = nullptr;   // @.strenc.ck — shared 32-byte ChaCha key

        StrEncCtx(Module& M, ModuleAnalysisManager& MAM)
            : ModPassCtx(M, MAM, "strenc"),
            KeyRng(R.fork("keys")) {

            // Merge StringEncryptionConfig across all annotated functions.
            //
            // useAES/keySplit merge with OR semantics (D1(a) module-wide model):
            // the module runs the AES path iff *any* enabled function requests
            // AES, and only falls back to the legacy XOR path when every enabled
            // function explicitly opted out (aes=0). This is deliberate — the AES
            // key schedule and shared decrypt stub are set up once per module
            // (see below), so the cipher choice cannot be soundly varied
            // per-function. Init to false so a per-function `strenc(aes=0)` is
            // honored instead of silently ignored (was a bug: Acc.useAES started
            // true and was only ever OR'd true, so aes=0 never took effect).
            bool Any = false;
            StringEncryptionConfig Acc;
            Acc.enable = false;
            Acc.minLength = 0;
            Acc.useAES = false;
            Acc.keySplit = false;
            Acc.useChaCha = false;

            for (auto& It : Ann.PerFunction) {
                auto PC = It.second.getPassConfig("strenc");
                if (!PC) continue;
                auto Local = StringEncryptionConfig::fromPassConfig(*PC);
                if (!Local.validate() || !Local.enable) continue;
                Any = true;
                Acc.enable = true;
                Acc.minLength = std::max(Acc.minLength, Local.minLength);
                // Any function requesting AES / keySplit turns it on module-wide.
                if (Local.useAES)    Acc.useAES = true;
                if (Local.keySplit)  Acc.keySplit = true;
                if (Local.useChaCha) Acc.useChaCha = true;
            }

            // ── NEW: collect strenc_stub config ──────────────────────────────────────
            for (auto& It : Ann.PerFunction) {
                auto PC = It.second.getPassConfig("aes_stub");
                if (!PC)
                    PC = It.second.getPassConfig("strenc_stub"); // legacy alias
                if (!PC) continue;
                Acc.stubPasses = AnnotationParser::parseAnnotationString(PC->rawInner);
                break;  // module-wide: first occurrence wins
            }

            Cfg = Acc;
            if (!Any) { Cfg.enable = false; return; }

            if (Cfg.useChaCha) {
                // ── Generate compile-time ChaCha20 32-byte key from RNG ──
                // Same byte-splat style as the AES MasterKey loop below.
                for (int i = 0; i < 8; i++) {
                    uint32_t W = KeyRng.u32();
                    ChaChaKey[4 * i + 0] = (W >> 0) & 0xFF;
                    ChaChaKey[4 * i + 1] = (W >> 8) & 0xFF;
                    ChaChaKey[4 * i + 2] = (W >> 16) & 0xFF;
                    ChaChaKey[4 * i + 3] = (W >> 24) & 0xFF;
                }
                // Phase B: mask words used to obfuscate the key in @.strenc.ck.
                // Pass-time-known; reconstructed at runtime via opaque constants.
                for (int w = 0; w < 8; w++)
                    MaskWords[w] = KeyRng.u32();
                return;   // skip AES key expansion — chacha path doesn't need it
            }

            if (!Cfg.useAES) return;   // legacy XOR path — key gen not needed

            // ── Generate compile-time AES master key from RNG ──
            for (int i = 0; i < 4; i++) {
                uint32_t W = KeyRng.u32();
                MasterKey[4 * i + 0] = (W >> 0) & 0xFF;
                MasterKey[4 * i + 1] = (W >> 8) & 0xFF;
                MasterKey[4 * i + 2] = (W >> 16) & 0xFF;
                MasterKey[4 * i + 3] = (W >> 24) & 0xFF;
            }
            aes_key_expand(MasterKey, ExpandedKeys);
        }
    };

    // ============================================================================
    // StrEncImpl — stateless helper methods
    // ============================================================================
    struct StrEncImpl {


        // —— Shared stub linking (used by both strenc and vmpass) ——————————
        
        /// Link the embedded AES stub bitcode into M if not already present.
        /// This is safe to call from multiple passes — deduplication is built-in.
        /// Returns the __obf_aes_ctr_decrypt function, or nullptr on failure.
        static Function * linkStubAndGetCTRDecrypt(Module & M) {
             // Fast path: if the stub is already linked (by strenc or a prior
             // vmpass invocation), just return the shared decrypt function.
            if (Function* Existing = M.getFunction("__obf_aes_ctr_decrypt"))
                return Existing;
            
            // Link the full stub — this also brings in __strenc_decrypt, but
            // it will only be used if strenc actually creates call sites to it.
            // Unused functions are eliminated by the linker.
            Function * DecFn = linkStub(M);
            if (!DecFn) return nullptr;
            
            return M.getFunction("__obf_aes_ctr_decrypt");
            
        }
        

        // ── Stub linking ─────────────────────────────────────────────────────────

        /// Parse the embedded AES stub bitcode and link it into M.
        /// Returns the __strenc_decrypt function (now a member of M), or nullptr.
        static Function* linkStub(Module& M);

        /// After linking, make all stub-private functions truly private + mark
        /// them to prevent self-re-encryption and to let the obfuscation driver
        /// pick them up naturally.
        static void hardenStubFunctions(Module& M,
            const ObfuscationConfig& StubPasses,
            ObfuscationAnnotationCache& Cache);

        // ── Key-provider IR generation ────────────────────────────────────────────

        /// Create @.strenc.kd global holding bytes 0–87 of the expanded key.
        static GlobalVariable* createKeyDataGlobal(Module& M,
            const uint8_t rk[176]);

        /// Create __strenc_key_a() — a private function that memcpy's @.strenc.kd
        /// into the caller's buffer (88 bytes).
        static Function* createKeyDataFn(Module& M, GlobalVariable* KDG);

        /// Create __strenc_key_b() — a private function with 88 individual stores
        /// of immediate byte constants (bytes 88–175 of the expanded key).
        /// These bytes live as instruction operands in the code segment, not data.
        static Function* createKeyCodeFn(Module& M, const uint8_t rk[176]);

        // ── Per-string helpers ────────────────────────────────────────────────────

        /// True if GV should be encrypted (is a non-empty, eligible string).
        static bool shouldEncrypt(GlobalVariable& GV, int minLength);

        /// Create a private constant global for the ciphertext bytes.
        static GlobalVariable* createCiphertextGlobal(Module& M,
            const std::string& cipher,
            unsigned idx);

        /// Create a private constant global holding the 8-byte nonce.
        static GlobalVariable* createNonceGlobal(Module& M,
            uint64_t nonce,
            unsigned idx);

        /// Create a private constant global holding a 12-byte ChaCha20 nonce.
        /// Sibling of createNonceGlobal, mirrored for the 12-byte layout.
        static GlobalVariable* createNonce12Global(Module& M,
            const uint8_t nonce12[12],
            unsigned idx);

        // ── Opaque-pointer GEP helper ─────────────────────────────────────────────
        static Value* gepI8(IRBuilder<>& B, Type* ArrTy, Value* ArrPtr);

        // ── ConstantExpr materialisation (same as before) ────────────────────────
        static void materializeConstExprUsers(GlobalVariable* GV);

        // ── Top-level entry ───────────────────────────────────────────────────────
        static bool encryptStrings(Module& M, StrEncCtx& Ctx);

        // ── ChaCha20 path (used when useChaCha=true) ──────────────────────────────
        static bool encryptStringsChaCha(Module& M, StrEncCtx& Ctx);

        // ── Legacy XOR path (fallback when useAES=false) ──────────────────────────
        static bool encryptStringsXOR(Module& M, StrEncCtx& Ctx);
    };

    // ── StrEncImpl::linkStub ─────────────────────────────────────────────────────

    Function* StrEncImpl::linkStub(Module& M) {
        if (llvm::obf::StubBitcodeSize == 0) {
            errs() << "strenc: embedded stub bitcode is empty — "
                "did the CMake build rule run?\n";
            return nullptr;
        }

        // If the decrypt function is already present (e.g., two TUs in one LTO
        // module), skip re-linking.
        if (Function* Existing = M.getFunction("__aes_decrypt"))
            return Existing;

        // Parse the embedded bitcode into a fresh Module.
        MemoryBufferRef MBR(
            StringRef(reinterpret_cast<const char*>(llvm::obf::StubBitcode), llvm::obf::StubBitcodeSize),
            "aes_stub.bc");

        LLVMContext& Ctx = M.getContext();
        auto StubOrErr = parseBitcodeFile(MBR, Ctx);
        if (!StubOrErr) {
            handleAllErrors(StubOrErr.takeError(), [](const ErrorInfoBase& E) {
                errs() << "strenc: failed to parse stub bitcode: "
                    << E.message() << "\n";
                });
            return nullptr;
        }

        std::unique_ptr<Module> StubM = std::move(*StubOrErr);

        // Set the data layout and target triple to match the target module so the
        // linker doesn't complain about mismatches.
        StubM->setDataLayout(M.getDataLayout());
        StubM->setTargetTriple(M.getTargetTriple());

        // Link — we only need definitions that are referenced.
        // Linker::Flags::LinkOnlyNeeded avoids pulling in unreferenced symbols.
        if (Linker::linkModules(M, std::move(StubM), 0)) {
            errs() << "strenc: linkModules failed\n";
            return nullptr;
        }

        ++StubLinked;
        return M.getFunction("__aes_decrypt");
    }

    // ── StrEncImpl::hardenStubFunctions ──────────────────────────────────────────

    void StrEncImpl::hardenStubFunctions(Module& M,
        const ObfuscationConfig& StubPasses,
        ObfuscationAnnotationCache& Cache) {
        // All stub functions are prefixed with "__aes_", "__obf_aes_", or
        // "__strenc_" (e.g. the ChaCha20 path's __strenc_chacha_decrypt).
        // After linking they may still have ExternalLinkage from their C
        // definition.  Make them private so:
        //   (a) the OS linker strips them from exports,
        //   (b) they are eligible for dead-code elimination,
        //   (c) they get individual obfuscation seeds from the function driver.
        for (Function& F : M) {
            if (!F.getName().starts_with("__aes_") &&
                !F.getName().starts_with("__obf_aes_") &&
                !F.getName().starts_with("__strenc_")) continue;
            if (F.isDeclaration()) continue;

            F.setLinkage(GlobalValue::PrivateLinkage);
            F.setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
            F.removeFnAttr(Attribute::OptimizeNone);
            F.removeFnAttr(Attribute::NoInline);

            if (!StubPasses.passes.empty() &&
                Cache.PerFunction.find(&F) == Cache.PerFunction.end()) {
                Cache.PerFunction[&F] = StubPasses;
            }
        }

        // Mark all strenc-private globals the same way.
        for (GlobalVariable& GV : M.globals()) {
            StringRef Sec = GV.hasSection() ? GV.getSection() : StringRef();
            if (Sec.starts_with(".strenc"))
                GV.setVisibility(GlobalValue::HiddenVisibility);
        }
    }

    // ── StrEncImpl::createKeyDataGlobal ──────────────────────────────────────────

    GlobalVariable* StrEncImpl::createKeyDataGlobal(Module& M,
        const uint8_t rk[176]) {
        LLVMContext& C = M.getContext();
        ArrayType* Ty = ArrayType::get(Type::getInt8Ty(C), 88);

        std::vector<Constant*> Bytes;
        Bytes.reserve(88);
        for (int i = 0; i < 88; i++)
            Bytes.push_back(ConstantInt::get(Type::getInt8Ty(C), rk[i]));

        GlobalVariable* GV = new GlobalVariable(
            M, Ty, /*isConstant=*/true,
            GlobalValue::PrivateLinkage,
            ConstantArray::get(Ty, Bytes),
            ".strenc.kd");

        GV->setSection(".strenc.kd");
        GV->setAlignment(Align(16));
        GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
        return GV;
    }

    // ── StrEncImpl::createKeyDataFn ───────────────────────────────────────────────
    // __strenc_key_a(ptr out)  →  memcpy(out, @.strenc.kd, 88)

    Function* StrEncImpl::createKeyDataFn(Module& M, GlobalVariable* KDG) {
        LLVMContext& C = M.getContext();
        Type* VoidTy = Type::getVoidTy(C);
        Type* PtrTy = PointerType::getUnqual(C);
        Type* I64Ty = Type::getInt64Ty(C);
        Type* I32Ty = Type::getInt32Ty(C);
        Type* I8Ty = Type::getInt8Ty(C);

        FunctionType* FT = FunctionType::get(VoidTy, { PtrTy }, false);

        // Get the existing declaration (inserted by stub linkage) or create fresh.
        Function* F = M.getFunction("__aes_key_a");
        if (!F)
            F = Function::Create(FT, GlobalValue::PrivateLinkage, "__aes_key_a", M);
        else if (!F->isDeclaration())
            return F;  // already fully defined, nothing to do

        // Promote: set linkage/attrs on whatever we got
        F->setLinkage(GlobalValue::PrivateLinkage);
        F->addFnAttr(Attribute::NoUnwind);
        F->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

        Argument* OutArg = F->getArg(0);
        OutArg->setName("out");

        BasicBlock* BB = BasicBlock::Create(C, "entry", F);
        IRBuilder<> B(BB);

        ArrayType* ArrTy = ArrayType::get(I8Ty, 88);
        Value* Z = ConstantInt::get(I32Ty, 0);
        Value* Src = B.CreateInBoundsGEP(ArrTy, KDG, { Z, Z }, "kd.ptr");
        B.CreateMemCpy(OutArg, Align(1), Src, Align(16),
            ConstantInt::get(I64Ty, 88));
        B.CreateRetVoid();

        return F;
    }

    Function* StrEncImpl::createKeyCodeFn(Module& M, const uint8_t rk[176]) {
        LLVMContext& C = M.getContext();
        Type* VoidTy = Type::getVoidTy(C);
        Type* PtrTy = PointerType::getUnqual(C);
        Type* I8Ty = Type::getInt8Ty(C);
        Type* I32Ty = Type::getInt32Ty(C);

        FunctionType* FT = FunctionType::get(VoidTy, { PtrTy }, false);

        Function* F = M.getFunction("__aes_key_b");
        if (!F)
            F = Function::Create(FT, GlobalValue::PrivateLinkage, "__aes_key_b", M);
        else if (!F->isDeclaration())
            return F;

        F->setLinkage(GlobalValue::PrivateLinkage);
        F->addFnAttr(Attribute::NoUnwind);
        F->setSection(".strenc.kt");
        F->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

        Argument* OutArg = F->getArg(0);
        OutArg->setName("out");

        BasicBlock* BB = BasicBlock::Create(C, "entry", F);
        IRBuilder<> B(BB);

        for (int i = 0; i < 88; i++) {
            Value* Idx = ConstantInt::get(I32Ty, i);
            Value* Ptr = B.CreateGEP(I8Ty, OutArg, Idx);
            B.CreateStore(ConstantInt::get(I8Ty, rk[88 + i]), Ptr);
        }
        B.CreateRetVoid();

        return F;
    }

    // ── StrEncImpl helpers ────────────────────────────────────────────────────────

    bool StrEncImpl::shouldEncrypt(GlobalVariable& GV, int minLength) {
        if (!GV.hasInitializer() || !GV.isConstant()) return false;
        auto* CDA = dyn_cast<ConstantDataArray>(GV.getInitializer());
        if (!CDA || !CDA->isCString()) return false;

        // Skip stub-owned globals (section starts with ".strenc")
        if (GV.hasSection() && GV.getSection().starts_with(".strenc"))
            return false;

        StringRef S = CDA->getAsCString();
        if ((int)S.size() < minLength) return false;

        // Skip printf-style format strings
        if (S.contains('%')) return false;

        return true;
    }

    GlobalVariable* StrEncImpl::createCiphertextGlobal(Module& M,
        const std::string& cipher,
        unsigned idx) {
        LLVMContext& C = M.getContext();
        size_t N = cipher.size() + 1;  // include null terminator byte
        ArrayType* Ty = ArrayType::get(Type::getInt8Ty(C), N);

        std::vector<Constant*> Bytes;
        Bytes.reserve(N);
        for (unsigned char c : cipher)
            Bytes.push_back(ConstantInt::get(Type::getInt8Ty(C), c));
        Bytes.push_back(ConstantInt::get(Type::getInt8Ty(C), 0)); // null terminator

        std::string Name = ".strenc.ct." + std::to_string(idx);
        GlobalVariable* GV = new GlobalVariable(
            M, Ty, /*isConstant=*/true,
            GlobalValue::PrivateLinkage,
            ConstantArray::get(Ty, Bytes),
            Name);

        GV->setSection(".strenc.ct");
        GV->setAlignment(Align(1));
        GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
        return GV;
    }

    GlobalVariable* StrEncImpl::createNonceGlobal(Module& M,
        uint64_t nonce,
        unsigned idx) {
        LLVMContext& C = M.getContext();
        ArrayType* Ty = ArrayType::get(Type::getInt8Ty(C), 8);

        std::vector<Constant*> Bytes;
        Bytes.reserve(8);
        for (int i = 0; i < 8; i++)
            Bytes.push_back(ConstantInt::get(Type::getInt8Ty(C),
                (uint8_t)((nonce >> (8 * i)) & 0xFF)));

        std::string Name = ".strenc.nonce." + std::to_string(idx);
        GlobalVariable* GV = new GlobalVariable(
            M, Ty, /*isConstant=*/true,
            GlobalValue::PrivateLinkage,
            ConstantArray::get(Ty, Bytes),
            Name);

        GV->setSection(".strenc.n");
        GV->setAlignment(Align(8));
        GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
        return GV;
    }

    GlobalVariable* StrEncImpl::createNonce12Global(Module& M,
        const uint8_t nonce12[12],
        unsigned idx) {
        LLVMContext& C = M.getContext();
        ArrayType* Ty = ArrayType::get(Type::getInt8Ty(C), 12);

        std::vector<Constant*> Bytes;
        Bytes.reserve(12);
        for (int i = 0; i < 12; i++)
            Bytes.push_back(ConstantInt::get(Type::getInt8Ty(C), nonce12[i]));

        std::string Name = ".strenc.nc12." + std::to_string(idx);
        GlobalVariable* GV = new GlobalVariable(
            M, Ty, /*isConstant=*/true,
            GlobalValue::PrivateLinkage,
            ConstantArray::get(Ty, Bytes),
            Name);

        GV->setSection(".strenc.n");
        GV->setAlignment(Align(8));
        GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
        return GV;
    }

    Value* StrEncImpl::gepI8(IRBuilder<>& B, Type* ArrTy, Value* ArrPtr) {
        Value* Z = ConstantInt::get(Type::getInt32Ty(B.getContext()), 0);
        return B.CreateInBoundsGEP(ArrTy, ArrPtr, { Z, Z }, "strenc.gep");
    }

    void StrEncImpl::materializeConstExprUsers(GlobalVariable* GV) {
        SmallVector<ConstantExpr*, 16> Work;
        for (User* U : GV->users())
            if (auto* CE = dyn_cast<ConstantExpr>(U))
                Work.push_back(CE);

        while (!Work.empty()) {
            ConstantExpr* CE = Work.pop_back_val();
            SmallVector<Use*, 16> Uses;
            for (Use& U : CE->uses()) Uses.push_back(&U);
            for (Use* UPtr : Uses) {
                auto* I = dyn_cast<Instruction>(UPtr->getUser());
                if (!I) continue;
                Instruction* NI = CE->getAsInstruction();
                NI->insertBefore(I);
                NI->setDebugLoc(I->getDebugLoc());
                UPtr->set(NI);
            }
        }
    }

    // StrEncImpl::encryptStrings 

    bool StrEncImpl::encryptStrings(Module& M, StrEncCtx& Ctx) {
        //  link the AES stub
        Function* DecryptFn = linkStub(M);
        if (!DecryptFn) {
            errs() << "strenc: AES stub link failed — skipping encryption\n";
            return false;
        }
         // Get a mutable reference to the annotation cache directly from the
        // MAM.  Do NOT use const_cast on Ctx.Ann — the function driver reads
        // the cache via getCachedResult on the MAM proxy, and const_cast on a
        // captured const& may not propagate reliably through NPM's analysis
        // caching layers.
        auto& MutableCache =
            Ctx.MAM.getResult<ObfuscationAnnotationAnalysis>(M);
        hardenStubFunctions(M, Ctx.Cfg.stubPasses, MutableCache);

        // create key-provider IR functions 
        GlobalVariable* KDG = createKeyDataGlobal(M, Ctx.ExpandedKeys);
        Ctx.KeyDataFn = createKeyDataFn(M, KDG);
        Ctx.KeyCodeFn = createKeyCodeFn(M, Ctx.ExpandedKeys);
        Ctx.KeyDataGV = KDG;
        Ctx.DecryptFn = DecryptFn;

        // collect string candidates 
        // Collect before iterating to avoid invalidating the globals list.
        struct Candidate {
            GlobalVariable* GV;
            std::string     Plaintext;
            unsigned        Index;
        };
        std::vector<Candidate> Cands;

        unsigned idx = 0;
        for (GlobalVariable& GV : M.globals()) {
            if (!shouldEncrypt(GV, Ctx.Cfg.minLength)) continue;
            auto* CDA = dyn_cast<ConstantDataArray>(GV.getInitializer());
            if (!CDA || !CDA->isString()) continue;
            Cands.push_back({ &GV, CDA->getAsCString().str(), idx++ });
        }

        if (Cands.empty()) return false;

        bool Changed = false;

        LLVMContext& C = M.getContext();
        Type* I32Ty = Type::getInt32Ty(C);
        Type* I64Ty = Type::getInt64Ty(C);

        // encrypt each candidate 
        for (auto& Cand : Cands) {
            GlobalVariable* GV = Cand.GV;
            const std::string& Plain = Cand.Plaintext;

            // Materialise ConstantExpr users so we can find using functions
            materializeConstExprUsers(GV);

            // Derive per-string nonce (FNV-64 of index + content)
            uint64_t Nonce = fnv64_nonce(Cand.Index, Plain);

            // Encrypt offline
            std::string Cipher = Plain;
            aes128_ctr(Ctx.ExpandedKeys,
                reinterpret_cast<const uint8_t*>(&Nonce),
                reinterpret_cast<uint8_t*>(Cipher.data()),
                Cipher.size());

            // Create per-string globals
            GlobalVariable* CtGV = createCiphertextGlobal(M, Cipher, Cand.Index);
            GlobalVariable* NonceGV = createNonceGlobal(M, Nonce, Cand.Index);

            ArrayType* CtTy = cast<ArrayType>(CtGV->getValueType());
            ArrayType* NonceTy = cast<ArrayType>(NonceGV->getValueType());
            const uint64_t CtBytes = CtTy->getNumElements();  // plaintext len + 1

            // Find all functions that use this string global
            std::set<Function*> Users;
            for (User* U : GV->users())
                if (auto* I = dyn_cast<Instruction>(U))
                    Users.insert(I->getFunction());

            // inject decryption at each using function's entry ──────
            for (Function* F : Users) {
                if (!F || F->isDeclaration()) continue;
                // Skip the stub functions themselves (avoids self-re-encryption)
                if (F->getName().starts_with("__strenc_")) continue;

                Instruction* IP = &*F->getEntryBlock().getFirstInsertionPt();
                IRBuilder<> B(IP);

                // alloca [N x i8]  (stack buffer for in-place decryption)
                AllocaInst* Buf = B.CreateAlloca(CtTy, nullptr, "strenc.buf");
                Buf->setAlignment(Align(16));

                // memcpy(Buf, CtGV, CtBytes)
                Value* Dst = gepI8(B, CtTy, Buf);
                Value* Src = gepI8(B, CtTy, CtGV);
                B.CreateMemCpy(Dst, Align(1), Src, Align(1),
                    ConstantInt::get(I64Ty, CtBytes));

                // ptr to nonce
                Value* NcPtr = gepI8(B, NonceTy, NonceGV);

                // call __strenc_decrypt(buf_ptr, plaintext_len, nonce_ptr)
                // Note: len = CtBytes - 1 (exclude null terminator)
                B.CreateCall(DecryptFn, {
                    Dst,
                    ConstantInt::get(I32Ty, (uint32_t)(CtBytes - 1)),
                    NcPtr
                    });

                // Replace all uses of the original GV in this function with Buf.
                // Buf and GV both have type 'ptr' in opaque-pointer mode.
                for (User* U : make_early_inc_range(GV->users())) {
                    auto* I = dyn_cast<Instruction>(U);
                    if (!I || I->getFunction() != F) continue;
                    I->replaceUsesOfWith(GV, Buf);
                }

                ++DecryptCallsInserted;
                Changed = true;
            }

            ++EncryptedStrings;

            if (GV->use_empty())
                GV->eraseFromParent();
        }

        return Changed;
    }

    // ── StrEncImpl::encryptStringsChaCha ─────────────────────────────────────────
    // The hardened string-encryption path (redesign phases A-E). Mirrors
    // encryptStrings() but replaces the AES/choke-point-call design:
    //   A. Tableless ChaCha20 (no AES S-box static signature). Nonce is 12
    //      bytes (low 8 = fnv64_nonce, high 4 = candidate index, LE).
    //   B. Key never stored flat: @.strenc.ck holds key XOR mask; the real key
    //      is reconstructed per-function at runtime from opaque-constant masks
    //      (defeats offline static bulk-decrypt via a flat key read).
    //   C. Decrypt is INLINED at pass time — no callable __*_decrypt boundary
    //      and no single "first call = decrypt" locate point.
    //   D. Lazy materialization at the uses' dominator + scrub before each ret.
    //   E. Key recombination MBA-encoded (no plain-xor provenance).
    //
    // CEILING (fundamental, not fixable in IR): a string consumed by an
    // external callee (strcmp/printf/...) MUST be plaintext in memory at the
    // point of use, so an attacker who taps that consumer at runtime can still
    // read it. A-E defeat STATIC recovery (no key, no signature, no plain xor)
    // and the DYNAMIC decrypt-hook attack (nothing locatable to hook) — see the
    // deobf_bench strenc_*_chacha cases (100% vs 0% for the AES call path) —
    // but they do not and cannot beat a point-of-use consumer tap. True
    // offline-impossibility + tamper-evidence (code-hash keying) needs a
    // post-link patch tool, out of scope for an IR pass.

    bool StrEncImpl::encryptStringsChaCha(Module& M, StrEncCtx& Ctx) {
        // link the stub (brings in __strenc_chacha_decrypt alongside the rest)
        Function* LinkedDecFn = linkStub(M);
        if (!LinkedDecFn) {
            errs() << "strenc: stub link failed — skipping chacha encryption\n";
            return false;
        }

        Function* ChaChaDecryptFn = M.getFunction("__strenc_chacha_decrypt");
        if (!ChaChaDecryptFn) {
            errs() << "strenc: __strenc_chacha_decrypt missing from linked stub "
                "— skipping chacha encryption\n";
            return false;
        }

        // Get a mutable reference to the annotation cache directly from the
        // MAM (see encryptStrings() for why we don't const_cast Ctx.Ann).
        auto& MutableCache =
            Ctx.MAM.getResult<ObfuscationAnnotationAnalysis>(M);
        hardenStubFunctions(M, Ctx.Cfg.stubPasses, MutableCache);

        Ctx.DecryptFn = ChaChaDecryptFn;

        // Phase D: per-function DominatorTree, fetched via the
        // FunctionAnalysisManager reachable from the module's MAM. Must be
        // queried per-function BEFORE that function is mutated; inserting
        // instructions (as Phase 2 below does) does not change the block-level
        // CFG, so a DT computed here stays valid across those insertions.
        // Phase C's later inlining DOES change the CFG, so DT must not be
        // queried after that point (it isn't — Phase C runs once, after all
        // Phase 2 placement, and doesn't touch DT at all).
        auto& FAM =
            Ctx.MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();

        // collect string candidates
        struct Candidate {
            GlobalVariable* GV;
            std::string     Plaintext;
            unsigned        Index;
        };
        std::vector<Candidate> Cands;

        unsigned idx = 0;
        for (GlobalVariable& GV : M.globals()) {
            if (!shouldEncrypt(GV, Ctx.Cfg.minLength)) continue;
            auto* CDA = dyn_cast<ConstantDataArray>(GV.getInitializer());
            if (!CDA || !CDA->isString()) continue;
            Cands.push_back({ &GV, CDA->getAsCString().str(), idx++ });
        }

        if (Cands.empty()) return false;

        bool Changed = false;

        LLVMContext& C = M.getContext();
        Type* I8Ty = Type::getInt8Ty(C);
        Type* I32Ty = Type::getInt32Ty(C);
        Type* I64Ty = Type::getInt64Ty(C);

        // Phase B: single OpaqueUtils instance for the whole call — it caches
        // its per-function volatile slot internally and is safe to reuse
        // across functions/sites (see OpaqueUtils.h).
        llvm::obf::OpaqueUtils::Options OptsO;
        OptsO.EnableOpaqueConsts = true;
        OptsO.PredStrength = 2;
        llvm::obf::OpaqueUtils Opaque(M, Ctx.R, "strenc.opaque.salt.i32", OptsO);

        // Phase E: MBA factory used to encode the key recombination. The
        // per-word recovery `key = ck XOR mask` is the one operation that
        // materialises key bytes from the (masked) global + opaque mask, so a
        // static lifter that recognises a plain `xor` there could fold the two
        // together. Rewriting it through MBA (equivalent value, boolean/
        // arithmetic identity + runtime-zero noise anchored to a volatile
        // slot) removes that plain-xor signature. Same instance reused across
        // functions; caches its own per-function noise slot.
        //
        // NOTE on the *control-flow-bound* half of the original Phase-E plan:
        // deliberately NOT implemented. Offline encryption forces the runtime
        // mask to equal a build-time constant (MaskWords[w]), so a genuine
        // path accumulator would have to be path-invariant anyway; and the
        // benchmark's string attack is a *concrete* dynamic memory tap that
        // runs the real code, so any value correct for genuine execution is
        // equally correct for the attacker's concrete replay. True
        // offline-impossibility / tamper-evidence needs the post-link
        // code-hash patch tool (separate track), not an IR transform.
        llvm::obf::MbaUtils Mba(M, Ctx.R, "strenc.mba.noise.i32");

        // ── Phase 1: per candidate — offline crypto + globals, no IR yet ──────
        // Dominance fix: we no longer inject a self-contained cluster per
        // (string, using-function) pair at getFirstInsertionPt() — doing so
        // front-inserts each new cluster ahead of previously-inserted ones,
        // so a function using 2+ encrypted strings ends up with its second
        // cluster's key-reconstruction loads referencing an OpaqueUtils
        // volatile-slot alloca created by the first cluster, which no longer
        // dominates it (physically after in the block). Instead we collect
        // per-candidate data here, grouped by using function, and emit all
        // IR for a function in one forward-advancing pass (Phase 2).
        struct CandInj {
            GlobalVariable* GV;       // original plaintext global (to RAUW + maybe erase)
            GlobalVariable* CtGV;     // ciphertext global
            GlobalVariable* NonceGV;  // 12-byte nonce global
            ArrayType* CtTy;          // CtGV value type
            ArrayType* NonceTy;       // NonceGV value type
            uint64_t CtBytes;         // CtTy->getNumElements() (plaintext len + 1)
        };

        llvm::MapVector<Function*, SmallVector<CandInj, 4>> ByFn;
        SmallVector<GlobalVariable*, 16> AllCandGVs;

        for (auto& Cand : Cands) {
            GlobalVariable* GV = Cand.GV;
            const std::string& Plain = Cand.Plaintext;

            // Materialise ConstantExpr users so we can find using functions
            materializeConstExprUsers(GV);

            // Derive per-string 12-byte nonce: low 8 bytes = fnv64_nonce
            // (little-endian), high 4 bytes = candidate index (little-endian).
            uint64_t Nonce64 = fnv64_nonce(Cand.Index, Plain);
            uint8_t Nonce12[12];
            for (int i = 0; i < 8; i++)
                Nonce12[i] = (uint8_t)((Nonce64 >> (8 * i)) & 0xFF);
            uint32_t IdxWord = (uint32_t)Cand.Index;
            for (int i = 0; i < 4; i++)
                Nonce12[8 + i] = (uint8_t)((IdxWord >> (8 * i)) & 0xFF);

            // Encrypt offline
            std::string Cipher = Plain;
            chacha20_xor(Ctx.ChaChaKey, Nonce12, /*counter=*/0,
                reinterpret_cast<uint8_t*>(Cipher.data()),
                Cipher.size());

            // Create per-string globals
            GlobalVariable* CtGV = createCiphertextGlobal(M, Cipher, Cand.Index);
            GlobalVariable* NonceGV = createNonce12Global(M, Nonce12, Cand.Index);

            // Create the single module-shared 32-byte key global lazily.
            // Phase B: this global never holds the flat ChaCha key. It holds
            // (key XOR mask) — ck_byte[i] = ChaChaKey[i] ^ MaskWords[i/4]'s
            // little-endian byte i%4. The real key is reconstructed at each
            // using function's entry at runtime (see Phase 2) by XORing this
            // global back with the mask, where the mask arrives as an opaque
            // constant (equals MaskWords[w] at runtime, not statically
            // foldable).
            if (!Ctx.ChaChaKeyGV) {
                ArrayType* KeyTy = ArrayType::get(I8Ty, 32);
                std::vector<Constant*> KeyBytes;
                KeyBytes.reserve(32);
                for (int i = 0; i < 32; i++) {
                    uint8_t MaskByte =
                        (uint8_t)((Ctx.MaskWords[i / 4] >> (8 * (i % 4))) & 0xFF);
                    KeyBytes.push_back(
                        ConstantInt::get(I8Ty, Ctx.ChaChaKey[i] ^ MaskByte));
                }
                Ctx.ChaChaKeyGV = new GlobalVariable(
                    M, KeyTy, /*isConstant=*/true,
                    GlobalValue::PrivateLinkage,
                    ConstantArray::get(KeyTy, KeyBytes),
                    ".strenc.ck");
                Ctx.ChaChaKeyGV->setSection(".strenc.ck");
                Ctx.ChaChaKeyGV->setAlignment(Align(16));
                Ctx.ChaChaKeyGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
            }

            ArrayType* CtTy = cast<ArrayType>(CtGV->getValueType());
            ArrayType* NonceTy = cast<ArrayType>(NonceGV->getValueType());
            const uint64_t CtBytes = CtTy->getNumElements();  // plaintext len + 1

            // Find all functions that use this string global
            std::set<Function*> Users;
            for (User* U : GV->users())
                if (auto* I = dyn_cast<Instruction>(U))
                    Users.insert(I->getFunction());

            for (Function* F : Users) {
                if (!F || F->isDeclaration()) continue;
                // Skip the stub functions themselves (avoids self-re-encryption)
                if (F->getName().starts_with("__strenc_")) continue;

                ByFn[F].push_back(CandInj{ GV, CtGV, NonceGV, CtTy, NonceTy, CtBytes });
            }

            AllCandGVs.push_back(GV);
            ++EncryptedStrings;
        }

        // ── Phase 2: per using function — single forward-advancing IRBuilder ──
        // The key reconstruction is emitted ONCE per function, first, so it
        // dominates every decrypt cluster that follows in the same block.
        ArrayType* KeyTy = cast<ArrayType>(Ctx.ChaChaKeyGV->getValueType());

        // Phase C: decrypt calls are collected here during emission and
        // inlined in a separate pass below, after all emission is done.
        // Inlining during emission would split the caller block at the call
        // site and invalidate the live, forward-advancing IRBuilder B.
        SmallVector<CallInst*, 16> DecCalls;

        for (auto& Entry : ByFn) {
            Function* F = Entry.first;
            SmallVectorImpl<CandInj>& CandsForFn = Entry.second;

            Instruction* IP = &*F->getEntryBlock().getFirstInsertionPt();
            IRBuilder<> B(IP);

            // Phase B: reconstruct the real ChaCha key at runtime into a
            // stack buffer, rather than pointing decrypt calls at the flat
            // @.strenc.ck global. @.strenc.ck holds key XOR mask; XOR it
            // back with each mask word (delivered as an opaque constant, not
            // statically foldable) to recover the key.
            // Phase E will replace the opaque-const mask with a
            // control-flow-bound path accumulator (genuine path ->
            // MaskWords[w], forced path -> garbage). For now MaskWords are
            // opaque constants.
            AllocaInst* Rk = B.CreateAlloca(ArrayType::get(I8Ty, 32),
                nullptr, "strenc.rk");
            Rk->setAlignment(Align(16));

            Value* CkBasePtr = gepI8(B, KeyTy, Ctx.ChaChaKeyGV);
            for (unsigned w = 0; w < 8; w++) {
                Value* CkWordPtr = B.CreateInBoundsGEP(
                    I8Ty, CkBasePtr, ConstantInt::get(I64Ty, 4ULL * w),
                    "strenc.ck.word.ptr");
                Value* CkWord = B.CreateAlignedLoad(
                    I32Ty, CkWordPtr, Align(1), "strenc.ck.word");

                Value* MaskW = Opaque.opaqueI32Const(B, Ctx.MaskWords[w]);
                // Phase E: MBA-encode the recombination instead of a plain xor.
                // bitwiseXor returns a value equal to (CkWord ^ MaskW) but
                // expressed as an MBA identity; inflateLinear then folds in
                // runtime-zero terms so the recovered key word has no clean
                // static provenance. Runtime value is unchanged → decrypt stays
                // correct.
                Value* KeyW = Mba.bitwiseXor(B, CkWord, MaskW);
                KeyW = Mba.inflateLinear(B, KeyW, /*DepthHint=*/0);

                Value* RkWordPtr = B.CreateInBoundsGEP(
                    I8Ty, Rk, ConstantInt::get(I64Ty, 4ULL * w),
                    "strenc.rk.word.ptr");
                B.CreateAlignedStore(KeyW, RkWordPtr, Align(1));
            }

            Value* KeyPtr = gepI8(B, ArrayType::get(I8Ty, 32), Rk);

            // Phase D: per-function dominator tree, used to place each string's
            // decrypt lazily (at the NCD of its uses). Scrub is emitted before
            // every return (see below), so no post-dominator tree is needed.
            // Fetched once per function, before any Phase 2 mutation of F —
            // inserting instructions doesn't change the CFG, so it stays valid
            // for the rest of this function's processing.
            DominatorTree& DT = FAM.getResult<DominatorTreeAnalysis>(*F);

            // Note: Buf is emitted below via the same, now-advanced builder
            // B, so it lands after the key-reconstruction instructions
            // rather than at the very top of entry. That is valid IR —
            // allocas need not be at block top — and is required for
            // dominance: do not re-anchor to entry's insertion point here.
            for (CandInj& ci : CandsForFn) {
                // alloca [N x i8]  (stack buffer for in-place decryption)
                AllocaInst* Buf = B.CreateAlloca(ci.CtTy, nullptr, "strenc.buf");
                Buf->setAlignment(Align(16));

                // Gather in-function use instructions of the plaintext global
                // before deciding on placement — RAUW below invalidates GV's
                // use-list, so snapshot first.
                SmallVector<Instruction*, 8> Uses;
                for (User* U : ci.GV->users())
                    if (auto* I = dyn_cast<Instruction>(U))
                        if (I->getFunction() == F) Uses.push_back(I);

                // Fallback conditions: reproduce current (Phase C) behavior —
                // materialize at entry, no scrub — whenever lazy placement
                // would be unsound or ill-defined:
                //   - no in-function uses at all;
                //   - a PHI use (PHI operand uses are logically "on the edge"
                //     from the predecessor, not at the PHI's block, so NCD/NCPD
                //     over the PHI's own block would be wrong);
                //   - an EH-pad use (funclet/landingpad/catchswitch), where
                //     ordinary dominance-based insertion is not meaningful.
                bool NeedsFallback = Uses.empty();
                for (Instruction* U : Uses) {
                    if (isa<PHINode>(U) || isa<FuncletPadInst>(U) ||
                        isa<LandingPadInst>(U) || isa<CatchSwitchInst>(U)) {
                        NeedsFallback = true;
                        break;
                    }
                }

                BasicBlock* NCD = nullptr;
                if (!NeedsFallback) {
                    NCD = Uses[0]->getParent();
                    for (Instruction* U : Uses)
                        NCD = DT.findNearestCommonDominator(NCD, U->getParent());
                    if (!NCD) NeedsFallback = true;
                }

                CallInst* DecCall = nullptr;

                if (NeedsFallback) {
                    // Current behavior: memcpy+decrypt right after key recon,
                    // via the entry builder B, no scrub.
                    Value* Dst = gepI8(B, ci.CtTy, Buf);
                    Value* Src = gepI8(B, ci.CtTy, ci.CtGV);
                    B.CreateMemCpy(Dst, Align(1), Src, Align(1),
                        ConstantInt::get(I64Ty, ci.CtBytes));

                    Value* NoncePtr = gepI8(B, ci.NonceTy, ci.NonceGV);

                    DecCall = B.CreateCall(ChaChaDecryptFn, {
                        Dst,
                        ConstantInt::get(I32Ty, (uint32_t)(ci.CtBytes - 1)),
                        KeyPtr,
                        NoncePtr,
                        ConstantInt::get(I32Ty, 0)
                        });
                } else {
                    // LAZY: insert memcpy+decrypt at the earliest point in NCD
                    // that still dominates all uses — either right before the
                    // earliest use instruction physically in NCD, or (if no
                    // use lives in NCD itself, only in blocks it dominates)
                    // before NCD's terminator.
                    Instruction* InsertPt = nullptr;
                    for (Instruction& I : *NCD) {
                        if (is_contained(Uses, &I)) { InsertPt = &I; break; }
                    }
                    if (!InsertPt) InsertPt = NCD->getTerminator();

                    IRBuilder<> MB(InsertPt);
                    Value* Dst = gepI8(MB, ci.CtTy, Buf);
                    Value* Src = gepI8(MB, ci.CtTy, ci.CtGV);
                    MB.CreateMemCpy(Dst, Align(1), Src, Align(1),
                        ConstantInt::get(I64Ty, ci.CtBytes));

                    Value* NoncePtr = gepI8(MB, ci.NonceTy, ci.NonceGV);

                    DecCall = MB.CreateCall(ChaChaDecryptFn, {
                        Dst,
                        ConstantInt::get(I32Ty, (uint32_t)(ci.CtBytes - 1)),
                        KeyPtr,
                        NoncePtr,
                        ConstantInt::get(I32Ty, 0)
                        });
                }

                DecCalls.push_back(DecCall);

                // Replace all uses of the original GV in this function with Buf.
                // Buf and GV both have type 'ptr' in opaque-pointer mode.
                for (User* U : make_early_inc_range(ci.GV->users())) {
                    auto* I = dyn_cast<Instruction>(U);
                    if (!I || I->getFunction() != F) continue;
                    I->replaceUsesOfWith(ci.GV, Buf);
                }

                // SCRUB (non-fallback): wipe Buf before every function return.
                // We scrub at returns, NOT at the "last GV use": the tracked GV
                // uses are pointer/address operations (e.g. the
                // `store ptr @.str, ptr %local` of `const char* a = "..."`),
                // while the actual plaintext READS happen later through that
                // pointer (loads feeding strcmp/printf). Scrubbing after the
                // last GV *use* wiped the buffer before those reads (a real
                // miscompile). Scrubbing before every ret is sound — Buf is an
                // entry alloca that dominates all rets, and all reads precede
                // the return on every path — and gives "no plaintext resident
                // after the function returns". Tighter per-read windowing would
                // need consumer-level data-flow / escape analysis (out of
                // scope; marginal given the consumer must see plaintext at
                // point-of-use anyway).
                if (!NeedsFallback) {
                    for (BasicBlock& BB : *F) {
                        auto* Ret = dyn_cast<ReturnInst>(BB.getTerminator());
                        if (!Ret) continue;
                        IRBuilder<> SB(Ret);
                        SB.CreateMemSet(gepI8(SB, ci.CtTy, Buf),
                            ConstantInt::get(I8Ty, 0),
                            ConstantInt::get(I64Ty, ci.CtBytes),
                            Align(16));
                    }
                }

                ++DecryptCallsInserted;
                Changed = true;
            }
        }

        // Phase C: inline every decrypt call so no callable decrypt boundary
        // remains in the using functions (defeats "first direct call" tap +
        // symbol/choke-point hooks). __strenc_chacha_decrypt is self-contained
        // (-O2 stub, helpers already inlined) and its NoInline was stripped by
        // hardenStubFunctions, so a single InlineFunction per site fully inlines.
        // Collected first and inlined here (not during emission) because
        // InlineFunction splits the caller block and would invalidate the live
        // emission IRBuilder.
        for (CallInst* DC : DecCalls) {
            InlineFunctionInfo IFI;
            InlineResult Res = InlineFunction(*DC, IFI);
            (void)Res;  // on the rare failure the call simply remains — still correct
        }

        // linkStub() pulls in the WHOLE aes stub, including the AES decrypt
        // chain (__aes_decrypt → __obf_aes_ctr_decrypt, plus extern
        // __aes_key_a/__aes_key_b that only the AES path defines). The chacha
        // path never calls that chain and never emits the key providers, so at
        // -O0 (no globaldce) the dead __aes_decrypt keeps unresolved references
        // to __aes_key_a/b and the final link fails. Erase the dead AES chain
        // here. use_empty-guarded + ordered (drop __aes_decrypt first so
        // __obf_aes_ctr_decrypt becomes dead too) so a module that also runs
        // the AES strenc path, or the VM's own __obf_aes_ctr_decrypt ctor, is
        // untouched (those keep a live use and are skipped).
        for (const char* Name : { "__aes_decrypt", "__obf_aes_ctr_decrypt" }) {
            if (Function* Dead = M.getFunction(Name))
                if (Dead->use_empty())
                    Dead->eraseFromParent();
        }

        // ── Phase 3: cleanup — erase candidate globals now fully replaced ──
        for (GlobalVariable* GV : AllCandGVs)
            if (GV->use_empty())
                GV->eraseFromParent();

        return Changed;
    }

    // ── StrEncImpl::encryptStringsXOR (legacy fallback) ───────────────────────────
    // Kept verbatim from original implementation; activated when useAES=false.

    bool StrEncImpl::encryptStringsXOR(Module& M, StrEncCtx& Ctx) {
        LLVMContext& C = M.getContext();
        Type* I8Ty = Type::getInt8Ty(C);
        Type* I32Ty = Type::getInt32Ty(C);
        Type* I64Ty = Type::getInt64Ty(C);
        Type* PtrTy = PointerType::getUnqual(C);

        // ── build/get the legacy XOR decrypt function ──────────────────────────
        auto getOrCreateXORDecrypt = [&]() -> Function* {
            if (Function* F = M.getFunction("__decrypt_string")) return F;

            FunctionType* FT = FunctionType::get(
                PtrTy, { PtrTy, I8Ty, I32Ty }, false);
            Function* F = Function::Create(
                FT, GlobalValue::PrivateLinkage, "__decrypt_string", M);
            F->addFnAttr(Attribute::NoInline);
            F->addFnAttr(Attribute::NoUnwind);

            Argument* strArg = F->getArg(0); strArg->setName("str");
            Argument* keyArg = F->getArg(1); keyArg->setName("key");
            Argument* lenArg = F->getArg(2); lenArg->setName("len");

            BasicBlock* entry = BasicBlock::Create(C, "entry", F);
            BasicBlock* loopCond = BasicBlock::Create(C, "loop.cond", F);
            BasicBlock* loopBody = BasicBlock::Create(C, "loop.body", F);
            BasicBlock* loopEnd = BasicBlock::Create(C, "loop.end", F);

            IRBuilder<> B(entry);
            AllocaInst* iA = B.CreateAlloca(I32Ty, nullptr, "i");
            B.CreateStore(ConstantInt::get(I32Ty, 0), iA);
            B.CreateBr(loopCond);

            B.SetInsertPoint(loopCond);
            LoadInst* iV = B.CreateLoad(I32Ty, iA, "i.val");
            B.CreateCondBr(B.CreateICmpSLT(iV, lenArg, "cmp"), loopBody, loopEnd);

            B.SetInsertPoint(loopBody);
            Value* ptr = B.CreateGEP(I8Ty, strArg, iV, "ptr");
            Value* ch = B.CreateLoad(I8Ty, ptr, "ch");
            Value* dec = B.CreateXor(ch, keyArg, "dec");
            B.CreateStore(dec, ptr);
            B.CreateStore(B.CreateAdd(iV, ConstantInt::get(I32Ty, 1)), iA);
            B.CreateBr(loopCond);

            B.SetInsertPoint(loopEnd);
            B.CreateRet(strArg);
            return F;
            };

        Function* DecFn = getOrCreateXORDecrypt();

        auto gepI8 = [&](IRBuilder<>& B, Type* ArrTy, Value* ArrPtr) -> Value* {
            Value* Z = ConstantInt::get(I32Ty, 0);
            return B.CreateInBoundsGEP(ArrTy, ArrPtr, { Z, Z }, "strenc.gep");
            };

        auto materialize = [&](GlobalVariable* GV) {
            SmallVector<ConstantExpr*, 16> Work;
            for (User* U : GV->users())
                if (auto* CE = dyn_cast<ConstantExpr>(U)) Work.push_back(CE);
            while (!Work.empty()) {
                auto* CE = Work.pop_back_val();
                SmallVector<Use*, 16> Uses;
                for (Use& U : CE->uses()) Uses.push_back(&U);
                for (Use* UP : Uses) {
                    if (auto* I = dyn_cast<Instruction>(UP->getUser())) {
                        Instruction* NI = CE->getAsInstruction();
                        NI->insertBefore(I);
                        NI->setDebugLoc(I->getDebugLoc());
                        UP->set(NI);
                    }
                }
            }
            };

        std::vector<std::tuple<GlobalVariable*, uint8_t, std::string>> ToEnc;
        for (GlobalVariable& GV : M.globals()) {
            if (!shouldEncrypt(GV, Ctx.Cfg.minLength)) continue;
            auto* CDA = dyn_cast<ConstantDataArray>(GV.getInitializer());
            if (!CDA || !CDA->isString()) continue;
            uint8_t K = (uint8_t)(Ctx.KeyRng.u32() & 0xFF);
            if (!K) K = 42;
            ToEnc.emplace_back(&GV, K, CDA->getAsCString().str());
        }
        if (ToEnc.empty()) return false;

        bool Changed = false;
        for (auto& [GV, Key, Str] : ToEnc) {
            materialize(GV);

            std::vector<Constant*> Enc;
            for (char ch : Str)
                Enc.push_back(ConstantInt::get(I8Ty, (uint8_t)ch ^ Key));
            Enc.push_back(ConstantInt::get(I8Ty, 0));

            ArrayType* ArrTy = ArrayType::get(I8Ty, Enc.size());
            auto* EncGV = new GlobalVariable(M, ArrTy, true,
                GlobalValue::PrivateLinkage,
                ConstantArray::get(ArrTy, Enc),
                ".enc_str");
            EncGV->setAlignment(Align(1));

            std::set<Function*> Users;
            for (User* U : GV->users())
                if (auto* I = dyn_cast<Instruction>(U))
                    Users.insert(I->getFunction());

            for (Function* F : Users) {
                if (!F || F->isDeclaration()) continue;
                Instruction* IP = &*F->getEntryBlock().getFirstInsertionPt();
                IRBuilder<> B(IP);

                AllocaInst* Buf = B.CreateAlloca(ArrTy, nullptr, "strenc.buf");
                Buf->setAlignment(Align(1));
                Value* Dst = gepI8(B, ArrTy, Buf);
                Value* Src = gepI8(B, ArrTy, EncGV);
                B.CreateMemCpy(Dst, Align(1), Src, Align(1),
                    ConstantInt::get(I64Ty, Enc.size()));
                B.CreateCall(DecFn, {
                    B.CreateBitCast(Dst, PtrTy),
                    ConstantInt::get(I8Ty, Key),
                    ConstantInt::get(I32Ty, (uint32_t)Str.size())
                    });

                for (User* U : make_early_inc_range(GV->users())) {
                    auto* I = dyn_cast<Instruction>(U);
                    if (!I || I->getFunction() != F) continue;
                    I->replaceUsesOfWith(GV, Buf);
                }
                ++DecryptCallsInserted;
                Changed = true;
            }
            ++EncryptedStrings;
            if (GV->use_empty()) GV->eraseFromParent();
        }
        return Changed;
    }

} // anonymous namespace

// ============================================================================
// StringEncryptionPass::run
// ============================================================================

PreservedAnalyses StringEncryptionPass::run(Module& M,
    ModuleAnalysisManager& MAM) {
    StrEncCtx Ctx(M, MAM);
    if (!Ctx.Cfg.enable)
        return PreservedAnalyses::all();

    if (ObfVerbose) {
        errs() << "[strenc] enable=" << Ctx.Cfg.enable
            << " minlen=" << Ctx.Cfg.minLength
            << " aes=" << Ctx.Cfg.useAES
            << " keysplit=" << Ctx.Cfg.keySplit
            << " chacha=" << Ctx.Cfg.useChaCha
            << "\n";
    }

    bool Changed = Ctx.Cfg.useChaCha
        ? StrEncImpl::encryptStringsChaCha(M, Ctx)
        : Ctx.Cfg.useAES
            ? StrEncImpl::encryptStrings(M, Ctx)
            : StrEncImpl::encryptStringsXOR(M, Ctx);

    if (Changed && ObfVerbose)
        errs() << "[strenc] done: " << (uint64_t)EncryptedStrings
        << " strings, " << (uint64_t)DecryptCallsInserted
        << " call sites\n";

    return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}