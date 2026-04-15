// ============================================================================
// ObfStubBitcode.h — Single embed of aes_stub bitcode, shared by all passes
//
// Both StringEncryption.cpp and VMPass_Impl.cpp need the embedded AES stub
// bitcode to link it into target modules.  Previously each had its own static
// copy, wasting ~4 KB in the compiler binary and creating maintenance risk
// (two arrays that must stay in sync).
//
// This header defines the bitcode blob as an inline variable (C++17) so that
// every TU that includes it shares a single definition.  The linker
// deduplicates them automatically — no ODR violation, no LNK2001.
//
// Location: llvm/include/llvm/Transforms/Obfuscator/AESStubBitcode.h
// ============================================================================

#pragma once

#include <cstddef>

namespace llvm {
namespace obf {

/// Embedded aes_stub bitcode (shared AES-128-CTR runtime, linked by strenc + vmpass).
inline const unsigned char StubBitcode[] = {
#include "aes_stub_bc.inc"
};

inline const unsigned StubBitcodeSize = sizeof(StubBitcode);

} // namespace obf
} // namespace llvm