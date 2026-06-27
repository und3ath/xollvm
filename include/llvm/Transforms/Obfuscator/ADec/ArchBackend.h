#pragma once
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Obfuscator/ADec/Types.h"
#include <memory>
#include <vector>

namespace llvm {
namespace obf {
namespace adec {

// Per-architecture data source: built-in gadget table + default clobber set.
// Phase B layers user-loaded JSON gadgets on top via GadgetPool.
class ADecArchBackend {
public:
	virtual ~ADecArchBackend() = default;

	// Canonical short arch name ("x86_64", "aarch64"). Must match the
	// "arch" field in user-supplied JSON gadgets.
	virtual llvm::StringRef archName() const = 0;

	// True when this backend targets the given triple.
	virtual bool matches(const llvm::Triple& T) const = 0;

	// Compile-time gadget table for this arch.
	virtual llvm::ArrayRef<GadgetSpec> builtinGadgets() const = 0;

	// Default inline-asm clobber list, already formatted ("~{a},~{b}").
	// Empty string means no clobbers.
	virtual llvm::StringRef defaultClobbers() const = 0;
};

std::unique_ptr<ADecArchBackend> makeX86_64Backend();
std::unique_ptr<ADecArchBackend> makeAArch64Backend();

// All compiled-in backends in registration order.
std::vector<std::unique_ptr<ADecArchBackend>> buildArchBackendRegistry();

// Resolve the active backend for the current triple. Returns nullptr if
// no built-in backend matches (caller should disable asm-gadget tech).
const ADecArchBackend*
selectBackend(const llvm::Triple& T,
              const std::vector<std::unique_ptr<ADecArchBackend>>& Registry);

} // namespace adec
} // namespace obf
} // namespace llvm
