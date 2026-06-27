#pragma once
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/Allocator.h"
#include "llvm/Support/StringSaver.h"
#include "llvm/Transforms/Obfuscator/ADec/ArchBackend.h"
#include "llvm/Transforms/Obfuscator/ADec/Types.h"
#include <string>
#include <vector>

namespace llvm {
namespace obf {
namespace adec {

// Aggregated, ready-to-use gadget set for one execution context.
// Merges sources in priority order:
//   1. Built-in compile-time tables (unless suppressed by CLI)
//   2. Global JSON files from -adec-gadgets-file
//   3. Per-function JSON file from `obf:adec(gadgets="...")` annotation
//   4. Per-function inline asm from `obf:adec(asmInline="...")` annotation
//
// Category and arch filters are applied after the merge.
// Strings loaded from JSON / inline are owned by the pool's StringSaver,
// so GadgetSpec StringRefs remain valid for the pool's lifetime.
class GadgetPool {
public:
	// Build a pool for the active backend.
	//
	// fatalOnError flags: when true, parse/IO errors call report_fatal_error
	// (used for static/CLI input). When false, errors warn-and-skip (used
	// for per-function annotation input).
	GadgetPool(const ADecArchBackend* Backend,
	           llvm::ArrayRef<std::string> CliFiles,
	           bool DisableBuiltins,
	           llvm::StringRef ClobberOverride,
	           llvm::StringRef PerFnFile,
	           llvm::StringRef InlineAsmBodies,
	           llvm::ArrayRef<std::string> CategoryFilter);

	llvm::ArrayRef<GadgetSpec> gadgets() const { return Gadgets; }
	llvm::StringRef defaultClobbers() const { return DefaultClobbers; }
	bool empty() const { return Gadgets.empty(); }

private:
	// Parse one JSON file. Returns true on success.
	bool loadJsonFile(llvm::StringRef Path, bool FatalOnError);
	// Append inline asm bodies (';'-separated) as gadgets for the active arch.
	void loadInlineAsm(llvm::StringRef Bodies);

	void appendFiltered(const GadgetSpec& G);

	const ADecArchBackend* Backend = nullptr;

	llvm::BumpPtrAllocator Alloc;
	llvm::StringSaver Saver{ Alloc };

	llvm::SmallVector<GadgetSpec, 32> Gadgets;

	// Resolved default clobbers (CLI override wins, otherwise backend default).
	llvm::StringRef DefaultClobbers;
	// Owns the override string when set.
	std::string ClobberOverrideOwned;
	// Owned copy of the category filter so it applies across all loaders.
	std::vector<std::string> CategoryFilter;
};

} // namespace adec
} // namespace obf
} // namespace llvm
