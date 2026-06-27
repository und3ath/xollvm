#include "llvm/Transforms/Obfuscator/ADec/GadgetPool.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"

#include <algorithm>

namespace llvm {
namespace obf {
namespace adec {

namespace {

// Issue a parse diagnostic and either abort or return false.
static bool fail(llvm::Twine Msg, bool Fatal) {
	if (Fatal)
		llvm::report_fatal_error(Msg, /*gen_crash_diag=*/false);
	if (llvm::ObfVerbose)
		llvm::errs() << "[adec] " << Msg << " (skipping)\n";
	return false;
}

} // namespace

GadgetPool::GadgetPool(const ADecArchBackend* B,
                       llvm::ArrayRef<std::string> CliFiles,
                       bool DisableBuiltins,
                       llvm::StringRef ClobberOverride,
                       llvm::StringRef PerFnFile,
                       llvm::StringRef InlineAsmBodies,
                       llvm::ArrayRef<std::string> CategoryFilterIn)
	: Backend(B) {

	if (!Backend)
		return;

	CategoryFilter.assign(CategoryFilterIn.begin(), CategoryFilterIn.end());

	if (!ClobberOverride.empty()) {
		ClobberOverrideOwned = llvm::FormatClobberList(ClobberOverride);
		DefaultClobbers = ClobberOverrideOwned;
	} else {
		DefaultClobbers = Backend->defaultClobbers();
	}

	if (!DisableBuiltins) {
		for (const GadgetSpec& G : Backend->builtinGadgets())
			appendFiltered(G);
	}

	for (const auto& Path : CliFiles)
		(void)loadJsonFile(Path, /*FatalOnError=*/true);

	if (!PerFnFile.empty())
		(void)loadJsonFile(PerFnFile, /*FatalOnError=*/false);

	if (!InlineAsmBodies.empty())
		loadInlineAsm(InlineAsmBodies);
}

void GadgetPool::appendFiltered(const GadgetSpec& G) {
	if (!Backend)
		return;
	if (G.Arch != Backend->archName())
		return;
	if (!CategoryFilter.empty()) {
		if (G.Category.empty())
			return;
		bool ok = false;
		for (const auto& F : CategoryFilter)
			if (G.Category == F) { ok = true; break; }
		if (!ok)
			return;
	}
	Gadgets.push_back(G);
}

bool GadgetPool::loadJsonFile(llvm::StringRef Path, bool FatalOnError) {
	auto BufOrErr = llvm::MemoryBuffer::getFile(Path);
	if (!BufOrErr)
		return fail("gadget file: cannot read '" + Path + "': " +
		            BufOrErr.getError().message(), FatalOnError);

	auto Parsed = llvm::json::parse((*BufOrErr)->getBuffer());
	if (!Parsed) {
		std::string M;
		llvm::raw_string_ostream OS(M);
		OS << "gadget file: JSON parse error in '" << Path
		   << "': " << llvm::toString(Parsed.takeError());
		return fail(OS.str(), FatalOnError);
	}

	const llvm::json::Array* Arr = Parsed->getAsArray();
	if (!Arr)
		return fail("gadget file: '" + Path + "' top-level must be an array",
		            FatalOnError);

	for (const auto& Item : *Arr) {
		const llvm::json::Object* Obj = Item.getAsObject();
		if (!Obj) {
			fail("gadget file: '" + Path + "' entry is not an object",
			     FatalOnError);
			continue;
		}

		auto NameSV = Obj->getString("name");
		auto ArchSV = Obj->getString("arch");
		auto BodySV = Obj->getString("body");
		if (!NameSV || !ArchSV || !BodySV) {
			fail("gadget file: '" + Path +
			     "' entry missing required field (name/arch/body)",
			     FatalOnError);
			continue;
		}

		GadgetSpec G;
		G.Name = Saver.save(*NameSV);
		G.Arch = Saver.save(*ArchSV);
		G.Body = Saver.save(*BodySV);

		if (auto CatSV = Obj->getString("category"))
			G.Category = Saver.save(*CatSV);

		if (auto W = Obj->getInteger("weight"))
			G.Weight = (unsigned)std::max<int64_t>(1, *W);
		else
			G.Weight = 1;

		if (const auto* ClobArr = Obj->getArray("clobbers")) {
			std::string Formatted;
			bool first = true;
			for (const auto& C : *ClobArr) {
				auto CS = C.getAsString();
				if (!CS)
					continue;
				if (!first)
					Formatted.push_back(',');
				first = false;
				Formatted += "~{";
				Formatted += CS->str();
				Formatted.push_back('}');
			}
			if (!Formatted.empty())
				G.Clobbers = Saver.save(Formatted);
		}

		appendFiltered(G);
	}

	return true;
}

void GadgetPool::loadInlineAsm(llvm::StringRef Bodies) {
	if (!Backend)
		return;
	llvm::SmallVector<llvm::StringRef, 8> Parts;
	Bodies.split(Parts, ';', /*MaxSplit=*/-1, /*KeepEmpty=*/false);
	for (auto& P : Parts) {
		llvm::StringRef Trim = P.trim();
		if (Trim.empty())
			continue;
		GadgetSpec G;
		G.Name = Saver.save("user.inline");
		G.Arch = Backend->archName();
		G.Category = Saver.save("user-inline");
		G.Weight = 1;
		G.Body = Saver.save(Trim);
		// Clobbers left empty → asm tech falls back to DefaultClobbers.
		Gadgets.push_back(G); // user inline always passes filter
	}
}

} // namespace adec
} // namespace obf
} // namespace llvm
