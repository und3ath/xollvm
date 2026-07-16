#pragma once

// ============================================================================
// EHUtils.h — Exception Handling utilities for the obfuscator
//
// Provides helper functions for safely manipulating IR that contains
// invoke/landingpad/catchswitch/catchpad/cleanuppad constructs.
//
// Key design principles:
//   - Never split invoke edges (the edge from invoke to landingpad is sacred)
//   - Treat EH pads as opaque (don't insert code into them)
//   - When flattening, invoke unwind targets become state-machine transitions
//   - BCF should never insert bogus blocks on unwind paths
// ============================================================================

#include "llvm/IR/BasicBlock.h"

namespace llvm::obf {

	/// Returns true if the block is part of an EH "region" — either an EH pad
	/// itself or a block that is reachable only through EH pads (between
	/// landingpad and resume/catchret/cleanupret).
	bool isInEHRegion(const BasicBlock* BB);

} // namespace llvm::obf
