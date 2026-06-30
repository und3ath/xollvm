"""aes_stub sub-pass IR gates (post-stub-obfuscation structure checks)."""

from __future__ import annotations

import re
from typing import Optional

from . import register
from ._ir import extract_fn_body


_STUB_FN_CANDIDATES = (
    # Workhorse — does the actual CTR/AES math; survives -O2 with many
    # blocks even after inlining of the small helpers.
    "__obf_aes_ctr_decrypt",
    # Top-level entry: under -O2 the helper calls get inlined and the
    # body collapses to a single basic block, so BB-growth checks here
    # are unreliable. Kept as a fallback for Debug-built stubs.
    "__aes_decrypt",
)


@register("aes_stub_grew")
def aes_stub_grew(obf_ir: str) -> Optional[str]:
    """Check that at least one stub function got >1 basic block after
    stub-pass obfuscation. -O2-compiled stubs collapse __aes_decrypt
    into a single BB, so we accept growth in any of the candidate
    workhorses below."""
    missing: list[str] = []
    bb_counts: dict[str, int] = {}
    for name in _STUB_FN_CANDIDATES:
        body = extract_fn_body(obf_ir, name)
        if body is None:
            missing.append(name)
            continue
        bb_counts[name] = sum(1 for line in body.splitlines()
                              if re.match(r"^\s*\w[\w.]*\s*:", line))

    if not bb_counts:
        return ("none of the AES stub functions are defined in IR ("
                + ", ".join(missing) + ")")

    if any(c > 1 for c in bb_counts.values()):
        return None

    summary = ", ".join(f"{n}={c}" for n, c in bb_counts.items())
    return (f"no stub function grew past 1 basic block ({summary}) — "
            f"stub obfuscation passes appear not to have run")


@register("aes_stub_no_plaintext_key")
def aes_stub_no_plaintext_key(obf_ir: str) -> Optional[str]:
    fn_body = extract_fn_body(obf_ir, "__aes_key_b")
    if fn_body is None:
        return "__aes_key_b body not found in IR — function not defined"
    if "store" not in fn_body:
        return "__strenc_key_b has no store instructions — key bytes missing"
    return None
