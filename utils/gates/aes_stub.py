"""aes_stub sub-pass IR gates (post-stub-obfuscation structure checks)."""

from __future__ import annotations

import re
from typing import Optional

from . import register
from ._ir import extract_fn_body


@register("aes_stub_grew")
def aes_stub_grew(obf_ir: str) -> Optional[str]:
    fn_body = extract_fn_body(obf_ir, "__aes_decrypt")
    if fn_body is None:
        return "__aes_decrypt not found — cannot check stub growth"
    bb_count = sum(1 for line in fn_body.splitlines()
                   if re.match(r"^\s*\w[\w.]*\s*:", line))
    if bb_count <= 1:
        return (f"__aes_decrypt has only {bb_count} basic block(s) — "
                f"stub obfuscation passes appear not to have run")
    return None


@register("aes_stub_no_plaintext_key")
def aes_stub_no_plaintext_key(obf_ir: str) -> Optional[str]:
    fn_body = extract_fn_body(obf_ir, "__aes_key_b")
    if fn_body is None:
        return "__aes_key_b body not found in IR — function not defined"
    if "store" not in fn_body:
        return "__strenc_key_b has no store instructions — key bytes missing"
    return None
