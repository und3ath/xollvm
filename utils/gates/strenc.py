"""strenc (string-encryption pass) IR gates."""

from __future__ import annotations

from typing import Optional

from . import register

# Secrets shared between programs (encrypted at compile time) and gates
# (which assert they don't survive as plaintext in the obfuscated IR).
SECRET_A = "OBF_RUNTIME_SECRET_2026"
SECRET_B = "STRENC_ALPHA_BRAVO_2026"
SECRET_C = "CIPHER_VERIFICATION_KEY"
SHORT    = "hi"


@register("strenc_no_plaintext")
def strenc_no_plaintext(obf_ir: str) -> Optional[str]:
    for s in (SECRET_A, SECRET_B, SECRET_C):
        if s in obf_ir:
            return (f"plaintext secret found in obfuscated IR: {s!r} "
                    f"— encryption may have been skipped")
    return None


@register("strenc_decrypt_present")
def strenc_decrypt_present(obf_ir: str) -> Optional[str]:
    if "__aes_decrypt" not in obf_ir:
        return "__aes_decrypt not found in obfuscated IR — stub not linked"
    return None


@register("strenc_key_providers")
def strenc_key_providers(obf_ir: str) -> Optional[str]:
    missing = [fn for fn in ("__aes_key_a", "__aes_key_b")
               if fn not in obf_ir]
    if missing:
        return f"key-provider(s) missing from IR: {', '.join(missing)}"
    return None


@register("strenc_keysplit_sections")
def strenc_keysplit_sections(obf_ir: str) -> Optional[str]:
    missing = [sec for sec in (".strenc.kd", ".strenc.kt")
               if sec not in obf_ir]
    if missing:
        return f"key-split section(s) missing from IR: {', '.join(missing)}"
    return None


@register("strenc_short_plaintext")
def strenc_short_plaintext(obf_ir: str) -> Optional[str]:
    s = SHORT
    if f'c"{s}\\00"' in obf_ir or f'c"{s}"' in obf_ir or s in obf_ir:
        return None
    return (f"short string {s!r} not found as plaintext in IR "
            f"— may have been incorrectly encrypted")
