"""constenc (numeric constant encryption) IR gates."""

from __future__ import annotations

from typing import Optional

from . import register


# Distinctive magic constants embedded in programs/constenc/basic.c.tmpl.
# constenc materializes them at runtime, so they must not survive as plaintext
# immediates in the obfuscated IR. All are positive so LLVM prints them verbatim
# in decimal — an exact substring match against the textual IR.
MAGICS = ("1985229328", "305419896", "1732584193", "81985529216486895")


@register("constenc_magic_encoded", needs="ir_and_base")
def constenc_magic_encoded(obf_ir: str, base_ir: str) -> Optional[str]:
    """Self-calibrating leak check: a magic constant is a leak only if it was a
    plaintext immediate in the *base* IR and still survives in the obfuscated
    IR. This never false-fails if a given constant happened to be folded away at
    the chosen -O level — it simply won't be checked."""
    leaked = [m for m in MAGICS if m in base_ir and m in obf_ir]
    if leaked:
        return ("magic constant(s) survived as plaintext in obfuscated IR: "
                + ", ".join(leaked) + " — constenc did not encode them")
    # Guard against silent drift: if none of the magics are even in the base
    # IR, the fixture/template changed and this test would be vacuous.
    if not any(m in base_ir for m in MAGICS):
        return ("no magic constants present in base IR — constenc leak test is "
                "vacuous; check programs/constenc/basic.c.tmpl")
    return None


@register("constenc_materialized", needs="ir")
def constenc_materialized(obf_ir: str) -> Optional[str]:
    """Positive check that constenc actually ran: opaqueI32Const names its
    materialized values "obf.oc*", and the pass anchors a volatile slot named
    "obf.constenc.salt.i32". Either marker proves the pass fired."""
    if "obf.oc" in obf_ir or "obf.constenc.salt" in obf_ir:
        return None
    return ("no constenc materialization markers (obf.oc / obf.constenc.salt) "
            "found in obfuscated IR — pass may not have run")
