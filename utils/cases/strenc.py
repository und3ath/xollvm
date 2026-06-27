"""strenc (AES-128-CTR string encryption) tests and aes_stub sub-pass variants."""

from __future__ import annotations

from ._common import Registry


_AES = "obf: strenc(minlen=4,aes=1,keysplit=1)"
_XOR = "obf: strenc(minlen=4,aes=0)"
_STUB = ("obf: strenc(minlen=4,aes=1,keysplit=1), "
         "mba(prob=80,depth=2,maxSites=150), "
         "bcf(prob=60,loop=1)")

_STUB_MBA_BCF = (
    "obf: strenc(minlen=4,aes=1,keysplit=1), "
    "aes_stub(split(num=4),mba(prob=80,depth=2,maxSites=150),bcf(prob=60,loop=1))"
)
_STUB_FLA = (
    "obf: strenc(minlen=4,aes=1,keysplit=1), "
    "aes_stub(split(num=4),flattening(minBlocks=2,maxBlocks=100))"
)
_STUB_SUB = (
    "obf: strenc(minlen=4,aes=1,keysplit=1), "
    "aes_stub(substitution(loop=1))"
)
_STUB_FULL = (
    "obf: strenc(minlen=4,aes=1,keysplit=1), "
    "aes_stub(split(num=4),"
    "mba(prob=80,depth=2,maxSites=100),"
    "bcf(prob=60,loop=1),"
    "substitution(loop=1))"
)


def register(reg: Registry, **_opts) -> None:
    reg.add(name="strenc_aes_basic", passes=["strenc"],
            ann_override=_AES,
            gates=["strenc_no_plaintext", "strenc_decrypt_present",
                   "strenc_key_providers", "strenc_keysplit_sections"],
            category="strenc")
    reg.add(name="strenc_aes_multi", passes=["strenc"],
            ann_override=_AES,
            gates=["strenc_no_plaintext", "strenc_decrypt_present"],
            category="strenc")
    reg.add(name="strenc_aes_minlen", passes=["strenc"],
            ann_override=_AES,
            gates=["strenc_decrypt_present", "strenc_short_plaintext"],
            category="strenc")
    reg.add(name="strenc_aes_keysplit", passes=["strenc"],
            ann_override=_AES,
            gates=["strenc_no_plaintext", "strenc_decrypt_present",
                   "strenc_key_providers", "strenc_keysplit_sections"],
            category="strenc")
    reg.add(name="strenc_aes_keysplit_off", passes=["strenc"],
            ann_override="obf: strenc(minlen=4,aes=1,keysplit=0)",
            gates=["strenc_no_plaintext", "strenc_decrypt_present"],
            category="strenc")
    reg.add(name="strenc_xor_fallback", passes=["strenc"],
            ann_override=_XOR, gates=[], category="strenc")
    reg.add(name="aes_stub_obfuscated", passes=["strenc", "mba", "bcf"],
            ann_override=_STUB,
            gates=["strenc_no_plaintext", "strenc_decrypt_present"],
            category="strenc")
    reg.add(name="strenc_seed_determinism", passes=["strenc"],
            ann_override=_AES, gates=["seed_determinism"], category="strenc")
    reg.add(name="strenc_seed_divergence", passes=["strenc"],
            ann_override=_AES, gates=["seed_divergence"], category="strenc")

    reg.add(name="aes_stub_passes_mba_bcf", passes=["strenc"],
            ann_override=_STUB_MBA_BCF,
            expect_enabled=["strenc", "aes_stub"],
            gates=["strenc_no_plaintext", "strenc_decrypt_present",
                   "strenc_key_providers", "strenc_keysplit_sections",
                   "aes_stub_grew", "aes_stub_no_plaintext_key"],
            category="strenc")
    reg.add(name="aes_stub_passes_fla", passes=["strenc"],
            ann_override=_STUB_FLA,
            expect_enabled=["strenc", "aes_stub"],
            gates=["strenc_no_plaintext", "strenc_decrypt_present",
                   "aes_stub_grew"],
            category="strenc")
    reg.add(name="aes_stub_passes_sub", passes=["strenc"],
            ann_override=_STUB_SUB,
            expect_enabled=["strenc", "aes_stub"],
            gates=["strenc_no_plaintext", "strenc_decrypt_present",
                   "strenc_key_providers", "strenc_keysplit_sections"],
            category="strenc")
    reg.add(name="aes_stub_passes_full", passes=["strenc"],
            ann_override=_STUB_FULL,
            expect_enabled=["strenc", "aes_stub"],
            gates=["strenc_no_plaintext", "strenc_decrypt_present",
                   "strenc_key_providers", "strenc_keysplit_sections",
                   "aes_stub_grew", "aes_stub_no_plaintext_key"],
            category="strenc")
