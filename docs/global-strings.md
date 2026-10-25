# Persistent global strings

Strings referenced through static aggregates are encrypted in their original
storage and decrypted once by a module constructor. Pointers and string views
retain stable addresses, including views captured before `main`. A compact
record table and loop keep generated code size bounded for large catalogues.
XOR, ChaCha20, and AES use the same persistent-storage path.

The constructor uses priority zero, ahead of normal C++ dynamic initialisation
and supported user priorities (101 and above). Code running before constructors,
or competing priority-zero constructors in other modules, is outside this
contract. This requires a runtime which runs global constructors normally.
Plaintext stays in memory afterwards; this is not on-demand memory protection.

Persistent strings with non-local linkage are excluded: coalescing the storage
across translation units while retaining distinct decryption constructors/keys
would corrupt it. Local string literals in externally visible tables remain
supported. Existing metadata and address-as-integer exclusions still apply.

Run `python3 utils/test_global_strings.py --compiler clang++ --plugin /path/to/Obfuscator.so`.
It links two translation units, checks early startup and retained pointer
identity, checks shared ODR storage, and verifies plaintext removal and identical
runtime output for all three ciphers.
