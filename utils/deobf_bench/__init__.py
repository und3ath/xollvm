"""Deobfuscation resilience bench.

Throws modern deobfuscation techniques at obfuscator pass output and scores
how well each pass resists recovery (as opposed to runner/gates/cases, which
only prove obfuscated code still executes correctly / still *looks*
obfuscated by regex).
"""
