"""Shared IR-text helpers used by multiple gate modules."""

from __future__ import annotations

import re
from typing import Optional


def extract_fn_body(ir: str, fn_name: str) -> Optional[str]:
    """Return the text between 'define ... @fn_name' and its closing '}',
    or None if the function is not defined (only declared, or absent)."""
    pattern = re.compile(
        r"^define\b[^\n]*@" + re.escape(fn_name) + r"\b[^\n]*\{",
        re.MULTILINE,
    )
    m = pattern.search(ir)
    if not m:
        return None
    start = m.end()
    depth = 1
    i = start
    while i < len(ir) and depth:
        if ir[i] == '{':
            depth += 1
        elif ir[i] == '}':
            depth -= 1
        i += 1
    return ir[start:i - 1]
