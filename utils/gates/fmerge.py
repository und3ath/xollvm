"""fmerge (function merging) IR gates."""

from __future__ import annotations

import re
from typing import Optional

from . import register
from ._ir import extract_fn_body

# Original merge-group members are named fm_* in the fmerge fixtures.
_FM_DEF = re.compile(r"^define\b[^\n]*@(fm_[A-Za-z0-9_]+)\b", re.MULTILINE)


@register("fmerge_merged", needs="ir")
def fmerge_merged(obf_ir: str) -> Optional[str]:
    """Positive check that fmerge fired: at least one __obf_merged_ super-
    function must exist in the obfuscated IR."""
    if "@__obf_merged_" in obf_ir:
        return None
    return ("no @__obf_merged_ super-function in obfuscated IR — "
            "fmerge did not run")


@register("fmerge_folded", needs="ir_and_base")
def fmerge_folded(obf_ir: str, base_ir: str) -> Optional[str]:
    """Self-calibrating: the fm_* originals defined in the base IR must be
    folded into the super-function and gone from the obfuscated IR. Requires at
    least two to have disappeared (a real merge) alongside a __obf_merged_
    symbol."""
    base_fns = set(_FM_DEF.findall(base_ir))
    if not base_fns:
        return ("no fm_* functions defined in base IR — fmerge fixture drifted; "
                "check programs/fmerge/*.c.tmpl")
    obf_fns = set(_FM_DEF.findall(obf_ir))
    folded = base_fns - obf_fns
    if len(folded) < 2:
        return (f"expected >=2 fm_* functions folded away; "
                f"base={sorted(base_fns)} still-present={sorted(obf_fns)}")
    if "@__obf_merged_" not in obf_ir:
        return "fm_* folded but no @__obf_merged_ super-function present"
    return None


@register("fmerge_thunk", needs="ir")
def fmerge_thunk(obf_ir: str) -> Optional[str]:
    """Thunks: address-taken / external members keep their symbol, and the
    surviving fm_* body forwards into the super-function. At least one fm_*
    definition must remain and call @__obf_merged_."""
    if "@__obf_merged_" not in obf_ir:
        return "no @__obf_merged_ super-function — fmerge did not run"
    surviving = _FM_DEF.findall(obf_ir)
    if not surviving:
        return ("no surviving fm_* thunk — expected address-taken/external "
                "forwarders to remain")
    for name in surviving:
        body = extract_fn_body(obf_ir, name)
        if body and "@__obf_merged_" in body:
            return None
    return ("surviving fm_* function(s) do not forward to @__obf_merged_ — "
            "not a thunk")


@register("fmerge_launder", needs="ir")
def fmerge_launder(obf_ir: str) -> Optional[str]:
    """Selector laundering: a __obf_fmsel_ selector-table global must exist and
    call sites must read it with a volatile load (no inline constant selector)."""
    if "@__obf_fmsel_" not in obf_ir:
        return "no @__obf_fmsel_ selector table — laundering not emitted"
    if "load volatile" not in obf_ir:
        return "selector table present but no volatile load at call sites"
    return None


@register("fmerge_indirectbr", needs="ir")
def fmerge_indirectbr(obf_ir: str) -> Optional[str]:
    """Indirectbr dispatch: a __obf_fmjt_ jump table + an indirectbr must be
    present (the switch is replaced)."""
    if "@__obf_fmjt_" not in obf_ir:
        return "no @__obf_fmjt_ jump table — indirectbr dispatch not emitted"
    if "indirectbr" not in obf_ir:
        return "jump table present but no indirectbr instruction"
    return None
