"""whole-program selection (-obf-all): a global pass spec applied to every
defined function, overriding per-function annotations (PR #38).

-obf-all is off by default, so the rest of the suite never exercises it. These
cases drive it through tc.extra_opts (forwarded verbatim to the obfuscation
`opt` run and to dump-config), and assert via the dump-config enabled-list that
the spec reached obf_target. Correctness is the usual base-vs-obf differential.
"""

from __future__ import annotations

from ._common import Registry


_SPEC = "mba(prob=100,depth=2,maxSites=200)"


def register(reg: Registry, **_opts) -> None:
    # Global application: obf_target carries no effective annotation; -obf-all
    # alone must make mba run on it (dump-config enabled == [mba]) while output
    # stays identical to baseline.
    reg.add(name="obf_all_global", passes=[],
            ann_override="obf: ",
            extra_opts=[f"-obf-all={_SPEC}"],
            expect_enabled=["mba"],
            category="pass")
    # Override: obf_target is annotated with substitution, but a non-empty
    # -obf-all replaces annotations outright, so only mba runs (exact enabled
    # and order == [mba], substitution gone).
    reg.add(name="obf_all_override", passes=[],
            ann_override="obf: substitution(loop=1)",
            extra_opts=[f"-obf-all={_SPEC}"],
            expect_enabled=["mba"],
            expect_order=["mba"],
            category="pass")
