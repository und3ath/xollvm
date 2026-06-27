"""Test-program template registry.

Templates live as `.c.tmpl` / `.cpp.tmpl` files alongside this module under
subdirectories (base/, vm/, eh/, strenc/, aes_stub/). They use the standard
str.format substitution syntax: `{name}` for placeholders and `{{` / `}}` for
literal braces (matching the source they were extracted from).

Lookup uses dotted names mapped to filesystem paths. `render("vm.gep_chain",
annotation=...)` reads `programs/vm/gep_chain.c.tmpl` (or `.cpp.tmpl`) and
substitutes the keyword arguments.
"""

from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _path(name: str) -> Path:
    rel = name.replace(".", "/")
    for ext in (".c.tmpl", ".cpp.tmpl"):
        p = _HERE / (rel + ext)
        if p.exists():
            return p
    raise FileNotFoundError(f"no template found for: {name}")


def render(name: str, **kwargs: str) -> str:
    """Render programs/<dotted name>.{c,cpp}.tmpl with format kwargs."""
    return _path(name).read_text(encoding="utf-8").format(**kwargs)


def is_cpp(name: str) -> bool:
    """True if the program is a .cpp.tmpl rather than a .c.tmpl."""
    return _path(name).suffix == ".tmpl" and _path(name).name.endswith(".cpp.tmpl")
