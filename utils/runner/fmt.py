"""ANSI color/formatting helpers."""

from __future__ import annotations

import os
import platform
import re
import sys


class _ColorState:
    """Mutable singleton so --no-color can be applied after import."""
    enabled: bool = True

    def __init__(self):
        self.enabled = self._detect()

    @staticmethod
    def _detect() -> bool:
        if os.environ.get("NO_COLOR"):
            return False
        if os.environ.get("FORCE_COLOR"):
            return True
        if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
            return False
        if platform.system() == "Windows":
            try:
                import ctypes
                k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
                h = k32.GetStdHandle(-11)
                m = ctypes.c_ulong()
                k32.GetConsoleMode(h, ctypes.byref(m))
                k32.SetConsoleMode(h, m.value | 0x0004)
                return True
            except Exception:
                return False
        return True


_cs = _ColorState()


def disable_color() -> None:
    _cs.enabled = False


def _c(code: str) -> str:
    return code if _cs.enabled else ""


RST   = lambda: _c("\033[0m")
BOLD  = lambda: _c("\033[1m")
DIM   = lambda: _c("\033[2m")

RED     = lambda: _c("\033[31m")
GREEN   = lambda: _c("\033[32m")
YELLOW  = lambda: _c("\033[33m")
BLUE    = lambda: _c("\033[34m")
MAGENTA = lambda: _c("\033[35m")
CYAN    = lambda: _c("\033[36m")
WHITE   = lambda: _c("\033[37m")
GRAY    = lambda: _c("\033[90m")

BRED    = lambda: _c("\033[91m")
BGREEN  = lambda: _c("\033[92m")
BYELLOW = lambda: _c("\033[93m")
BCYAN   = lambda: _c("\033[96m")

BG_RED    = lambda: _c("\033[41m")
BG_GREEN  = lambda: _c("\033[42m")
BG_YELLOW = lambda: _c("\033[43m")


def badge_pass()  -> str: return f"{BG_GREEN()}{BOLD()}{WHITE()} PASS {RST()}"
def badge_fail()  -> str: return f"{BG_RED()}{BOLD()}{WHITE()} FAIL {RST()}"
def badge_skip()  -> str: return f"{BG_YELLOW()}{BOLD()}{WHITE()} SKIP {RST()}"
def info(s: str)  -> str: return f"{CYAN()}[•]{RST()} {s}"
def warn(s: str)  -> str: return f"{YELLOW()}[!]{RST()} {s}"
def err(s: str)   -> str: return f"{RED()}[✗]{RST()} {s}"
def ok(s: str)    -> str: return f"{GREEN()}[✓]{RST()} {s}"
def head(s: str)  -> str: return f"{BOLD()}{BCYAN()}{s}{RST()}"
def dim(s: str)   -> str: return f"{DIM()}{s}{RST()}"
def bold(s: str)  -> str: return f"{BOLD()}{s}{RST()}"


def fmt_time(s: float) -> str:
    if s < 1.0:
        return f"{GRAY()}{s*1000:.0f}ms{RST()}"
    if s < 60.0:
        return f"{GRAY()}{s:.1f}s{RST()}"
    m, sec = divmod(s, 60)
    return f"{GRAY()}{int(m)}m{sec:.0f}s{RST()}"


def fmt_growth(ratio: float) -> str:
    if ratio <= 0:
        return f"{DIM()}—{RST()}"
    if ratio > 20:
        return f"{RED()}{ratio:.0f}×{RST()}"
    if ratio > 10:
        return f"{YELLOW()}{ratio:.0f}×{RST()}"
    return f"{GREEN()}{ratio:.1f}×{RST()}"


def stripped_len(s: str) -> int:
    return len(re.sub(r"\033\[[0-9;]*m", "", s))
