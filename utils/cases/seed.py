"""Seed determinism + divergence meta-tests."""

from __future__ import annotations

from ._common import Registry


def register(reg: Registry, **_opts) -> None:
    reg.add(name="rt_seed_determinism", passes=["mba", "bcf"],
            gates=["seed_determinism"], category="meta")
    reg.add(name="rt_seed_divergence", passes=["mba", "bcf"],
            gates=["seed_divergence"], category="meta")
