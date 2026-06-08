"""Invart runtime control plane package."""

from __future__ import annotations

from ._module_aliases import LEGACY_MODULE_ALIASES, install_module_aliases

install_module_aliases(__name__, LEGACY_MODULE_ALIASES)

__all__ = ["__version__"]

__version__ = "0.9.0"
