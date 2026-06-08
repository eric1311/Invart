"""Compatibility package for the former Kappaski import path.

Invart is the public package name. This module keeps old integrations working
while downstream callers migrate from ``kappaski`` to ``invart``.
"""

from __future__ import annotations

import invart as _invart
from invart import *  # noqa: F401,F403
from invart._module_aliases import LEGACY_MODULE_ALIASES, install_module_aliases

__all__ = getattr(_invart, "__all__", [])
__version__ = _invart.__version__
install_module_aliases(__name__, LEGACY_MODULE_ALIASES)
