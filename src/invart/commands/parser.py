from __future__ import annotations

import argparse

from .parser_foundation import register_foundation_commands
from .parser_governance import register_governance_commands
from .parser_integrations import register_integration_commands
from .parser_product import register_product_commands


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="invart",
        description="Local-first agent runtime control plane for safety, policy, evidence, and audit.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    register_governance_commands(subparsers)
    register_foundation_commands(subparsers)
    register_integration_commands(subparsers)
    register_product_commands(subparsers)

    return parser
