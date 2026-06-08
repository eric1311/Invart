"""Compatibility CLI module for ``python -m kappaski.cli``."""

from invart.cli import main


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
