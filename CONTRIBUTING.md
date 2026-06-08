# Contributing To Invart

Invart is a control-plane project. Contributions should preserve the product loop:

1. pre-runtime inventory;
2. runtime mediation and evidence;
3. post-runtime proof, replay, audit, and verification.

## Development Setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m pytest -q
```

## Contribution Rules

- Keep public CLI behavior stable unless the README and docs are updated in the same change.
- Keep deterministic critical rules non-downgradable by LLM judgment.
- Add or update tests for every product-visible behavior change.
- Prefer real fixtures, public benchmark-shaped data, or safe equivalents of real agent risk cases over mock-only tests.
- Do not commit `.invart/`, `.venv/`, `build/`, `dist/`, `logs/`, `.pytest_cache/`, Rust `target/`, or local internal notes.

## Compatibility

The old `kappaski` import path and CLI are compatibility aliases. New code and documentation should use `invart`.
