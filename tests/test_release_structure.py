import importlib
import struct
from pathlib import Path

from invart.core.env import child_env, invart_session_env
from invart.evaluation.roadmap import roadmap_capabilities


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_invart_source_root_is_domain_organized() -> None:
    src = _repo_root() / "src" / "invart"
    root_files = {path.name for path in src.glob("*.py")}
    assert root_files == {"__init__.py", "_module_aliases.py", "cli.py"}

    expected_packages = {
        "assurance",
        "benchmarks",
        "commands",
        "control",
        "core",
        "evaluation",
        "governance",
        "surfaces",
    }
    actual_packages = {path.name for path in src.iterdir() if path.is_dir() and not path.name.startswith("__")}
    assert expected_packages.issubset(actual_packages)


def test_legacy_module_aliases_preserve_old_import_paths() -> None:
    expected = {
        "invart.ledger": "invart.core.ledger",
        "invart.models": "invart.core.models",
        "invart.runtime": "invart.control.runtime",
        "invart.postruntime": "invart.assurance.postruntime",
        "invart.adapter": "invart.surfaces.adapter",
        "invart.release_candidate": "invart.evaluation.release_candidate",
        "kappaski.ledger": "invart.core.ledger",
        "kappaski.runtime": "invart.control.runtime",
        "kappaski.postruntime": "invart.assurance.postruntime",
    }
    for legacy_name, canonical_name in expected.items():
        legacy = importlib.import_module(legacy_name)
        canonical = importlib.import_module(canonical_name)
        assert legacy is canonical


def test_invart_child_env_uses_current_names_by_default_and_legacy_only_when_requested() -> None:
    current = invart_session_env(session_id="s1", ledger="ledger.jsonl", target=".", include_legacy=False)
    assert current["INVART_SESSION_ID"] == "s1"
    assert current["INVART_LEDGER"] == "ledger.jsonl"
    assert "KAPPASKI_SESSION_ID" not in current
    assert "KAPPASKI_LEDGER" not in current

    legacy = child_env(
        {"INVART_ENABLE_LEGACY_KAPPASKI_ENV": "1"},
        session_id="s2",
        ledger="legacy.jsonl",
        adapter="claude-code",
    )
    assert legacy["INVART_SESSION_ID"] == "s2"
    assert legacy["KAPPASKI_SESSION_ID"] == "s2"
    assert legacy["KAPPASKI_ADAPTER"] == "claude-code"


def test_kappaski_mentions_are_limited_to_compatibility_boundaries() -> None:
    root = _repo_root()
    allowed = {
        "AGENTS.md",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "README.md",
        "docs/api-sdk.md",
        "docs/architecture.md",
        "docs/open-source-boundary.md",
        "docs/html/api-sdk.html",
        "docs/html/architecture.html",
        "docs/html/open-source-boundary.html",
        "pyproject.toml",
        "src/invart/commands/parser_product.py",
        "src/invart/control/review.py",
        "src/invart/control/rules.py",
        "src/invart/core/env.py",
        "src/invart/evaluation/container_demo.py",
        "src/invart/evaluation/product_readiness.py",
        "src/kappaski/__init__.py",
        "src/kappaski/cli.py",
    }
    skip_dirs = {
        ".git",
        ".internal",
        ".invart",
        ".kappaski",
        ".pytest_cache",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "internal",
        "target",
    }
    findings: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        parts = path.relative_to(root).parts
        if any(part in skip_dirs or part.endswith(".egg-info") for part in parts):
            continue
        if rel == ".gitignore" or rel == "tests/test_release_structure.py":
            continue
        if path.suffix not in {"", ".html", ".json", ".md", ".py", ".toml", ".txt", ".yml"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if any(token in text for token in ("Kappaski", "kappaski", "KAPPASKI", ".kappaski")):
            if rel not in allowed:
                findings.append(rel)
    assert findings == []


def test_roadmap_implementation_paths_match_current_source_layout() -> None:
    root = _repo_root()
    stale_root_modules = {f"src/invart/{name}.py" for name in (
        "adapter",
        "approval",
        "coverage",
        "daemon",
        "evals",
        "gate",
        "ledger",
        "models",
        "postruntime",
        "runtime",
    )}
    stale: list[str] = []
    missing: list[str] = []
    for capability in roadmap_capabilities():
        for path in capability["implementation"]:
            if path in stale_root_modules:
                stale.append(path)
            if path.startswith("src/") and not (root / path).exists():
                missing.append(path)
    assert stale == []
    assert missing == []


def _png_dimensions(path: Path) -> tuple[int, int]:
    with path.open("rb") as handle:
        signature = handle.read(8)
        assert signature == b"\x89PNG\r\n\x1a\n"
        length = struct.unpack(">I", handle.read(4))[0]
        chunk_type = handle.read(4)
        assert length == 13
        assert chunk_type == b"IHDR"
        width, height = struct.unpack(">II", handle.read(8))
    return width, height


def test_public_brand_assets_are_original_png_kit() -> None:
    root = _repo_root()
    expected = {
        "assets/brand/png-from-original/invart-logo-original-master-1774x887.png": (1774, 887),
        "assets/brand/png-from-original/invart-logo-horizontal-1600x800.png": (1600, 800),
        "assets/brand/png-from-original/invart-logo-docs-header-1200x400.png": (1200, 400),
        "assets/brand/png-from-original/invart-logo-og-1600x900.png": (1600, 900),
        "assets/brand/png-from-original/invart-logo-square-preview-1024x1024.png": (1024, 1024),
        "assets/brand/png-from-original/invart-mark-from-original-512x512.png": (512, 512),
        "assets/brand/png-from-original/invart-mark-from-original-64x64.png": (64, 64),
    }
    for asset, dimensions in expected.items():
        path = root / asset
        assert path.exists()
        assert _png_dimensions(path) == dimensions


def test_public_docs_use_original_png_brand_assets() -> None:
    root = _repo_root()
    readme = (root / "README.md").read_text(encoding="utf-8")
    docs_index = (root / "docs" / "html" / "index.html").read_text(encoding="utf-8")
    assert "assets/brand/png-from-original/invart-logo-horizontal-1600x800.png" in readme
    assert "../../assets/brand/png-from-original/invart-logo-docs-header-1200x400.png" in docs_index
    assert "../../assets/brand/png-from-original/invart-mark-from-original-64x64.png" in docs_index
