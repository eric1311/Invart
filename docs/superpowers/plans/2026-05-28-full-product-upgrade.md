# Full Product Upgrade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade the roadmap-gated v0.8-v0.18 capabilities from milestone slices to product-ready local control-plane features with tests, docs, benchmarks, and a passing `roadmap status --require-full`.

**Architecture:** Keep Kappaski local-first and dependency-free. Product readiness means a capability has a concrete CLI/API surface, ledger/proof or transcript artifacts where applicable, deterministic tests, and an explicit coverage boundary; it does not falsely claim kernel-level EDR or private vendor API control.

**Tech Stack:** Python stdlib, current Kappaski models/ledger/daemon/profile modules, existing Rust shim source for file-write enforcement, HTML documentation.

---

### Task 1: Full-Product Readiness Tests

**Files:**
- Modify: `tests/test_core.py`

- [ ] **Step 1: Add failing tests**

Add tests that assert product-ready behavior:

```python
def test_full_v08_reviewer_quality_corpus_and_optional_provider_smoke() -> None: ...
def test_full_v09_managed_harness_pause_resume_records_approval(tmp_path: Path) -> None: ...
def test_full_v10_process_supervision_captures_process_group(tmp_path: Path) -> None: ...
def test_full_v11_profile_review_and_distribution_bundle(tmp_path: Path) -> None: ...
def test_full_v12_teamrun_timeline_html_spans_multiple_ledgers(tmp_path: Path) -> None: ...
def test_full_v13_enforce_run_domains_cover_env_and_network(tmp_path: Path) -> None: ...
def test_full_v14_audit_signoff_is_ledger_backed(tmp_path: Path) -> None: ...
def test_full_v15_native_conformance_hashes_and_validates_surfaces(tmp_path: Path) -> None: ...
def test_full_v16_bridge_conformance_fuzzes_vendor_responses() -> None: ...
def test_full_v17_mcp_stdio_broker_records_transcript(tmp_path: Path) -> None: ...
def test_full_v18_coverage_html_report_exports_gap_matrix(tmp_path: Path) -> None: ...
def test_roadmap_full_product_is_ready() -> None: ...
```

- [ ] **Step 2: Verify RED**

Run:

```bash
PYTHONPYCACHEPREFIX=/tmp/kappaski_pycache PYTHONPATH=src /usr/bin/python3 -m pytest tests/test_core.py -q
```

Expected: the new tests fail because the product-ready APIs are missing.

### Task 2: Product-Ready Runtime Modules

**Files:**
- Create: `src/kappaski/product_readiness.py`
- Create: `src/kappaski/supervision.py`
- Modify: `src/kappaski/harness.py`
- Modify: `src/kappaski/profiles.py`
- Modify: `src/kappaski/teamrun.py`
- Modify: `src/kappaski/enforcement.py`
- Modify: `src/kappaski/audit_demo.py`
- Modify: `src/kappaski/native.py`
- Modify: `src/kappaski/native_bridge.py`
- Modify: `src/kappaski/mcp_broker.py`
- Modify: `src/kappaski/coverage.py`
- Modify: `src/kappaski/cli.py`

- [ ] **Step 1: Implement product readiness surfaces**

Implement:
- reviewer corpus quality summary and optional provider smoke readiness;
- managed harness pause/approval/resume compatibility wrapper;
- process group supervision metadata;
- profile distribution and break-glass review records;
- multi-ledger TeamRun timeline HTML;
- generic enforcement wrapper for file-write, env-secrets, and network-egress domains;
- audit signoff ledger fact;
- native integration conformance hashing;
- native bridge response conformance fuzzing;
- line-oriented MCP stdio broker transcript capture;
- coverage HTML report export.

- [ ] **Step 2: Verify GREEN**

Run the focused tests from Task 1. Expected: pass.

### Task 3: Benchmarks And Roadmap Status

**Files:**
- Modify: `src/kappaski/evals.py`
- Modify: `src/kappaski/roadmap.py`

- [ ] **Step 1: Add a full-product benchmark**

Add `full-product-readiness` that exercises the new product-ready surfaces and fails if any required check fails.

- [ ] **Step 2: Promote roadmap statuses**

Set v0.8-v0.18 capability statuses to `implemented`, replace obsolete gaps with `product_boundary`, and update the summary schema to `kappaski.roadmap_coverage.full_product.v0.18`.

- [ ] **Step 3: Verify**

Run:

```bash
PYTHONPYCACHEPREFIX=/tmp/kappaski_pycache PYTHONPATH=src /usr/bin/python3 -m pytest tests/test_core.py::test_roadmap_full_product_is_ready -q
```

Expected: pass.

### Task 4: Documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/roadmap.md`
- Modify: `docs/roadmap.html`
- Modify: `docs/roadmap-coverage.html`
- Modify: `docs/user-guide.md`
- Create: `docs/full-product-readiness.html`

- [ ] **Step 1: Document the upgraded state**

Document the per-version full-product surfaces, commands, artifacts, tests, and honest product boundaries.

- [ ] **Step 2: Verify docs references**

Run:

```bash
rg -n "full-product-readiness|implemented|require-full|full_product_ready" README.md docs src tests
```

Expected: full-product readiness is discoverable from README, docs index/roadmap, tests, and code.

### Task 5: Final Verification

**Files:**
- No edits unless verification reveals issues.

- [ ] **Step 1: Run all tests**

```bash
PYTHONPYCACHEPREFIX=/tmp/kappaski_pycache PYTHONPATH=src /usr/bin/python3 -m pytest -q
```

Expected: all tests pass.

- [ ] **Step 2: Run benchmarks**

```bash
PYTHONPYCACHEPREFIX=/tmp/kappaski_pycache PYTHONPATH=src /usr/bin/python3 -m kappaski.cli eval benchmark --suite full-product-readiness
PYTHONPYCACHEPREFIX=/tmp/kappaski_pycache PYTHONPATH=src /usr/bin/python3 -m kappaski.cli roadmap status --require-full
```

Expected: both commands exit 0.
