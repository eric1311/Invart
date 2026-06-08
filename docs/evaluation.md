# Measure control-plane behavior, not just code paths.

[HTML version](html/evaluation.html)


Invart separates local product checks from optional heavy external benchmark evidence.

## Default Local Checks

```bash
python -m pytest -q
PYTHONPATH=src python -m invart.cli eval benchmark --suite full-product-readiness
PYTHONPATH=src python -m invart.cli eval benchmark --suite real-world-agent-risk-demo
PYTHONPATH=src python -m invart.cli roadmap status --require-full
```

## Metrics

| Metric | Why it matters |
| --- | --- |
| Critical block/approval behavior | High-risk actions should not silently pass. |
| Benign false-positive proxy | Low-risk agent work should keep moving. |
| Proof completeness | The proof should answer who, what, why, policy, approval, outcome, and coverage. |
| Coverage truthfulness | Observed, mediated, enforced, and fail-open are not the same claim. |
| Audit reconstruction | A reviewer should reconstruct the run from durable evidence. |

## External Validation Boundary

Full SWE-Bench and other upstream benchmark runs are optional heavy validation. Invart can verify complete external evidence artifacts, but local tests do not pretend that a partial sample is a full upstream benchmark result.
