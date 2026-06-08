#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${INVART_TEST_IMAGE:-invart/container-test:py311}"
BASE_IMAGE="${INVART_TEST_BASE_IMAGE:-python:3.11-slim}"
FALLBACK_BASE_IMAGE="${INVART_TEST_FALLBACK_BASE_IMAGE:-swebench/sweb.eval.x86_64.django_1776_django-11001:latest}"
MODE="${1:-local}"
if [[ $# -gt 0 ]]; then
  shift
fi

if ! docker build --build-arg BASE_IMAGE="$BASE_IMAGE" -f "$ROOT/Dockerfile.test" -t "$IMAGE" "$ROOT"; then
  if docker image inspect "$FALLBACK_BASE_IMAGE" >/dev/null 2>&1; then
    echo "default base image build failed; retrying with local fallback image: $FALLBACK_BASE_IMAGE" >&2
    docker build --build-arg BASE_IMAGE="$FALLBACK_BASE_IMAGE" -f "$ROOT/Dockerfile.test" -t "$IMAGE" "$ROOT"
  else
    echo "container image build failed and fallback image is unavailable: $FALLBACK_BASE_IMAGE" >&2
    exit 1
  fi
fi

run_args=(
  --rm
  --user "$(id -u):$(id -g)"
  -e HOME=/tmp/invart-home
  -e PYTHONPATH=src
  -v "$ROOT:/workspace"
  -w /workspace
)

if [[ -S /var/run/docker.sock ]]; then
  run_args+=(-v /var/run/docker.sock:/var/run/docker.sock)
fi

case "$MODE" in
  local)
    docker run "${run_args[@]}" "$IMAGE" bash -lc '
      set -euo pipefail
      mkdir -p "$HOME" .invart/container-test
      python -m pytest -q
      python -m invart.cli eval benchmark --suite v0.40-swe-bench-full-validation-contract > .invart/container-test/v0.40-swe-bench-contract.json
      python -m invart.cli eval benchmark --suite full-product-readiness > .invart/container-test/full-product-readiness.json
      python -m invart.cli roadmap status --require-full > .invart/container-test/roadmap-full.json
      python -m invart.cli release-candidate verify --out-dir .invart/container-test/rc --skip-pytest > .invart/container-test/rc.json
      set +e
      python -m invart.cli roadmap status --require-external-validation > .invart/container-test/roadmap-external-validation.json
      external_status=$?
      set -e
      if [[ "$external_status" -eq 0 ]]; then
        echo "roadmap external validation unexpectedly passed before external-heavy evidence was attached" >&2
        exit 1
      fi
      echo "container-local-suite: pass"
    '
    ;;
  swe-bench-full)
    predictions_path="${1:-gold}"
    run_id="${2:-invart_full_$(date -u +%Y%m%d_%H%M%S)}"
    out_dir="${3:-.invart/swe-bench-full}"
    docker run "${run_args[@]}" "$IMAGE" bash -lc '
      set -euo pipefail
      mkdir -p "$HOME" "'"$out_dir"'"
      python -m invart.cli external-validation swe-bench-full \
        --python python \
        --predictions-path "'"$predictions_path"'" \
        --run-id "'"$run_id"'" \
        --work-dir "'"$out_dir"'" \
        --max-workers "${INVART_SWEBENCH_MAX_WORKERS:-4}" \
        --timeout "${INVART_SWEBENCH_TIMEOUT:-1800}" \
        --cache-level "${INVART_SWEBENCH_CACHE_LEVEL:-env}" \
        --out "'"$out_dir"'/full-validation.json"
    '
    ;;
  shell)
    docker run -it "${run_args[@]}" "$IMAGE" bash
    ;;
  *)
    echo "usage: $0 [local|swe-bench-full [predictions_path] [run_id] [out_dir]|shell]" >&2
    exit 2
    ;;
esac
