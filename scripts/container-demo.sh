#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${INVART_DEMO_IMAGE:-invart/container-risk-demo:py311}"
BASE_IMAGE="${INVART_TEST_BASE_IMAGE:-python:3.11-slim}"
FALLBACK_BASE_IMAGE="${INVART_TEST_FALLBACK_BASE_IMAGE:-swebench/sweb.eval.x86_64.django_1776_django-11001:latest}"
MODE="${1:-all}"
OUT_DIR="${2:-.invart/container-risk-demo}"

if [[ "$MODE" == "help" || "$MODE" == "--help" || "$MODE" == "-h" ]]; then
  echo "usage: $0 [all|unfriendly-skill|secret-egress|unsafe-delete] [out_dir]" >&2
  exit 0
fi

mkdir -p "$OUT_DIR"
OUT_ABS="$(cd "$OUT_DIR" && pwd)"

if ! docker build --build-arg BASE_IMAGE="$BASE_IMAGE" -f "$ROOT/Dockerfile.test" -t "$IMAGE" "$ROOT"; then
  if docker image inspect "$FALLBACK_BASE_IMAGE" >/dev/null 2>&1; then
    echo "default base image build failed; retrying with local fallback image: $FALLBACK_BASE_IMAGE" >&2
    docker build --build-arg BASE_IMAGE="$FALLBACK_BASE_IMAGE" -f "$ROOT/Dockerfile.test" -t "$IMAGE" "$ROOT"
  else
    echo "container demo image build failed and fallback image is unavailable: $FALLBACK_BASE_IMAGE" >&2
    exit 1
  fi
fi

case "$MODE" in
  all)
    cases=(unfriendly-skill secret-egress unsafe-delete)
    ;;
  unfriendly-skill|secret-egress|unsafe-delete)
    cases=("$MODE")
    ;;
  *)
    echo "usage: $0 [all|unfriendly-skill|secret-egress|unsafe-delete] [out_dir]" >&2
    exit 2
    ;;
esac

run_args=(
  --rm
  --user "$(id -u):$(id -g)"
  -e HOME=/tmp/invart-home
  -e PYTHONPATH=src
  -e PYTHONDONTWRITEBYTECODE=1
  -e INVART_CONTAINER_DEMO=1
  -e INVART_CONTAINER_DEMO_IMAGE="$IMAGE"
  -v "$ROOT:/workspace:ro"
  -v "$OUT_ABS:/out"
  -w /workspace
)

for case_id in "${cases[@]}"; do
  echo "container-risk-case: $case_id"
  docker run "${run_args[@]}" -e INVART_CONTAINER_DEMO_CASE="$case_id" "$IMAGE" bash -lc '
    set -euo pipefail
    mkdir -p "$HOME" "/out/$INVART_CONTAINER_DEMO_CASE"
    python -m invart.cli demo container-risk-case \
      --case "$INVART_CONTAINER_DEMO_CASE" \
      --out-dir "/out/$INVART_CONTAINER_DEMO_CASE" \
      > "/out/$INVART_CONTAINER_DEMO_CASE/stdout.json"
  '
done

docker run "${run_args[@]}" -e INVART_CONTAINER_DEMO_CASE=summary "$IMAGE" bash -lc '
  set -euo pipefail
  mkdir -p "$HOME"
  python -m invart.cli demo container-risk-suite \
    --out-dir /out \
    --collect-existing \
    > /out/container-risk-suite.stdout.json
'

echo "container-risk-demo: pass"
echo "entrypoint: $OUT_ABS/container-risk-suite.html"
