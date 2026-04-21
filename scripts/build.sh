#!/usr/bin/env bash
set -euo pipefail

is_true() {
  case "${1,,}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

IMAGE_NAME="${IMAGE_NAME:-seal-key-server}"
PUSH="${PUSH:-false}"
NO_CACHE="${NO_CACHE:-false}"
DOCKERFILE="${DOCKERFILE:-${ROOT_DIR}/Dockerfile}"
CONTEXT_DIR="${CONTEXT_DIR:-${ROOT_DIR}}"
GIT_REVISION="${GIT_REVISION:-$(git -C "${ROOT_DIR}" describe --always --abbrev=12 --dirty --exclude '*')}"

declare -a image_refs=()

if [[ -n "${IMAGE_REFS:-}" ]]; then
  while IFS= read -r ref; do
    [[ -n "${ref}" ]] && image_refs+=("${ref}")
  done <<< "${IMAGE_REFS}"
elif [[ -n "${IMAGE_TAGS:-}" ]]; then
  while IFS= read -r tag; do
    [[ -n "${tag}" ]] && image_refs+=("${IMAGE_NAME}:${tag}")
  done < <(printf '%s\n' "${IMAGE_TAGS}" | tr ',[:space:]' '\n')
else
  image_refs+=("${IMAGE_NAME}:latest")
fi

build_cmd=(
  docker
  build
  --file "${DOCKERFILE}"
  --build-arg "GIT_REVISION=${GIT_REVISION}"
)

if is_true "${NO_CACHE}"; then
  build_cmd+=(--no-cache)
fi

for image_ref in "${image_refs[@]}"; do
  build_cmd+=(--tag "${image_ref}")
done

build_cmd+=("${CONTEXT_DIR}")

echo "Building Docker image(s):"
printf '  %s\n' "${image_refs[@]}"
echo "Git revision: ${GIT_REVISION}"

"${build_cmd[@]}"

if is_true "${PUSH}"; then
  echo "Pushing Docker image(s):"
  for image_ref in "${image_refs[@]}"; do
    echo "  ${image_ref}"
    docker push "${image_ref}"
  done
fi
