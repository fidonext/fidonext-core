#!/usr/bin/env sh
set -eu

# Build and push relay image to Docker Hub.
# Example:
#   DOCKERHUB_REPO=myuser/fidonext-relay IMAGE_TAG=v0.1.0 ./publish_dockerhub.sh

DOCKERHUB_REPO="${DOCKERHUB_REPO:-}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
IMAGE_PLATFORM="${IMAGE_PLATFORM:-linux/amd64}"

if [ -z "${DOCKERHUB_REPO}" ]; then
  echo "error: set DOCKERHUB_REPO, for example myuser/fidonext-relay" >&2
  exit 1
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/../../.." && pwd)"
IMAGE="${DOCKERHUB_REPO}:${IMAGE_TAG}"

echo "[publish] repo root: ${REPO_ROOT}"
echo "[publish] image: ${IMAGE}"
echo "[publish] platform: ${IMAGE_PLATFORM}"
echo "[publish] ensure docker login is already completed"

docker build --platform "${IMAGE_PLATFORM}" \
  -f "${REPO_ROOT}/c-abi-libp2p/deploy/relay/Dockerfile" \
  -t "${IMAGE}" \
  "${REPO_ROOT}"

docker push "${IMAGE}"

echo "[publish] done: docker pull ${IMAGE}"
