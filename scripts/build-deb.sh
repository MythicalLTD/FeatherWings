#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

SRC_PATH="${SRC_PATH:-github.com/mythicalltd/featherwings}"
OUT_DIR="${OUT_DIR:-dist}"
ARCHES="${ARCHES:-amd64 arm64}"
PACKAGE_CHANNEL="${PACKAGE_CHANNEL:-prod}"
BASE_VERSION="${BASE_VERSION:-}"

if [[ -z "${BASE_VERSION}" ]]; then
  if git describe --tags --abbrev=0 >/dev/null 2>&1; then
    BASE_VERSION="$(git describe --tags --abbrev=0 | sed 's/^v//')"
  else
    BASE_VERSION="0.0.0"
  fi
fi

if [[ -z "${VERSION:-}" ]]; then
  if [[ "${PACKAGE_CHANNEL}" == "dev" ]]; then
    short_sha="$(git rev-parse --short HEAD 2>/dev/null || echo local)"
    stamp="$(date -u +%Y%m%d%H%M%S)"
    VERSION="${BASE_VERSION}~dev+${stamp}.${short_sha}"
  elif git describe --tags --exact-match >/dev/null 2>&1; then
    VERSION="$(git describe --tags --exact-match | sed 's/^v//')"
  else
    VERSION="${BASE_VERSION}"
  fi
fi

VERSION="${VERSION#v}"

case "${PACKAGE_CHANNEL}" in
  dev)
    NFPM_NAME="featherwings-dev"
    NFPM_CONFLICT="featherwings"
    ;;
  prod|*)
    NFPM_NAME="featherwings"
    NFPM_CONFLICT="featherwings-dev"
    ;;
esac

ensure_nfpm() {
  if command -v nfpm >/dev/null 2>&1; then
    return 0
  fi

  echo "nfpm not found; installing from Goreleaser apt repo..."
  if ! command -v sudo >/dev/null 2>&1; then
    echo "nfpm is required. Install it from https://nfpm.goreleaser.com/install/" >&2
    exit 1
  fi

  echo 'deb [trusted=yes] https://repo.goreleaser.com/apt/ /' | sudo tee /etc/apt/sources.list.d/goreleaser.list >/dev/null
  sudo apt-get update
  sudo apt-get install -y nfpm
}

mkdir -p "${OUT_DIR}"
ensure_nfpm

VERSION="${VERSION}" ./scripts/generate-deb-metadata.sh

echo "Building FeatherWings ${VERSION} (${NFPM_NAME}) for: ${ARCHES}"

: > "${OUT_DIR}/.deb-manifest"

for arch in ${ARCHES}; do
  echo ""
  echo "==> ${arch}"

  GOOS=linux GOARCH="${arch}" CGO_ENABLED=0 go build \
    -o "${OUT_DIR}/featherwings" \
    -v -trimpath \
    -ldflags="-s -w -X ${SRC_PATH}/system.Version=${VERSION}" \
    "${SRC_PATH}"
  chmod 755 "${OUT_DIR}/featherwings"

  cp "${OUT_DIR}/featherwings" "${OUT_DIR}/wings_linux_${arch}"
  chmod 755 "${OUT_DIR}/wings_linux_${arch}"

  NFPM_NAME="${NFPM_NAME}" \
  NFPM_CONFLICT="${NFPM_CONFLICT}" \
  NFPM_ARCH="${arch}" \
  NFPM_VERSION="${VERSION}" \
  nfpm pkg \
    --packager deb \
    --config nfpm.yaml \
    --target "${OUT_DIR}/"

  echo "${OUT_DIR}/${NFPM_NAME}_${VERSION}_${arch}.deb" >> "${OUT_DIR}/.deb-manifest"
done

echo "${VERSION}" > "${OUT_DIR}/.deb-version"
echo "${NFPM_NAME}" > "${OUT_DIR}/.deb-package"

echo ""
echo "Built packages:"
ls -lh "${OUT_DIR}"/*.deb "${OUT_DIR}"/wings_linux_* 2>/dev/null || true

if command -v sha256sum >/dev/null 2>&1; then
  (
    cd "${OUT_DIR}"
    sha256sum wings_linux_* *.deb > checksums.txt
  )
  echo ""
  echo "Checksums written to ${OUT_DIR}/checksums.txt"
fi
