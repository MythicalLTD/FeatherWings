#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

SRC_PATH="${SRC_PATH:-github.com/mythicalltd/featherwings}"
OUT_DIR="${OUT_DIR:-dist}"
ARCHES="${ARCHES:-amd64 arm64}"

if [[ -z "${VERSION:-}" ]]; then
  if git describe --tags --exact-match >/dev/null 2>&1; then
    VERSION="$(git describe --tags --exact-match | sed 's/^v//')"
  elif git describe --tags >/dev/null 2>&1; then
    VERSION="$(git describe --tags | sed 's/^v//')"
  else
    VERSION="dev-$(git rev-parse --short HEAD 2>/dev/null || echo local)"
  fi
fi

VERSION="${VERSION#v}"

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

echo "Building FeatherWings ${VERSION} for: ${ARCHES}"

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

  NFPM_ARCH="${arch}" NFPM_VERSION="${VERSION}" nfpm pkg \
    --packager deb \
    --config nfpm.yaml \
    --target "${OUT_DIR}/"

  echo "${OUT_DIR}/featherwings_${VERSION}_${arch}.deb" >> "${OUT_DIR}/.deb-manifest"
done

echo "${VERSION}" > "${OUT_DIR}/.deb-version"

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
