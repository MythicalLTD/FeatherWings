#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

OUT_DIR="${OUT_DIR:-dist}"
MANIFEST="${OUT_DIR}/.deb-manifest"

deb_files=()

if [[ -f "${MANIFEST}" ]]; then
  while IFS= read -r line; do
    [[ -n "${line}" && -f "${line}" ]] && deb_files+=("${line}")
  done < "${MANIFEST}"
fi

if [[ "${#deb_files[@]}" -eq 0 ]]; then
  shopt -s nullglob
  if [[ -n "${VERSION:-}" ]]; then
    VERSION="${VERSION#v}"
    deb_files=("${OUT_DIR}/featherwings_${VERSION}"_*.deb)
  else
    echo "No ${MANIFEST} found and VERSION is unset; refusing to upload every .deb in ${OUT_DIR}." >&2
    echo "Run ./scripts/build-deb.sh first, or set VERSION explicitly." >&2
    exit 1
  fi
fi

if [[ "${#deb_files[@]}" -eq 0 ]]; then
  echo "No .deb files to upload." >&2
  exit 1
fi

echo "Uploading ${#deb_files[@]} package(s) to Nexus..."

for deb_file in "${deb_files[@]}"; do
  set +e
  "${ROOT}/scripts/nexus-upload-deb.sh" "${deb_file}"
  status=$?
  set -e
  if [[ "${status}" -eq 1 ]]; then
    exit 1
  fi
  sleep 2
done

echo "Upload complete."
