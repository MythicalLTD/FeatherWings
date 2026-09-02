#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

REPO="${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
WORKDIR="${WORKDIR:-$(mktemp -d)}"
ARCHES="${ARCHES:-amd64 arm64}"
NEXUS_BLOCKED_VERSIONS="${NEXUS_BLOCKED_VERSIONS:-1.4.0}"

cleanup() {
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI (gh) is required." >&2
  exit 1
fi

if [[ -z "${NEXUS_USERNAME:-}" || -z "${NEXUS_PASSWORD:-}" ]]; then
  echo "NEXUS_USERNAME and NEXUS_PASSWORD must be set." >&2
  exit 1
fi

if ! command -v nfpm >/dev/null 2>&1; then
  echo "nfpm is required. Run ./scripts/build-deb.sh once to install it, or install nfpm manually." >&2
  exit 1
fi

is_blocked_version() {
  local version="$1"
  local blocked
  for blocked in ${NEXUS_BLOCKED_VERSIONS//,/ }; do
    blocked="${blocked#v}"
    if [[ "${version}" == "${blocked}" ]]; then
      return 0
    fi
  done
  return 1
}

mapfile -t release_tags < <(
  gh release list --repo "${REPO}" --limit 1000 --json tagName,isDraft \
    -q '.[] | select(.isDraft == false) | .tagName' | sort -Vr
)

if [[ "${#release_tags[@]}" -eq 0 ]]; then
  echo "No published releases found."
  exit 0
fi

uploaded=0
skipped=0
failed=0
built=0

echo "Backfilling .deb packages from GitHub release binaries (${#release_tags[@]} releases)"
echo "Blocked versions: ${NEXUS_BLOCKED_VERSIONS}"
echo ""

for tag in "${release_tags[@]}"; do
  version="${tag#v}"

  if is_blocked_version "${version}"; then
    echo "==> ${tag}: blocked, skipping"
    continue
  fi

  release_dir="${WORKDIR}/${tag}"
  mkdir -p "${release_dir}"

  echo "==> ${tag}: downloading release binaries"
  if ! gh release download "${tag}" --repo "${REPO}" \
    --pattern 'wings_linux_amd64' \
    --pattern 'wings_linux_arm64' \
    --dir "${release_dir}" 2>/dev/null; then
    echo "   missing wings_linux_* assets, skipping"
    continue
  fi

  for arch in ${ARCHES}; do
    binary="${release_dir}/wings_linux_${arch}"
    deb_name="featherwings_${version}_${arch}.deb"
    deb_path="${release_dir}/${deb_name}"

    if [[ ! -f "${binary}" ]]; then
      echo "   missing ${arch} binary, skipping"
      continue
    fi

    mkdir -p "${ROOT}/dist"
    cp -f "${binary}" "${ROOT}/dist/featherwings"
    chmod 755 "${ROOT}/dist/featherwings"

    VERSION="${version}" "${ROOT}/scripts/generate-deb-metadata.sh"

    NFPM_ARCH="${arch}" NFPM_VERSION="${version}" nfpm pkg \
      --packager deb \
      --config nfpm.yaml \
      --target "${release_dir}/"

    ((built++)) || true

    set +e
    "${ROOT}/scripts/nexus-upload-deb.sh" "${deb_path}"
    status=$?
    set -e
    case "${status}" in
      0) ((uploaded++)) || true ;;
      2) ((skipped++)) || true ;;
      *) ((failed++)) || true ;;
    esac

    sleep 2
  done

  echo ""
done

echo "Backfill complete. Built: ${built}, uploaded: ${uploaded}, skipped: ${skipped}, failed: ${failed}"

if [[ "${failed}" -gt 0 ]]; then
  exit 1
fi
