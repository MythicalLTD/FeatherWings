#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

VERSION="${VERSION:-}"
if [[ -z "${VERSION}" ]]; then
  if git describe --tags --exact-match >/dev/null 2>&1; then
    VERSION="$(git describe --tags --exact-match | sed 's/^v//')"
  elif git describe --tags >/dev/null 2>&1; then
    VERSION="$(git describe --tags | sed 's/^v//')"
  else
    VERSION="dev"
  fi
fi

VERSION="${VERSION#v}"
TAG="v${VERSION}"
MAINTAINER="${DEB_MAINTAINER:-MythicalSystems <support@mythicalsystems.org>}"
METAINFO="${ROOT}/packaging/featherwings.metainfo.xml"
CHANGELOG_YAML="${ROOT}/packaging/changelog.yaml"
CHANGELOG_MD="${ROOT}/CHANGELOG.md"

extract_release_notes() {
  local notes=""
  if [[ ! -f "${CHANGELOG_MD}" ]]; then
    return 0
  fi

  notes="$(
    awk -v tag="${TAG}" '
      $0 ~ "^## " tag "$" { capture=1; next }
      capture && /^## / { exit }
      capture && /^### / {
        section=$0
        sub(/^### /, "", section)
        if (section != "") {
          printf("%s:\n", section)
        }
        next
      }
      capture && /^[-*] / {
        sub(/^[-*] /, "", $0)
        print
      }
    ' "${CHANGELOG_MD}" \
      | head -n 40
  )"

  if [[ -z "${notes}" ]]; then
    notes="See CHANGELOG.md for release notes."
  fi

  printf '%s' "${notes}"
}

release_date() {
  local date=""
  if date="$(git log -1 --format=%cs "refs/tags/${TAG}" 2>/dev/null)" && [[ -n "${date}" ]]; then
    printf '%s' "${date}"
    return 0
  fi

  if date="$(git log -1 --format=%cs "HEAD" 2>/dev/null)" && [[ -n "${date}" ]]; then
    printf '%s' "${date}"
    return 0
  fi

  date -u +%Y-%m-%d
}

escape_xml() {
  sed \
    -e 's/&/\&amp;/g' \
    -e 's/</\&lt;/g' \
    -e 's/>/\&gt;/g' \
    -e 's/"/\&quot;/g' \
    -e "s/'/\&apos;/g"
}

notes="$(extract_release_notes)"
date="$(release_date)"
iso_date="${date}T00:00:00Z"

mapfile -t note_lines < <(printf '%s\n' "${notes}")

{
  printf '%s\n' "- semver: ${VERSION}"
  printf '%s\n' "  date: ${iso_date}"
  printf '%s\n' "  packager: ${MAINTAINER}"
  printf '%s\n' "  changes:"
  for line in "${note_lines[@]}"; do
    [[ -z "${line}" ]] && continue
    printf '%s\n' "    - note: |-"
    printf '%s\n' "        ${line}"
  done
} > "${CHANGELOG_YAML}"

{
  cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<component type="service">
  <id>org.mythicalsystems.FeatherWings</id>
  <name>FeatherWings</name>
  <summary>Server control plane for FeatherPanel</summary>
  <metadata_license>CC0-1.0</metadata_license>
  <project_license>MIT</project_license>
  <developer_name>MythicalSystems</developer_name>
  <launchable type="service-name">featherwings.service</launchable>
  <url type="homepage">https://github.com/mythicalltd/featherwings</url>
  <url type="bugtracker">https://github.com/mythicalltd/featherwings/issues</url>
  <url type="vcs-browser">https://github.com/mythicalltd/featherwings</url>
  <icon type="local">org.mythicalsystems.FeatherWings</icon>
  <categories>
    <category>System</category>
  </categories>
  <keywords>
    <keyword>featherpanel</keyword>
    <keyword>game-server</keyword>
    <keyword>docker</keyword>
    <keyword>wings</keyword>
  </keywords>
  <description>
    <p>
      FeatherWings is FeatherPanel&apos;s server control plane, built for the
      rapidly changing gaming industry and designed to be highly performant and
      secure.
    </p>
    <p>
      It provides an HTTP API for managing running game servers, fetching logs,
      generating backups, and controlling the full server lifecycle. A built-in
      SFTP server lets users authenticate with the same credentials they use in
      the panel.
    </p>
    <p>Features include:</p>
    <ul>
      <li>Docker-based game server lifecycle management</li>
      <li>HTTP API and built-in SFTP access</li>
      <li>Backup and restore integrations, including Proxmox Backup Server</li>
      <li>Interactive first-run configuration via <code>featherwings configure</code></li>
      <li>systemd service integration for production deployments</li>
    </ul>
  </description>
  <release version="${VERSION}" date="${date}">
    <description>
EOF

  for line in "${note_lines[@]}"; do
    [[ -z "${line}" ]] && continue
    printf '      <p>%s</p>\n' "$(printf '%s' "${line}" | escape_xml)"
  done

  cat <<EOF
    </description>
  </release>
  <content_rating type="oars-1.1"/>
</component>
EOF
} > "${METAINFO}"

echo "Generated ${METAINFO} and ${CHANGELOG_YAML} for version ${VERSION}"
