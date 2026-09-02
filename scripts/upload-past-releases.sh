#!/usr/bin/env bash
set -euo pipefail

echo "This script now builds .deb packages from GitHub release binaries."
echo "Run ./scripts/backfill-release-debs.sh instead."
echo ""

exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/backfill-release-debs.sh" "$@"
