#!/usr/bin/env bash
# Software bills of materials into sbom/ (generated, gitignored, not published:
# package.json "files" ships only dist/ and NOTICE).
#
#   sbom/dev-toolchain.spdx.json trivy SBOMs of package-lock.json: the dev/test
#   sbom/dev-toolchain.cdx.json  toolchain (@n8n/node-cli, eslint, typescript, …) and
#                                the n8n-workflow peer, all NOT shipped (hence
#                                --include-dev-deps).
#
# The published package has no runtime dependencies: n8n-workflow is a peer the
# n8n instance provides, so its transitive packages (axios, …) are the n8n
# instance's, not this package's.
#
# Needs: trivy.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p sbom

echo "→ trivy fs package-lock.json (SPDX 2.3, dev toolchain)"
trivy fs --skip-version-check --quiet --include-dev-deps --format spdx-json \
  --output sbom/dev-toolchain.spdx.json package-lock.json
echo "→ trivy fs package-lock.json (CycloneDX, dev toolchain)"
trivy fs --skip-version-check --quiet --include-dev-deps --format cyclonedx \
  --output sbom/dev-toolchain.cdx.json package-lock.json

echo "✔ sbom/: dev-toolchain.spdx.json dev-toolchain.cdx.json"
