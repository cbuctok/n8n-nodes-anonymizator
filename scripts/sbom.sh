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
#   sbom/vendored.cdx.json       the third-party code that IS shipped, vendored as
#                                source (EXPERIMENTAL protocol v3): @noble/post-quantum,
#                                @noble/hashes and @noble/curves with versions, tarball
#                                hashes and the vendored files, from vendor-noble.lock.json
#                                (trivy cannot see it: it is in no lockfile).
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

echo "→ vendor-noble.lock.json (CycloneDX 1.5, vendored source)"
node --input-type=module - <<'JS'
import { readFileSync, writeFileSync } from 'node:fs';
const lock = JSON.parse(readFileSync('vendor-noble.lock.json', 'utf8'));
const bom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  version: 1,
  metadata: { component: { type: 'library', name: 'n8n-nodes-anonymizator (vendored code)' } },
  components: lock.packages.map((p) => ({
    type: 'library',
    'bom-ref': `pkg:npm/${p.name.replace('@', '%40')}@${p.version}`,
    name: p.name,
    version: p.version,
    purl: `pkg:npm/${p.name.replace('@', '%40')}@${p.version}`,
    licenses: [{ license: { id: p.license } }],
    hashes: [{ alg: 'SHA-256', content: p.tarball_sha256 }],
    externalReferences: [{ type: 'distribution', url: p.tarball_url }],
    properties: p.source_files
      .filter((f) => f.output)
      .map((f) => ({ name: `vendored:${f.path}`, value: `${f.output} (upstream sha256 ${f.sha256})` })),
  })),
};
writeFileSync('sbom/vendored.cdx.json', JSON.stringify(bom, null, 2) + '\n');
JS

echo "✔ sbom/: dev-toolchain.spdx.json dev-toolchain.cdx.json vendored.cdx.json"
