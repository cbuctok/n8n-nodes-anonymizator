# Commands, install and releasing

_Moved out of `AGENTS.md` (2026-11-05). Section names quoted in the text may now live in a sibling file under `docs/agents/`; `AGENTS.md` has the index._

## Commands

All node tooling goes through `@n8n/node-cli` (`n8n-node`), exposed as npm scripts.

| Command | What it does |
| --- | --- |
| `npm run lint` | `n8n-node lint`. Necessary but **not** the final gate; see `npm run scan`. |
| `npm run lint:fix` | Auto-fixes what it can. |
| `npm run build` | `n8n-node build`: clears `dist`, runs `tsc`, copies icons. |
| `npm run build:watch` | Raw `tsc --watch`. Does **not** copy icons, so they go missing in `dist/`. |
| `npm run dev` | `n8n-node dev`. Not used in this repo's workflow; Docker is (below). |
| `npm test` | `npm run build && node --test "test/*.test.mjs"`. Unit tests against `dist/`, no network. |
| `npm run check:fields` | `fixedCollection` consistency check (the node has none today; kept as a guard). |
| `npm run scan` | n8n's verification scanner on the source and on the packed tarball. **The real gate.** Needs `dist/`. |
| `npm run sbom` | `scripts/sbom.sh`: trivy SBOMs (SPDX + CycloneDX) of `package-lock.json` into the gitignored `sbom/`. Dev toolchain only; the published package has no runtime dependencies. Needs trivy. |
| `npm run smoke` | Drives the built node against the live production gateway, without n8n. Needs the API key. |
| `npm run e2e` | Drives the built node through a real n8n in Docker. Needs the API key and `n8n:up`. |
| `npm run n8n:up` / `n8n:logs` / `n8n:down` | Start (and wait for healthy), follow and stop the Docker n8n. |
| `npm run n8n:reset` | Wipes the n8n volume and starts clean. |
| `npm run release` | `scripts/release.mjs`: checks, version bump, changelog stub, commit, tag, push. Does not publish. Non-interactive: `npm run release -- --bump minor --notes-ready` (same checks and refusals; the notes must already be under `## Unreleased`). |

The usual pre-commit chain is:

```
npm run lint && npm test && npm run scan
```

and before a release also `npm run smoke` and `npm run n8n:reset && npm run e2e`.

**Install with a plain `npm ci` (or `npm install`), as CI does.** No flags are needed on Node 26 with
npm 11.19+ (checked 2026-10-05): there is no eslint peer conflict (`@n8n/node-cli` only asks for
`eslint >= 9`), npm 11 skips dependency install scripts that are not allowed (`npm install-scripts
ls`), and `isolated-vm` ships a Node 26 prebuild. On an older npm that runs install scripts, add
`--ignore-scripts` if a dependency's preinstall (`eslint-plugin-n8n-nodes-base` runs
`only-allow pnpm`) or a native build fails. Do not use `--force`; it hides real conflicts.

**Prettier is never invoked by a script.** The n8n lint config does not include
`eslint-config-prettier`, so run `npx prettier --write <file>` by hand on `.ts` and `.mjs` files.
`.prettierrc.js` is authoritative: **tabs**, single quotes, trailing commas, semicolons, print width
100, LF. Markdown is not run through Prettier.

### Releasing

`npm run release` runs lint, the unit tests, `check:fields` and the scanner, asks for the bump, writes
the version and a dated `## x.y.z - YYYY-MM-DD` changelog section, waits while you write the notes,
then commits `Release x.y.z`, tags `x.y.z` (no `v`) and pushes. Notes collect between releases
under `## Unreleased` in `CHANGELOG.md`; the script renames that heading to the dated version
section instead of inserting an empty one, so the notes are already there when it pauses. The README's "Version history" **Unreleased** bullet is rewritten to `**x.y.z** (date):` in the
same step, and `README.md` is part of the release commit. The heading match tolerates
`## [Unreleased]`, trailing spaces and CRLF; any other heading mentioning Unreleased is refused rather
than left outside the release section. `publish.yml` sees the tag, re-runs lint,
tests and the scanner on a clean checkout, and **stages** the package with a provenance
attestation. The version is not installable until a maintainer approves it at npmjs.com → package →
**Staged versions**. Nothing goes live from a tag alone.

The release script refuses on a dirty tree, a branch other than `dev`/`master`, being offline,
unpushed or unpulled commits, or a tag that already exists locally or on origin (checked with
`git ls-remote`, since `git fetch` does not see every remote tag), because a tag is a promise about
a commit. It bumps the version in `package.json` and both version fields of `package-lock.json`. The
notes are the one part that cannot be derived, so it stops for them and refuses to commit an empty
section (undo with `git checkout -- package.json package-lock.json CHANGELOG.md README.md`). The branch and the
tag go up in one `git push --atomic`, so either both land or neither does. Changelog bullets are past tense,
written for users, with operation names in bold. Run `npm run smoke` and `npm run e2e` yourself
before releasing anything that touches the gateway or the parameters; the script cannot (they need
the key and Docker).

**`n8n-node release` is not used, anywhere.** Locally it passes `-n` to `release-it`, which no
`release-it` major has accepted, so it fails before the first prompt; `@n8n/node-cli` does not even
depend on `release-it`. In CI it runs a plain `npm publish`, which goes live immediately and cannot be
redirected to the staging endpoint. `publish.yml` therefore runs the checks and `npm stage publish`
itself, which means the gate steps live in both `ci.yml` and `publish.yml`: change one, check the
other.

`RELEASE_MODE: 'true'` in `publish.yml` satisfies the `prepublishOnly: n8n-node prerelease` guard,
which otherwise refuses any publish. Keep the guard: it stops a hand-run `npm publish`.

One-time npm setup (Trusted Publishing over OIDC, no `NPM_TOKEN`) is described at the top of
`.github/workflows/publish.yml`. Both "Allow npm stage publish" **and** "Allow npm publish" must be
enabled; without the second the OIDC exchange succeeds and the upload fails with "OIDC permission
denied for this action". n8n requires community nodes to be published from GitHub Actions with
provenance since 1 May 2026.

**Publishing goes through GitHub Actions only.** Never run `npm publish` or `npm stage publish` by
hand. The single exception is already spent: npm only lets you add a trusted publisher to a package
that already exists, so `0.1.0` was published by hand on 2026-10-06 from a clean clone of tag `0.1.0`
(`6c6f86b`). It has no provenance attestation, so submit a later, CI-staged version for n8n
verification, never `0.1.0`.

CI (`ci.yml`) runs on pull requests and on pushes to `master`: `npm ci`, lint, `npm test`,
`check:fields`, `npm run scan`. The scan step installs the scanner from the npm registry, which the
GitHub runner can reach. Smoke and e2e need the real API key and are never run in CI. The
pull-request trigger is a GitHub Actions fact only: agents never open PRs; work lands by a local
`--no-ff` merge into `dev`, then `master` is fast-forwarded from `dev`.

