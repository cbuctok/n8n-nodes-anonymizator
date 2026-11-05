# n8n-nodes-anonymizator

Shared prosecco37 rules (git flow, no PRs, no attribution, secrets, safety, shell, context hygiene)
come from the umbrella `~/repos/prosecco37/AGENTS.md`. This file has only what is specific to this
repo; reference detail lives in `docs/agents/` (index at the end).

## Quick facts

- **What**: n8n community node (npm `n8n-nodes-anonymizator`) for the Anonymizator privacy gateway.
- **Test**: `npm run lint && npm test && npm run scan` (scan is the real gate); `smoke`/`e2e` need the API key.
- **Build**: `npm ci`, then `npm run build` (`n8n-node build` into `dist/`).
- **Release**: `npm run release` (bumps, tags, pushes) → `publish.yml` **stages** on npm; a maintainer approves. Never publish by hand; ask before any release.
- **Branch flow**: feature branch → `git merge --no-ff` into `dev` → fast-forward `master` (release branch) from `dev`. Remote is GitHub.
- **Secrets**: only the gateway key in `.env.dev` (`ANON_API_KEY`); never print or commit it (see "The API key").
- **Ships**: only `dist/` and `NOTICE` (`files` in `package.json`); `.claude/`, `docs/`, `test/`, `examples/` never ship.

An n8n community node package for the Anonymizator privacy gateway. **Protect** replaces personal
data in text with placeholders before the text reaches an LLM; **Reveal** puts the original values
back; **Detect** reports what a text contains without changing it. Only detection runs remotely:
the text is HPKE-sealed (protocol v2, or post-quantum v3 where Node.js has native ML-KEM) to a
stateless, ranges-only gateway that answers with entity positions. Substitution, the ID set and
placeholder map, companies, Additionally Protect, possible IDs, masking and reveal all happen inside
n8n, in a TypeScript port of the Anonymizator browser extension's Protect pipeline. The node is
meant to pass n8n's community-node verification, like its accepted sibling `n8n-nodes-judgment`.

Start with `README.md` for what the node does. This file covers how to work on it.

## Frozen names

Full table (wire strings, trust roots, headers, credential fields, output values):
`docs/agents/identifiers.md`. Read it before renaming anything. The rules:

- Package `n8n-nodes-anonymizator` (unscoped, stays unscoped; no `publishConfig.access`), node
  `anonymizator`, credential `anonymizatorApi`, codex id `n8n-nodes-anonymizator.anonymizator`,
  gateway `https://anon.prosecco37.com` (no base URL field, on purpose).
- Parameter names, option values and output field names are stored in saved workflows: adding is
  fine, renaming breaks users. Display names may change. New options default to the old behaviour.
- `n8n.nodes` / `n8n.credentials` in `package.json` point at `dist/` paths and are edited by hand
  on a rename; a stale entry makes the node silently disappear.
- Wire strings and pinned roots are shared with the gateway and the extension (`lib/hpke.js`,
  `lib/gateway.js`, `lib/constants.js`). One changed byte breaks every request
  (`hpke_open_failed`) or every keyconfig/capabilities verification.

## Commands

All node tooling goes through `@n8n/node-cli` (`n8n-node`), exposed as npm scripts. Details,
install notes and the full release procedure: `docs/agents/commands-and-releasing.md`.

| Command | What it does |
| --- | --- |
| `npm run lint` / `lint:fix` | `n8n-node lint`. Necessary, **not** the final gate. |
| `npm run build` | Clears `dist`, runs `tsc`, copies icons (`build:watch` does not copy icons). |
| `npm test` | Build, then `node --test "test/*.test.mjs"` against `dist/`, offline. |
| `npm run check:fields` | `fixedCollection` consistency guard. |
| `npm run scan` | n8n's verification scanner on source and packed tarball. **The real gate.** Needs `dist/`. |
| `npm run sbom` | trivy SBOMs of the dev toolchain into gitignored `sbom/`. |
| `npm run smoke` | Built node against the **production** gateway, no n8n. Needs the key. |
| `npm run e2e` | Built node in a real Docker n8n (`n8n:up` first; `n8n:reset` before believing a run). |
| `npm run release` | Checks, bump, changelog, commit, tag, **push**. Outward-facing: only when the user asks. |

- Install with a plain `npm ci`; never `--force`. `npm audit fix` and `overrides` are banned (the
  first broke judgment's lint, the second fails `no-overrides-field`).
- Prettier is never run by a script: `npx prettier --write <file>` by hand on `.ts`/`.mjs`
  (`.prettierrc.js`: tabs, single quotes, width 100). Markdown is not prettier-formatted.
- Release notes collect under `## Unreleased` in `CHANGELOG.md` (past tense, for users, operation
  names in bold). Tags are `x.y.z` without `v`.
- `n8n-node release` is never used; `publish.yml` runs the checks and `npm stage publish` itself, so
  the gate steps live in both `ci.yml` and `publish.yml`: change one, check the other.
- CI (`ci.yml`) runs on pull requests and on pushes to `master` (a GitHub Actions fact). **Agents
  never open PRs**: land with the umbrella flow (feature branch → `--no-ff` into `dev` →
  fast-forward `master`).
- Don't release when the shipped artifact would not change (for example a dev-toolchain-only
  lockfile bump): the package has no runtime dependencies, so such bumps need no npm version.

## Testing in short

Four layers (unit, smoke, e2e, scan), each catching what the others cannot; a green run of one is
not evidence for the others. Read `docs/agents/testing.md` before changing tests or examples. Traps:

- Extension differential/interop tests **skip, not fail**, without the extension checkout:
  `ANON_EXT_DIR` (the `anonymizator-chrome-ext` subdirectory) or
  `/home/ubuntu/repos/prosecco37/anonymizator-chrome/anonymizator-chrome-ext`. Look for
  `# SKIP extension checkout not found` in tap output when checking drift.
- Tests live in `test/`, never under `nodes/` (compiled, shipped and scanned).
- `smoke` builds parameters by hand and never exercises n8n's parameter resolution; `smoke` and
  `e2e` depend on server-side detection. Only synthetic data is ever sent.
- Verify an e2e run by node coverage (`docker compose logs n8n | grep 'Running node'`, all 19
  nodes), not exit status. The Docker n8n binds `127.0.0.1:5678` only; keep it that way.
- Node 22 skips the native ML-KEM cases; Node ≥ 24.7 runs them.

## The API key

The real gateway key lives in `.env.dev` at the repo root as `ANON_API_KEY=...`. `smoke` and `e2e`
read `process.env.ANON_API_KEY` first and fall back to parsing that file.

- **Never print it.** No `cat .env.dev`, no `env` dumps, no logging the credential. Both scripts pass
  everything they print through a redaction step. To check the key did not leak, grep for it
  silently (`grep -rqF -- "$ANON_API_KEY" ...`) and report only the hit count.
- **Never commit it.** `.gitignore` has `.env*`. The package ships only `dist/`.
- **Never mount the repo into Docker.** `docker-compose.yml` mounts only `./dist` and
  `./package.json`, because mounting the whole repo would put `.env.dev` inside the container. The
  e2e script creates the credential over n8n's REST API instead.
- The key is a Zitadel service-user token (`user` role on Anonymizator), sent as
  `Authorization: Bearer <key>` to the BFF in front of the gateway. Customers manage keys in the
  Prosecco 37 Anonymizator user portal, which has no public URL yet: every place it belongs carries
  `TODO(api-key-portal)`.

## Crypto and post-quantum policy

- The gateway is ranges-only and stateless; trust roots are pinned Ed25519 keys with a signed
  delegation chain, fail-closed. Detail and the status mapping: `docs/agents/crypto-and-gateway.md`.
- Encryption setting (credential field `postQuantum`, shown as **Encryption**): **Automatic**
  (default) uses v3 only with native ML-KEM (`node:crypto`, Node ≥ 24.7) and v2 otherwise;
  **Always Post-Quantum (Experimental)** uses native, else the vendored `@noble/post-quantum`, and
  fails closed. The output field `encryption` reports `v3-native`, `v3-noble`, `v2` or `none`.
- Policy (decided 2026-11-05): crypto that relies on an unaudited library (noble ML-KEM) stays
  experimental and opt-in, never the default, until an independent audit or a native audited
  implementation exists. Detail: `docs/agents/post-quantum-v3.md`.

## Lint and scanner, in short

All found by real failures; do not undo them. Full list: `docs/agents/lint-and-scanner.md`.

- The scanner (`@n8n/scan-community-package`) is stricter than local lint and **ignores
  `eslint-disable`**; there are no suppressions in this repo, keep it that way.
- `no-hardcoded-secrets` checks constant **names** (`key`, `token`, `auth`, ...) holding
  base64/hex-looking strings; hence `TRUST_ROOTS_B64URL`, `KC_DOCUMENT_HEADER`.
- Banned in `nodes/`: `globalThis`, `process`, `setTimeout` and friends, `__dirname`, `eval`,
  `new Function`, `child_process`; no `throw` lexically inside a `catch` unless `NodeApiError` /
  `NodeOperationError`. Every returned item carries `pairedItem`.
- `eslint.config.mjs` and `tsconfig.json` are byte-for-byte the CLI template's; do not edit them.
- Comments in `nodes/`, `credentials/`, `scripts/`, `test/` are English only.
- The codex `node` id and categories are what verification review bounces on; both are pinned by
  `test/scaffold.test.mjs`.

## Working on this node

- Read the relevant doc in `docs/agents/` before touching crypto, the gateway or the map formats.
  The wire format and the ID file are shared contracts; the extension is the reference
  implementation.
- A new parameter: add it to the action's description with `displayOptions` for its operation, read
  it in `execute*`, add a unit test in `test/node.test.mjs`, a smoke scenario if it changes what is
  sent, and a node in the e2e workflow if it involves expressions or collections. Then update the
  README's parameter tables, the "What leaves n8n" table if it changes what is sent, and the
  `## Unreleased` section of `CHANGELOG.md`.
- Defaults: never put another node's name in a default expression (users rename nodes, and a wrong
  prefilled expression resolves to nothing without an error). Show the usual expressions in `hint`
  or `placeholder` instead, as Reveal does; required fields stay empty so n8n flags them.
- A new gateway status or error code: add it to `KNOWN_ERROR_CODES` (plain JSON) or
  `SEALED_ERROR_CODES` (sealed) in `gateway.ts` only if the extension's lists have it, the
  `GatewayErrorCode` union in `errors.ts`, `GATEWAY_MESSAGES` (and `LOCAL_FAILURES` if decided
  client-side) in `shared/gatewayMessages.ts` with the extension's wording, and a fake-gateway test
  in `test/gateway.test.mjs`.
- A new entity type usually needs no release: the gateway's signed capabilities add it to the list.
  Add a bundled row to `ENTITY_CATALOG` only when the extension adds one, in its order, with its
  label and groups, then the entities test.
- Error messages are user-facing English: say what happened and how to fix it, avoid the words
  "error", "problem" and "failure", and never include a protected value.
- Porting more extension code: follow `docs/agents/extension-sync.md` and keep `NOTICE` in step.
- Done means: `npm run lint && npm test && npm run scan`, plus `npm run smoke` for anything touching
  the gateway, and `npm run n8n:reset && npm run e2e` for anything touching parameters.

## Licence

MIT, © 2026 Greg Evseev (`LICENSE.md`). The code ported from the Anonymizator browser extension
(`anonymizer.js`, `hpke.js`, the gateway and capabilities logic, the chunker, `entities.js`, the ID
set model and rules, the Protect pipeline, Additionally Protect, possible IDs, the error wording, the
ID file format) is © 2026 Prosecco 37 d.o.o. and contributed under the MIT licence with permission
(decided 2026-10-05). `NOTICE` records this and ships in the npm package (`files` lists it).

## Read before X (docs/agents/)

| Before you... | Read |
| --- | --- |
| rename or add a name, wire string, credential field or output value | `docs/agents/identifiers.md` |
| install, change scripts, CI or publish workflows, or release | `docs/agents/commands-and-releasing.md` |
| change tests, the e2e workflow or `examples/` | `docs/agents/testing.md` |
| move files or look for where something lives | `docs/agents/architecture.md` |
| touch HPKE, keyconfig, trust roots, status mapping, offsets, caches | `docs/agents/crypto-and-gateway.md` |
| touch v3, the Encryption setting or the vendored noble code | `docs/agents/post-quantum-v3.md` |
| touch placeholder styles, map formats, Reveal, ID file, Detect, entity catalog | `docs/agents/placeholders-and-maps.md` |
| port or re-sync code from the extension | `docs/agents/extension-sync.md` |
| hit a lint/scanner failure or touch dependencies | `docs/agents/lint-and-scanner.md` |
| prepare the verification submission or the next release | `docs/agents/open-items.md`, `docs/verification-submission.md` |
| write README/submission wording that compares with other nodes | `docs/agents/positioning.md` |

## Reference docs

- n8n node building: <https://docs.n8n.io/connect/create-nodes/overview>,
  <https://docs.n8n.io/connect/create-nodes/build-your-node/reference/ux-guidelines>,
  <https://docs.n8n.io/connect/create-nodes/build-your-node/reference/verification-guidelines>,
  <https://docs.n8n.io/connect/create-nodes/deploy-your-node/submit-community-nodes>.
- The `@n8n/node-cli` tarball ships canonical agent docs under
  `dist/template/templates/shared/default/.agents/` (`nodes.md`, `properties.md`, `credentials.md`,
  `versioning.md`).
- HPKE: RFC 9180 <https://www.rfc-editor.org/rfc/rfc9180>; HKDF: RFC 5869.
- The extension (`/home/ubuntu/repos/prosecco37/anonymizator-chrome`): its `AGENTS.md`,
  `BROWSER_EXTENSION_SPEC.md` and `README.md`, the reference for behaviour and wording. Gateway wire
  format, keyconfig, capabilities, errors and key custody: `docs/HPKE.md` (and
  `docs/HPKE-V3-EXPERIMENTAL.md`) in `/home/ubuntu/repos/prosecco37/anonymizator`, including
  "Client conformance".
- The sibling package `n8n-nodes-judgment` (<https://github.com/cbuctok/n8n-nodes-judgment>, not
  checked out on this box): its `AGENTS.md` for the verification history this repo follows,
  `.crush/verification-submission.md` for the model of `docs/verification-submission.md`, and
  `.crush/skills/n8n-template-submission/` for the template rules and validator.
