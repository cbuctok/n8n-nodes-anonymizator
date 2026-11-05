# Test layers and example workflows

_Moved out of `AGENTS.md` (2026-11-05). Section names quoted in the text may now live in a sibling file under `docs/agents/`; `AGENTS.md` has the index._

## Test layers, and why each exists

Four layers, each catching a class of failure the others cannot see. A green run of one is not
evidence for the others.

| Layer | What it runs | What only it catches |
| --- | --- | --- |
| `npm test` (`test/*.test.mjs`, `node:test`; on 2026-11-05: 1213 tests on Node 22.23.4 (1211 pass, 2 tests and 5 suites skipped, all "this Node.js has no native ML-KEM-768"), 1243 on Node 24.7.0 and 24.22.2 (1242 pass, 1 skipped: the native-absent case)) | The compiled `dist/` modules and the node class with fake `IExecuteFunctions` / `ILoadOptionsFunctions`. Every case of the gateway's vectors (`test/fixtures/pgw-v2.json` and `pgw-capabilities-v1.json`, copied byte for byte from the gateway repository's `tests/vectors/`): keyconfig cases, request frame bytes, response open, sealed errors, the `possible_emoji` exchange, offsets, capabilities cases. A fake v2 gateway (`test/helpers/pgw.mjs`: an independent `node:crypto` recipient with a test root, delegation and keyconfig, injected through the `trustRootsB64url` seam) for every status and retry path, and for long texts in parts (`test/chunker.test.mjs` ports the extension's chunker cases; `gateway.test.mjs` and `node.test.mjs` cover the split, the merge, straddling values, emoji offsets, failing parts, rate-limit waits and the `invalid_entities` restart). Differential and interop tests against the extension's real files (below). `examples.test.mjs` checks the example workflows' structure (package node type, connections, `$('Node')` references, no credential ids). | Crypto correctness (RFC 9180 and gateway vectors), the trust chain, wire format, every status mapping and retry path, the pipeline port's behaviour, map parsing, ID file rules, the catalog merge and filter, Detect offsets and counts, Ignore Terms, Include Placeholder Map, the new options. Fast and offline. |
| `npm run smoke` (`scripts/smoke.mjs`, 24 scenarios) | The compiled node against **production**, with a fake context whose `httpRequestWithAuthentication` does a real `fetch` and honours n8n's options (no redirect following, no throw on error statuses, full response, Buffer bodies, timeout). | The live contract: keyconfig v2 and capabilities verifying against the pinned roots, response shape, offset unit, the published per-request cap, a ~40 000-character Protect and a Detect sent in parts (one request per part, one placeholder per value, offsets, Reveal round trip), status codes for a rejected key, detection on real sentences. |
| `npm run e2e` (`scripts/e2e-n8n.mjs`) | `e2e/anonymizator-e2e.workflow.json` through a real n8n 2.44.5 in Docker over its REST API (19 nodes; "Protect No Map" also asserts Additionally Protect's `[AMOUNT_…]` and `[COMPANY_…]`, and "Check Typed" fails if the Type Only item, run with Include ID File on, has an `idFile`), a `getEntityTypes` call through `/rest/dynamic-node-parameters/options` that must return every bundled row plus at least one server-only type, then an import (no run) of every `examples/*/workflow.json` with the type prefix rewritten to `CUSTOM.`. | **n8n's parameter resolution**: expressions in json parameters, collections, the credential hidden by `displayOptions` on Reveal, the `CUSTOM.` type prefix, load options with a real credential, the tool variant being generated, icons being served; that every node type and version an example uses exists in this n8n (no "?" nodes on import). |
| `npm run scan` (`scripts/scan.mjs`) | `@n8n/scan-community-package` 0.40.0 (lint plugin 0.37.0) on the source and on the `npm pack` tarball, as the verification pipeline does. | Rules newer than the local lint plugin, inline suppressions (which it ignores), unexpected files in the tarball. |

**`smoke` never exercises parameter resolution.** It builds the parameter objects by hand, so its
field names must be kept in step with the node's parameter definitions. When they drift it does not
fail loudly: it feeds the node a shape n8n would never produce, and the errors look like node bugs.
Check the field names before touching the node when `smoke` fails in a way that makes no sense.

**`smoke` and `e2e` depend on server-side detection.** Their assertions use sentences the gateway
detects today ("my name is Janez Novak", synthetic emails, the `SI56 1910 0000 0123 438` test IBAN).
A model change on the server can turn them red with the client code unchanged. Check what the
gateway returned before "fixing" the node. Only synthetic data is ever sent; never send real
personal data to the gateway from a test.

**Unit tests that compare against the extension skip when its checkout is missing.** The
differential and interop cases load the extension's real `lib/anonymizer.js`, `lib/id-model.js`,
`lib/id-rules.js`, `lib/id-names.js`, `lib/extra-detect.js`, `lib/id-possible.js`,
`lib/id-edits.js`, `lib/hpke.js`, `lib/entities.js`, `lib/constants.js` and
`sidepanel/sidepanel-idfile.js` with `node:vm` (the pipeline: 120 rounds x 4 steps x 4 styles
against `anonIdEdits.anonymize`). The checkout is found through `ANON_EXT_DIR`, which must point at
the **`anonymizator-chrome-ext` subdirectory**, not the repo root (for example
`ANON_EXT_DIR=/path/to/anonymizator-chrome/anonymizator-chrome-ext npm test`), else the local
checkout `/home/ubuntu/repos/prosecco37/anonymizator-chrome/anonymizator-chrome-ext`
(`test/helpers/pgw.mjs`, `test/engine-ext.mjs`, `test/placeholderMap.test.mjs`). A missing checkout
makes these tests **skip, not fail**, which looks like a pass: when checking for drift, look for
`# SKIP extension checkout not found` in the output (`node --test --test-reporter=tap
"test/*.test.mjs"`). In CI they are reported as skipped too. The 2026-10-24 run had 0 skips.

**The generated differential tests use `prng` from `test/engine-ext.mjs`, a mulberry32.** The
earlier double-precision LCG lost its low bits after a few steps (`rnd(2)` stuck at 0), so the
"generated" runs covered only a handful of cases; never replace it with an LCG over doubles. Each
generated test also asserts that its inputs vary (distinct texts, several options on, entities and
extras present, every separator used), so a degenerate generator fails instead of passing quietly.
The perf tests (`timed()` in the same file) assert ratios or generous limits measured in the same
run, not tight wall-clock numbers, because they run on loaded machines.

**Tests live in `test/`, never under `nodes/`.** `nodes/` is compiled, shipped and scanned:
`no-dead-files` would flag test files there and `no-hardcoded-secrets` would trip on the RFC vectors
and test keys. `test/` is neither compiled (tsconfig includes only `nodes/` and `credentials/`) nor
shipped (`files: ["dist"]`) nor scanned.

**Verify an e2e run by node coverage, not exit status.** A node returning `[]` ends its branch
without error, so later nodes never run and the workflow still succeeds. The workflow's Code nodes
throw when a branch is wrong; confirm all 19 nodes ran:

```
docker compose logs n8n | grep 'Running node'
```

**Reset before believing an e2e run.** `npm run n8n:reset` wipes the volume; without it old
workflows, credentials and executions accumulate and can mask a failure. The script deletes its
workflow afterwards unless `KEEP_WORKFLOW=1`, but the execution data (which contains the synthetic
text and maps) stays in the volume until the next reset. The Docker editor is at
<http://localhost:5678>, owner `admin@example.com` / `AnonymizatorTest123!` (created by the e2e
script on a fresh volume; override with `N8N_EMAIL` / `N8N_PASSWORD`). The port is published on
`127.0.0.1` only, because that password is public and the instance holds the real API key as a
credential during a run; keep it that way. The script also deletes its `anonymizatorApi` credential
at the end unless `KEEP_WORKFLOW=1`.

`e2e/anonymizator-e2e.workflow.json` is a dev-instance fixture, not a template: it uses
`CUSTOM.anonymizator` and a credential id the script fills in, so it does not import into a normal
install. Edit the JSON directly (keep short arrays such as `position` on one line, as the file has
them).

## Example workflows

`examples/<name>/workflow.json` plus `README.md` are importable workflows for users, linked from the
README; they are not shipped (`files` excludes them). Today there is one, `protect-llm-reveal`
(Manual Trigger → Set → Protect → Basic LLM Chain with an OpenAI Chat Model → Reveal).

- Node type `n8n-nodes-anonymizator.anonymizator`, the type a **Settings → Community Nodes** install
  registers. Never `CUSTOM.`; the e2e script rewrites the prefix for the Docker n8n.
- No credential ids (`"id": ""`), no secrets, no node `id` fields, and only the top-level keys
  `name`, `nodes`, `connections`, `settings`, `pinData`. Never re-export over the file from n8n.
- Reveal reads the map with `$('Protect').item.json.placeholderMap`, so the Protect node must be
  named `Protect`. A Basic LLM Chain outputs only `{ text }` and drops every other field, which is why
  the map is read by node name and the answer is `$json.text` (`$json.output` after an AI Agent).
- Sticky notes and the README follow judgment's Creator Hub rules. Check with judgment's validator,
  `.crush/skills/n8n-template-submission/scripts/validate-template.mjs` in a clone of
  <https://github.com/cbuctok/n8n-nodes-judgment> (no checkout on this box):
  `node <judgment>/.crush/skills/n8n-template-submission/scripts/validate-template.mjs examples/*/workflow.json`.
  It always reports one FAIL, "Community node obligations", as a reminder for any non-built-in node
  (it also counts the `@n8n/n8n-nodes-langchain` nodes); the obligations it lists are met except the
  canvas screenshot, which needs a browser.

