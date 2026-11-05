# Architecture (source tree)

_Moved out of `AGENTS.md` (2026-11-05). Section names quoted in the text may now live in a sibling file under `docs/agents/`; `AGENTS.md` has the index._

## Architecture

```
nodes/Anonymizator/
  Anonymizator.node.ts      INodeType: description, operation switch, execute loop, catch block,
                            methods.loadOptions.getEntityTypes
  Anonymizator.node.json    codex: categories ["Utility", "Development"], alias (panel search), doc links
  actions/
    protect.ts              protectDescription + executeProtect; ID set per item or shared, merge;
                            mergeState, outputMap; shared helpers (detectRemotely, gatewayFailure,
                            readTextParameter, readEntityTypes, loadEntityTypeOptions, withoutFields,
                            IGNORE_TERMS_OPTION)
    detect.ts               detectDescription + executeDetect; companies, trimming, counts, offsets
                            into the original
    reveal.ts               revealDescription + executeReveal; unresolvedPlaceholders
  shared/
    hpke.ts                 RFC 9180 seal (Base mode, single shot), v2 frames, padding, response open
    keyconfig.ts            TRUST_ROOTS_B64URL, strict delegation/keyconfig v2 parsers, verifyDelegationV2,
                            verifyKeyconfigV2 (fail closed, key selection)
    hpkeV3.ts               protocol v3: X-Wing encapsulation (node:crypto X25519 + ML-KEM-768 from
                            Node.js itself (`native`, feature-tested by nativeMlKemAvailable) or the
                            vendored code (`noble`)), the FIPS 203 key check, the key schedule,
                            sealRequestV3
    keyconfigV3.ts          strict pgw-keyconfig-v3 parser, verifyKeyconfigV3 (the `v3` member, the
                            same delegation verifier)
    vendor/noblePq.ts, vendor/noble/*.ts   GENERATED subset of @noble/post-quantum, @noble/hashes and
                            @noble/curves (TypeScript sources); never edit, regenerate
    capabilities.ts         strict pgw-capabilities-v1 parser, verifyCapabilitiesV1
    gateway.ts              keyconfig acquisition (cache, serial floor), sealed /v1/analyze, long texts
                            in parts (split, sequential parts, rate-limit waits, merge), capabilities
                            fetch, error allowlists, retries
    chunker.ts              split / merge / assertCover / partTarget (extension lib/chunker.js)
    limits.ts               MAX_TEXT_CHARS (10 000), the plausibility window, effectiveMaxTextChars
    gatewayMessages.ts      GATEWAY_MESSAGES, LOCAL_FAILURES, gatewayErrorText (extension wording)
    anonymizer.ts           port of the extension's lib/anonymizer.js + mask/isValidKey from id-set.js
    idModel.ts              ID set model: types and prefixes, legal forms, companySpans, fromV1,
                            flatTypeFromKey, revealTable, own-placeholder test, extraBlockTest
                            (id-model.js, id-rules.js, id-names.js)
    protectPipeline.ts      protect() = anonIdEdits.anonymize; emptyState, fromFlatMap, detectedValues
    extraDetect.ts          Additionally Protect: NUMBER / AMOUNT / COMPANY spans, mergeExtra
    possible.ts             possible IDs: findPossible, detectedValues (id-possible.js)
    entities.ts             ENTITY_CATALOG (16 rows) + ENTITY_GROUPS, mergeCatalog, entityOptions,
                            entityFilter
    ignoreTerms.ts          parseIgnoreTerms, ignoredTermTest (Protect), filterIgnoredSpans (Detect)
    placeholderMap.ts       one map normaliser for every input format incl. ID file v1/v2; v2 writer
    types.ts                shared types, GATEWAY_BASE_URL, CREDENTIAL_NAME, GATEWAY_TIMEOUT_MS
    errors.ts               errorNode() guard, GatewayError (GatewayErrorCode), PlaceholderMapError
credentials/AnonymizatorApi.credentials.ts   apiKey, generic Bearer, test on GET /v1/keyconfig
icons/anonymizator{,.dark}.svg               from the extension's aperture symbol; light != dark
test/*.test.mjs                              node --test against dist/ (see "Test layers")
test/helpers/pgw.mjs, test/engine-ext.mjs    fake v2 gateway, extension loaders (node:vm)
test/fixtures/pgw-v2.json, pgw-capabilities-v1.json   gateway vectors, byte for byte
scripts/
  smoke.mjs                 the node against production, no n8n
  e2e-n8n.mjs               the node through Docker n8n over REST
  scan.mjs                  the verification scanner, source + packed tarball
  check-node-fields.mjs     fixedCollection consistency (copied from judgment)
  release.mjs               checks, bump, changelog stub, commit, tag, push
  vendor-noble-pq.mjs       regenerates shared/vendor/ from the pinned noble tarballs (by hand only)
vendor-noble.lock.json      provenance of shared/vendor/ (pins, upstream files, patches, outputs); not shipped
e2e/anonymizator-e2e.workflow.json   19-node workflow with asserting Code nodes
examples/protect-llm-reveal/         importable example workflow + README (not shipped)
docs/verification-submission.md      cover note, reviewer notes, video outline (not shipped)
SECURITY.md                          private reporting, scope (not shipped)
docker-compose.yml          n8n 2.44.5 with only dist/ and package.json linked in
dist/                       build output, gitignored, referenced by package.json
```

Each action module exports `<action>Description: INodeProperties[]` and
`execute<Action>(this: IExecuteFunctions, itemIndex, ...)`. `Anonymizator.node.ts` routes between
them and owns the catch block (`continueOnFail`, `pairedItem`, `NodeApiError` vs
`NodeOperationError`). Already-mapped n8n errors pass through it unchanged.

**Reveal never touches the network or the credential.** The credential is declared
`required: true` with `displayOptions: { show: { operation: ['protect', 'detect'] } }` (the precedent
is n8n's own Crypto v2 node), so the Reveal UI shows no credential, and only the Protect and Detect
code paths call `httpRequestWithAuthentication`. Keep it that way: a Reveal that needs a key would
break offline use and the privacy claim in the README.

**No runtime dependencies, on purpose.** `nodes/` and `credentials/` import only `n8n-workflow`,
`node:crypto` and relative paths. The lint rule `no-restricted-imports` also lets any
**devDependency** through, and that is a trap: the build does not bundle, so such an import passes
lint and then fails at runtime in the user's n8n. Third-party code that must ship is **vendored as
source** instead: protocol v3's fallback ML-KEM-768 and SHA-3 (used only by Always Post-Quantum
on a Node.js without native ML-KEM) live in `shared/vendor/` (see "Post-quantum protocol v3"),
compiled with the rest and scanned like our own code. `files` is `["dist", "NOTICE"]`; `npm pack` yields 108 files, 180 kB (`dist/`,
`NOTICE`, and `package.json`, `README.md` and `LICENSE.md`, which npm always adds; 2026-10-31,
with the vendored code). `npm run scan` fails on anything else in the tarball.

**Requests go through n8n's helper.** `gateway.ts` calls
`ctx.helpers.httpRequestWithAuthentication.call(ctx, 'anonymizatorApi', options)` with the context
as `this` (using `helpers` as `this` gives "this.getNode is not a function"). That brings n8n's
proxy support and the credential's `authenticate` block along. `GatewayContext` is the minimal
interface both `IExecuteFunctions` and `ILoadOptionsFunctions` satisfy, so `getEntityTypes` fetches
capabilities through the same path.

**One gateway round trip per part.** `/v1/analyze` takes one `text` per sealed request, at most the
per-request cap (`effectiveMaxTextChars`, code points); there is no batch endpoint. `analyze()` in
`gateway.ts` cuts a longer text into parts with `shared/chunker.ts` (a port of the extension's
`lib/chunker.js`, itself the web app's `pgw-chunker.js`: same algorithm, same constants), sends
them one after another (each through `analyzeSealed`, so each is sealed afresh with its own two
attempts), and merges their spans: each part's code-point offsets are converted to UTF-16 against
that part (`codePointSpansToUtf16`), shifted by the part's `start16`, sorted, exact duplicates and
spans inside another part's span dropped, partial overlaps across a cut united; possible spans the
same, dropped where they touch an entity. One-part texts go through the same merge. Fail closed:
any failing part throws for the whole item (`GatewayError.failedPart` / `parts` set for two or more
parts; `gatewayFailure` adds "This was part i of n of the text; no partial result is output." before
the code), so the Protect pipeline runs once over the whole text or not at all. There is no length
limit per item and no up-front refusal; the per-request code-point check in `analyzeSealed` is only
a guard (parts are always 2 000 below the cap). Blank text never leaves n8n (no capabilities or
keyconfig request either). The README's "Long texts" section is the user-facing description and
the reference for API callers; keep it in step.

