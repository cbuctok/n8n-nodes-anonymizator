# Post-quantum protocol v3

_Moved out of `AGENTS.md` (2026-11-05). Section names quoted in the text may now live in a sibling file under `docs/agents/`; `AGENTS.md` has the index._

The specification is the gateway repository's `docs/HPKE-V3-EXPERIMENTAL.md` (section 9.3 is this
node). v3 is v2 with the hybrid KEM X-Wing (X25519 + ML-KEM-768, KEM `0x647a`) instead of
DHKEM(X25519): frame `0x03 || key_id || timestamp || enc(1120) || ct` (at least 1149 bytes), the
same AAD, padding and response construction with `'pgw response v3'`, keys from a sibling `v3`
member of `/v1/keyconfig` (`pgw-keyconfig-v3`) signed under the same delegation. The v2 code paths
and bytes are unchanged.

Since the change after 0.4.0 (planned 0.5.0), **v3 is the default wherever Node.js has native
ML-KEM**, and the unaudited vendored ML-KEM is never used by default. This deliberately goes beyond
the spec's section 9, which keeps every client opt-in; the policy was decided by the owner.

- **Modes** (`EncryptionMode` in `gateway.ts`, read by `encryptionMode` in `actions/protect.ts`):
  - `automatic` (default): v3 with the **native** ML-KEM-768 when `nativeMlKemAvailable()` AND the
    keyconfig's `v3` member verifies, else v2. `acquireAutomaticResult` runs the v2 acquisition as
    always (cache, floor, renewal race), then verifies the `v3` member of **the same raw document**
    under the same floor, inside the one keyconfig queue: one `/v1/keyconfig` fetch serves both,
    and a missing, failing, stale or keyless `v3` member means v2 (v2 never depends on v3, spec
    7.1). A v2 failure fails as with standard encryption. A low-order `pk_X` in a verified v3 key is
    `hpke_seal_failed` (nothing was sent; not downgraded).
  - `postQuantum` (Always Post-Quantum): the previous experimental behaviour, v3 or nothing
    (`hpke_pq_unavailable` or the verifier's code), now with the native ML-KEM where present and
    the vendored one otherwise.
  - `standard`: what `analyze` does without a reader (tests, diagnostics): v2 only.
- **Credential and migration.** The 0.4.0 boolean `postQuantum` became an `options` field
  (display name **Encryption**) with the boolean values `true` (Always Post-Quantum
  (Experimental)) and `false` (Automatic, default), still shown only with `showExperimental`.
  n8n passes a node only the credential fields that are **defined and displayed**
  (`getNodeParameters` drops unknown and hidden ones), so a new field could not have read the old
  value; keeping the name and its stored values makes the migration an identity: a 0.4.0 credential
  with both booleans `true` is Always Post-Quantum, every other one Automatic. Boolean option values
  have precedent in n8n-nodes-base (MonicaCrm, HaloPSA, Google Docs). The reader is Always
  Post-Quantum only when both booleans are exactly `true`; a context without `getCredentials` is
  Automatic; a credential read that throws fails the item. The credential test stays v2.
- **Native ML-KEM** (`hpkeV3.ts`): `nativeMlKemAvailable()` is a memoised feature test (the KEM
  functions exist, `generateKeyPairSync('ml-kem-768')`, an encapsulate/decapsulate round trip
  through the SPKI import the seal uses); it never reads `process.version`. Node.js 24.7.0
  (OpenSSL 3.5.2) has it; 22.x does not. `@types/node` 18 does not declare `crypto.encapsulate`, so
  it is reached through a typed view of `import * as nodeCrypto` (no `any`, no lint change). The
  public key is imported as SPKI (`308204b2300b0609608648016503040402038204a100` || pk_M), which
  works from 24.7.0 on (`raw-public` / `raw-seed` only exist from 24.15). The native backend also
  takes SHA3-256 from node:crypto, so it uses no vendored code at all.
- **Native encapsulation is not derandomized.** OpenSSL draws ML-KEM's `m` itself, as the
  gateway's Python (`cryptography`) does; X-Wing `Encapsulate` is `EncapsulateDerand` with a random
  `eseed`, so the wire format is the spec's, but a fixed-`eseed` frame vector cannot be repeated
  byte for byte on the native path (the `eseed[0:32]` half is unused there; `eseed[32:64]`, the
  X25519 half, is used as before). `test/hpkeV3Native.test.mjs` therefore checks the native ML-KEM
  through keygen (every vector seed gives the vector's pk) and decapsulation (every vector
  ciphertext gives ss_M / ss / shared_secret), the native seal's X25519 half against the vectors
  byte for byte, its frames opened by the independent recipient, and a native/vendored
  differential. The vendored path still reproduces every frame byte for byte (`hpkeV3.test.mjs`).
- **Never v2 after a v3 attempt.** `analyze` keeps one `SendState` per text: once a send of the
  text was sealed as v3 (just before the POST), every later send of it (other parts, retries, the
  `invalid_entities` rerun) uses the v3 keyconfig only, whatever the mode. Under Automatic a v3
  that can no longer be had there is `hpke_pq_withdrawn` (own wording); under Always Post-Quantum
  it stays `hpke_pq_unavailable`. A later n8n retry of the item (Retry On Fail) is a new run and
  chooses afresh.
- **Read at every send.** The mode is read before each send, retry and reseal; after a v2
  acquisition it is read again and a switch to Always Post-Quantum restarts the send as v3 (spends
  no retry budget).
- **Retries:** v2's (one after `hpke_unknown_key` / `hpke_key_expired` / 5xx / `busy` / sealed
  `internal_error`), plus, for a v3 frame answered with a plain `hpke_bad_version`, one keyconfig
  refetch and reseal with its own budget; a second one is `hpke_pq_unavailable` /
  `hpke_pq_withdrawn`.
- **`encryption` output** (Protect and Detect): `GatewayAnalyzeResult.encryption` is the weakest
  of all sends of the text (`v2` < `v3-noble` < `v3-native`), so a `v3-…` value means no part and no
  attempt left n8n as v2; `none` for blank text (nothing sent). It is always written, so Include
  Input Fields never carries an input item's value over.
- **Test seam:** `nativeMlKem: false` in `GatewayTestSeams` simulates a Node.js without native
  ML-KEM. Run the suite on Node 22 (absent for real) **and** on Node 24.7+ (present); both must pass.
  Without a system Node 24, download the official tarball into a temp dir, check it against
  `SHASUMS256.txt` and run `<tmp>/bin/node --test "test/*.test.mjs"` against the `dist/` built as
  usual (and `<tmp>/bin/node scripts/smoke.mjs`).
- **Delegation serial floor:** one `commitDelegationFloor` (read, compare, raise) used by the v2,
  v3 and Automatic acquisitions, all inside `enqueue('keyconfig')`, so a floor raised by v3 is seen
  by v2 and capabilities and the other way round. v3 has its own keyconfig cache.
- **Leak rule:** errors are fixed codes; X-Wing intermediates and secrets are zeroed best effort.

### Vendoring (deviation from the spec's recipe, on purpose)

Section 13.1 of the spec settles an esbuild ESM bundle in a `// @ts-nocheck` `.ts` file, ignored in
`eslint.config.mjs`. That does not work here: `n8n.strict: true` makes `n8n-node lint` exit 1 when
`eslint.config.mjs` differs from the CLI's default, and `@ts-nocheck` is itself a lint error
(`@typescript-eslint/ban-ts-comment`). So `scripts/vendor-noble-pq.mjs` vendors **TypeScript
sources**: from the `src/*.ts` files inside the three pinned tarballs it keeps exactly the
declarations reachable from `ml_kem768`, `sha3_256` and `shake256` (TypeScript compiler API; the
same closure as esbuild's tree shaking, plus types, plus sha3's top-level table loop), one output
file per upstream module, byte for byte apart from listed patches:

- `randomBytes` throws instead of reading `globalThis.crypto` (banned global; never reached, the
  node passes ML-KEM's `m` from `node:crypto.randomBytes`);
- `Object.hasOwn` (ES2022) becomes `Object.prototype.hasOwnProperty.call`;
- four lint-only edits (`let` -> `const`, an unused parameter and destructured names, `{}` type);
- type-only: upstream's `any` is spelled `NobleAny` (= `ReturnType<typeof JSON.parse>`).

`vendor-noble.lock.json` records the tarball pins (SHA-256 and npm integrity, checked before
unpacking), every upstream file's SHA-256 with the declarations kept, the patches with reasons, the
TypeScript version and each output's SHA-256. Regenerate (by hand, never in a test or build):

```
mkdir /tmp/noble && cd /tmp/noble && npm pack @noble/post-quantum@0.7.1 @noble/hashes@2.4.0 @noble/curves@2.4.0
node scripts/vendor-noble-pq.mjs --tarballs /tmp/noble           # check: "up to date"
node scripts/vendor-noble-pq.mjs --tarballs /tmp/noble --write   # then lint, build, test, scan
```

`test/vendorNoble.test.mjs` checks the outputs against the lock, the scanner's restricted globals
and dangerous calls in the source and in `dist/`, and runs a differential test against the
extension's esbuild bundle of the same tarballs (unmodified upstream) when its experimental
checkout is present. `@noble/post-quantum` is **not independently audited** (self-audit of 0.6.1);
re-evaluate 0.6.1 vs 0.7.1 before any release (spec section 18). Since Automatic never uses it, it
only matters for Always Post-Quantum on a Node.js without native ML-KEM. NOTICE carries the MIT notice;
`npm run sbom` writes `sbom/vendored.cdx.json` from the lock.

### v3 tests and fixtures

`test/fixtures/pgw-v3.json` and `xwing-official.json` are byte-for-byte copies of the gateway's
`tests/vectors/` on branch `experimental-pq-v3` at `bd97c6f` (SHA-256 pinned in
`test/vendorNoble.test.mjs`; `xwing-official.json` transcribes IETF draft text, BSD-3-Clause code
components). `test/hpkeV3.test.mjs`: the three X-Wing draft-11 vectors and A.5 of
draft-ietf-hpke-pq-05 (encapsulation included, the key schedule with the AEAD 3 override), every
section of the shared vectors (frame byte for byte from the fixed `eseed`, responses, exchanges,
62 keyconfig cases, capabilities, frame and seal cases, `v2_unchanged`). `test/helpers/pgwV3.mjs`
holds the independent recipient (node:crypto SHA-3/SHAKE/X25519/HKDF; ML-KEM from the vendored
code, so it runs on Node 22), an independent native ML-KEM recipient (`xwingExpandNative`,
`xwingDecapsulateNative`: seed-only PKCS#8 import, `crypto.decapsulate`; `NATIVE_MLKEM` /
`NATIVE_SKIP`), `openRequestForTestV3` (the gateway's pre-open order) and a fake v2 + v3 gateway.
`test/hpkeV3Native.test.mjs` runs the vectors through the native ML-KEM (above).
`test/gatewayV3.test.mjs` covers standard without a reader, Always Post-Quantum (fail closed, the
bad-version budget, retries, the monotonic rule, native vs vendored), Automatic with native present
and absent (real and simulated), never-v2-after-v3, `encryption`, and the shared floor;
`test/nodeV3.test.mjs` the credential, the 0.4.0 migration and Protect / Detect end to end. `smoke`
covers v3 live (keyconfig v3, Automatic, Always Post-Quantum native and vendored); `e2e` does not
check the encryption.

