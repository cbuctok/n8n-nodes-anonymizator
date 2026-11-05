# Compliance model, crypto design and the gateway contract

_Moved out of `AGENTS.md` (2026-11-05). Section names quoted in the text may now live in a sibling file under `docs/agents/`; `AGENTS.md` has the index._

## Compliance model

- **Ranges only.** The gateway receives the sealed text and answers with
  `{"entities": [{"entity_type", "start", "end", "score"}]}` (plus `possible: [{start, end,
  entity_type}]` when asked). It keeps nothing and never sees a placeholder or a map. Placeholder
  allocation, substitution, PERSON sub-keys, companies, Additionally Protect, possible IDs, masking,
  the ID file and Reveal are computed locally. Do not add a feature that sends a map, a placeholder
  or revealed text to the gateway.
- **Sealed end to end.** The text is HPKE-sealed to the gateway's current X25519 key (v2) or X-Wing
  key (v3, see "Post-quantum protocol v3"), so the CDN and the BFF in front of the gateway see only
  ciphertext. The response is sealed back with keys derived
  from the same context. The README's "What leaves n8n" table lists every field and request sent
  (keyconfig, capabilities, analyze); keep it in step with `gateway.ts` and `hpke.ts`.
- **Local filters stay local.** Ignore Terms, Include Values, Additionally Protect and the local
  possible-ID rules are applied after detection and are never sent; the gateway always gets the
  whole text. The only request fields besides `text` are `entities` (Selected Types, unless every
  bundled row is selected) and `possible: true` (Include Possible IDs, and only when the verified
  capabilities list possible types, as the extension does).
- **Signed keyconfig v2, fail closed** (gateway `docs/HPKE.md`, "Keyconfig" and "Client
  conformance"). `GET /v1/keyconfig` must carry a `v2` member that verifies through the chain
  pinned root (`TRUST_ROOTS_B64URL`, exact string compare) -> root-signed delegation
  (`pgw-keyconfig-delegation-v2`, lifetime <= 32 days, `serial` within 300 s of `not_before`,
  `audience` containing `anon.prosecco37.com`) -> keyconfig (`pgw-keyconfig-v2`, `suite=32,1,2`,
  signed by the delegated key inside the delegation's window, `issued_at` at most 15 minutes old,
  300 s skew) -> keys with a signed `not_after`. The key used is the **highest `key_id` with
  `now + 300 < not_after`**, never `keys[0]`. Parsers are strict: raw bytes checked before decoding,
  canonical base64url, full-regex numbers, Ed25519 signatures with the S < L check; nothing
  canonicalises JSON. The v2 verifier reads only `v2` (the gateway serves `{"version": 2, "v2": ...}`,
plus a sibling `v3` that only the v3 verifier reads, see "Post-quantum protocol v3"):
  a missing or failing `v2` is `hpke_unverified_keyconfig` (an HTML login page included),
  `hpke_stale_keyconfig` for a time window that does not hold by this clock, `hpke_no_usable_key`
  when no key stays valid long enough. All happen before the text is sealed, and the item stops with
  a NodeOperationError whose message says this can mean interception (for example a
  TLS-inspecting proxy). Never add a "skip verification" option. An empty root list trusts nothing
  (as in the extension; its old v1 "empty root = warn and allow" branch is gone and must not
  return).
- **Delegation serial floor.** A module-level floor (per n8n process) holds the highest delegation
  `serial` that ever verified; a lower one is refused, so a stolen older delegated key cannot be
  replayed once the renewal was seen. Only a successful keyconfig acquisition raises it;
  capabilities only read it. Renewal race (as the extension's `acquireHpkeConfig`): when a replica
  still serves the older delegation, the previously verified config is kept if it still verifies
  against the floor, else the keyconfig is fetched once more after 2 s.
- **Capabilities can only add.** `GET /v1/capabilities` (`pgw-capabilities-v1`) is verified with the
  same delegation rules (`verifyCapabilitiesV1`, `issued_at` at most 2 h old). It adds entity types,
  labels and groups to the bundled catalog and sets the per-request text cap (within 10 000 to 1 000 000); it never
  removes a bundled row or a type a bundled row sends, `possible` types never become rows, and an
  omitted `entities` filter still means every type the server has. Any failure (404 from an older
  gateway, auth, HTTP, verification, stale, below the floor) gives `null` and the bundled data:
  passive, never an error.
- **n8n stores what passes through it.** Execution data contains the original text and the map. The
  Protect/Detect notice tells users to restrict saved executions. The map and the ID file are the
  re-identification key; the ID file is written only for Random and Numbers in Order, never for the
  masked styles. Our own Protect output
  contains the originals (in `placeholderMap`, `idFile`, and `possibleIds` values, which are text
  still in clear), so never claim that originals never appear in the output; the claim is about
  **where** the map is made and kept (locally; the gateway sees only the encrypted text and returns
  positions). Protect's `entities` never carry `value` or `key`, so with Include Placeholder Map off
  the output holds no protected value.

### Rotating the trust roots

The roots are pinned in two places that must agree: `TRUST_ROOTS_B64URL` in `shared/keyconfig.ts`
here and `ROOT_KEYCONFIG_PUBKEYS` in the extension's `lib/constants.js` (a unit test compares
them). Both list the **primary and the backup v2 root**. The root seeds are offline operator
secrets (gateway `docs/HPKE.md`, "Keys: lifecycle and custody"), never in this repo; the online signer is the
delegated key, renewed about every three weeks with a new delegation, which needs no client change.
Never pin the v1 root `LuE5xR_...` or a test-vector root.

People rarely update n8n nodes, so plan for installed versions that never update:

1. **Compromised root.** The gateway switches its delegations to the other pinned root at once; every
   installed version keeps working because both roots are pinned. Then release a version whose list
   drops the compromised root and adds a new backup (the extension ships the same list), and accept
   that old installs keep trusting the compromised root until they update.
2. **Planned replacement.** Add the new root to the list (keep both current ones), release, and wait
   until users and the extension have updated. Only then switch the gateway to delegations signed
   by the new root, and remove the retired root in a later release.
3. Keep the list short and identical to the extension's; a root that is in only one of them is a
   flag day for the other client.

## Crypto design

- **Classic synchronous `node:crypto`, not WebCrypto.** `createHmac`, `createCipheriv('aes-256-gcm')`,
  `createPrivateKey`/`createPublicKey` from DER (PKCS#8 prefix `302e020100300506032b656e04220420`,
  SPKI prefixes `302a300506032b656e032100` for X25519 and `302a300506032b6570032100` for Ed25519),
  `diffieHellman`, `generateKeyPairSync('x25519')`, `verify(null, ...)`. WebCrypto's X25519 types
  need a cast that compiles under `@types/node` 18 and fails under 24, and everything turns async.
  `globalThis.crypto` is banned by lint anyway.
- **Suite fixed, no negotiation:** DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM, Base mode,
  single shot (sequence 0 only). HKDF is built from HMAC; an empty HMAC key becomes 32 zero bytes,
  as in the extension (RFC 5869's absent salt), so outputs match byte for byte.
- **Protocol v2 only.** v1 was removed from the gateway (a `0x01` frame gets `hpke_bad_version`)
  and from the extension. Never add it back.
- **Request frame:** `0x02 || key_id u32BE || unix seconds u64BE || enc(32) || ct`, AAD = the 13-byte
  prefix, HPKE `info` = `'pgw request v2'`. Plaintext is `JSON.stringify({ text, entities?,
  possible? })` (UTF-8, no ASCII escaping) padded with spaces to 256 / 1024 / 4096 / 16384 / 65536
  UTF-8 bytes, then to the next multiple of 4096. Padding is part of the privacy design (body length
  must not track content length).
- **Response frame** (success and every post-open error): `0x02 || response_nonce(32) || ct`, with
  (RFC 9458 section 4.4, plain HKDF-SHA256) `secret = export('pgw response v2', 32)`,
  `prk = HKDF-Extract(enc || response_nonce, secret)`, key / nonce = HKDF-Expand `'key'` (32) /
  `'nonce'` (12), empty AAD, JSON padded with spaces (trimmed before parsing).
- **Every HTTP attempt is sealed afresh.** The gateway keeps each frame's `enc` for about 61 s and
  refuses a resent frame with `hpke_replay`; a retry with the old frame would fail.
- **Ed25519 via `verify(null, ...)`** plus an explicit S < L check (RFC 8032 5.1.7) against
  malleated signatures. Node's verify accepts an all-zero signature for the all-zero (small-order)
  public key; harmless here, because keys come only from the pinned roots or a root-signed
  delegation (WebCrypto behaves the same).
- **Buffer-only HTTP bodies.** axios sends `data.buffer` for any ArrayBuffer view that is not a
  `Buffer`, so a `Uint8Array.subarray` would put the **whole underlying buffer** on the wire. Hand
  n8n a `Buffer` (`Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength)` when converting).
- **`Buffer<ArrayBufferLike>` trap.** `@types/node` 18.19 makes `Buffer` generic, so
  `let t = Buffer.alloc(0); t = hmac(...)` fails with TS2322. Annotate: `let t: Buffer = ...`.
- **Target es2019.** No `10n` literals (use `BigInt(...)`), no `Object.hasOwn`, `.at()` or
  `replaceAll`. `\p{L}` and lookbehind are fine because they are built with `new RegExp(string)`.
- Secrets are zeroed with `fill(0)` after use on a best-effort basis.

## The gateway contract

Every request uses `{ disableFollowRedirect: true, ignoreHttpStatusErrors: true,
returnFullResponse: true, encoding: 'arraybuffer', json: false, timeout }` (60 s for analyze, the CDN's own cut-off, since a part of the published size may take up to ~50 s with queueing; 15 s for
keyconfig and capabilities) and branches on `statusCode` and the content type. The response body is
always a Buffer, JSON error bodies included. GETs send `Accept: application/json`; the analyze POST
sends `Content-Type: application/octet-stream` and `Accept: application/octet-stream,
application/json`.

### Status mapping

Port of the extension's `gatewayFetch` / `analyzeSealed`. An `application/octet-stream` answer, **of
any status**, is opened with the request's HPKE context and classified by content: exactly one of
`entities` (an array: success) or `error` (a sealed error code). Sealed v2 errors usually arrive
with **HTTP 200**.

| Response | Code | Node behaviour |
| --- | --- | --- |
| 302 (or any 3xx), 401 | `auth_required` | "The Anonymizator API key was rejected" (NodeApiError). |
| 403 `{"error":"missing_role"}` | `no_access` | "This API key has no access to Anonymizator". |
| other 403 | allowlisted code, else `http_403` | |
| 429 | `rate_limited` | `Retry-After` (integer 1-300 s) adds "Try again in N s.". A one-part text: no automatic retry. A part of a multi-part text waits `Retry-After` (else 5 s) and is sent again, at most 3 times; a wait over 60 s fails at once (`RATE_LIMIT_*` in `gateway.ts`, as the extension's `analyzePart`). |
| other 4xx / 5xx plain JSON | `{error}` through `KNOWN_ERROR_CODES` (the extension's allowlist), else `http_<status>` / `server_error` | The JSON is unauthenticated: `detail` / `error_description` are never kept or shown. |
| sealed answer with `error` | through `SEALED_ERROR_CODES` (`invalid_payload`, `invalid_entities`, `payload_too_large`, `hpke_bad_payload`, `internal_error`), else `http_<status>` | |
| `hpke_unknown_key`, `hpke_key_expired` | | Refetch the keyconfig (bypassing the cache) and send once more with a fresh seal. |
| plain (unsealed) 5xx, `busy`, sealed `internal_error` | | Send once more with a fresh seal after 1 s, then the "temporarily unavailable" message. The HTTP status of a sealed answer is unauthenticated and never triggers a retry: a sealed `invalid_payload` with HTTP 503, or an octet-stream 5xx that does not open, is not resent. |
| `hpke_replay`, `rate_limited`, `hpke_stale` | | Never retried. `hpke_stale`: "The n8n host's clock is off". |
| `invalid_entities` with a filter sent | | The whole text once more without `entities`, from the first part; output `entityFilterIgnored: true`. Never without a filter. |
| keyconfig 5xx (plain) | | Fetched once more at once (harmless to resend). |
| one part over `effectiveMaxTextChars` (code points) | `payload_too_large` | Local guard in `analyzeSealed`, before anything is sealed; never reached through `analyze`, whose parts are 2 000 below the cap. A 413 from the BFF and a sealed `payload_too_large` get the same message: "Part of the text was too long for one request", naming no number (there is no limit per item). |
| no response | `timeout` / `offline` | NodeOperationError. This includes n8n-core's wrapping: `httpRequestWithAuthentication` rethrows every axios failure as a `NodeApiError`, so a NodeApiError without a 3-digit HTTP status whose `cause` is a plain Error (ECONNREFUSED, ENOTFOUND, ECONNABORTED, ETIMEDOUT...) is mapped from the cause's code and message (`passesThrough` in `gateway.ts`). A NodeOperationError, a NodeApiError with a real status, or one around an n8n error (a missing credential) passes through unchanged. |
| 2xx that is not sealed, does not open, or has a span outside the text | `hpke_bad_response` | NodeOperationError (fail closed). |

So the analysis of one part is at most **two HTTP attempts** (plus up to three rate-limit waits in a
multi-part text), each freshly sealed, and the `invalid_entities` fallback is one more run over all
parts. The old 500 ms retry and the "sealed body over 256 KiB" rule are gone.
New codes since 0.1.1: `hpke_bad_frame`, `hpke_bad_version`, `hpke_key_expired`, `hpke_bad_payload`,
`hpke_replay`, `hpke_not_configured`, `hpke_bad_key_material`, `payload_too_large`,
`invalid_payload`, `internal_error`, `busy`, `upstream_unavailable`, `upstream_timeout`,
`unauthenticated`, `missing_role`, and the client-side `hpke_stale_keyconfig`, `hpke_no_usable_key`.
The protocol-v1 codes `hpke_bad_keyconfig` and `text_too_large` were removed from the union and
the wording table (a server that still sent one gets the generic `http_<status>` wording).

Local failures (`LOCAL_FAILURES`: the keyconfig codes, `hpke_seal_failed`, `hpke_bad_response`,
`timeout`, `offline`, and a `payload_too_large` without an HTTP status) become `NodeOperationError`
even when a response arrived; the rest become `NodeApiError` with the HTTP code. The wording lives in
`GATEWAY_MESSAGES` in `shared/gatewayMessages.ts`, taken from the extension's
`sidepanel/sidepanel-constants.js` and adapted to n8n; `gatewayErrorText` adds the Retry-After
sentence, `failedPartText` the failed part of a multi-part text, and both interpolate nothing but
numbers. Every message ends with `(code: ...)` in the description.

### 302, not 401, unless you ask for JSON

The BFF in front of the gateway decides by the `Accept` header (probed 2026-10-05):

- No `Accept`, or `*/*`, with a missing or rejected key: **302** to `/auth/login?return_to=...`
  (`text/html`). With redirects followed this ends on a **200** HTML login page, so a bad key looks
  like success. That is why `disableFollowRedirect: true` is on every request and in the credential
  test, and why every 3xx is treated as a rejected key.
- `Accept` containing `application/json` (the node sends it on both endpoints): **401**
  `{"error":"unauthenticated","error_description":"no valid session; ...","login_url":"..."}`.

Both are mapped the same way, in the code and in the credential test's rules (302, 401, 403). Do not
drop either. The capabilities fetch is passive: there a 3xx, 401 or 403 gives the cached document or `null`
(bundled catalog), never an error, and does not start the 5-minute backoff (see the caches below).

### Offsets

The gateway returns offsets in **code points** (Python/Presidio), not JavaScript UTF-16 indices. The
text is sent **exactly as given** (the old surrogate-to-space `sanitizeForOffsets` is gone), and
`codePointSpansToUtf16` converts every span against that same text, as the extension does. It fails
closed: a non-integer offset, an empty or reversed span, or one past the end makes the **whole
answer** `hpke_bad_response`, never a partly protected text. A lone surrogate counts as one code
point on both sides. Span edges are no longer trimmed by the gateway layer. Spans arrive unsorted;
they are sorted by start, longest first, and the substitution skips overlaps. An entity type outside
`^[A-Z][A-Z0-9_]{0,63}$` is kept as `PII` (protected, generic label), in Protect and Detect. The
`possible` member is validated the same way (array of at most 10 000 `{start, end, entity_type}`,
any malformed entry fails the answer), and possible spans overlapping an entity are dropped. The
gateway vectors' `offsets` and `possible_emoji` cases pin this.

### Live findings (production)

2026-11-05 (smoke 27/27 on Node 22.23.4, 24.7.0 and 24.22.2, branch `feat/pq-auto`):

- Production serves a verified `v3` member: v3 key id 1000003 under delegation serial 1793526621
  (the v2 member's delegation).
- Automatic: `v3-native` on both Node 24 versions for every Protect and Detect scenario (long texts
  in parts included); `v2` on Node 22. Always Post-Quantum: `v3-native` on Node 24, `v3-noble` on
  Node 22 and with the `nativeMlKem: false` seam. The gateway opened every frame, so its Python
  X-Wing interoperates with Node.js's OpenSSL ML-KEM-768 and with the vendored one.

2026-10-21 (smoke 24/24 on the integration commit):

- Keyconfig v2 verifies against the pinned roots: key id 113, delegation serial 1792597552.
- Capabilities verify; `server_version` 2026.10.19.1, 19 entity types, all `default: on` (including
  `IBAN_CODE`, `IT_FISCAL_CODE`, `SOCIAL_HANDLE`). Server-only rows in the merged list:
  `IT_FISCAL_CODE` ("Codice fiscale (IT)", group Italy) and `SOCIAL_HANDLE` ("Social handles",
  General). **No `possible` types** (so `"possible": true` is
  never sent today and Include Possible IDs lists only the local rules), label languages `en`, `sl`.
- "Modra Vila d.o.o." came back as one LOCATION span including the legal form; `companySpans` (same
  as the extension) does not retype it, so it is `[LOCATION_...]`, not `[COMPANY_...]`. Server-side.

Earlier (2026-10-05/06, protocol v1; the detection notes still apply):

- Scores seen: 0.85 and 1.
- Size: 100k characters analysed in about 5 s; 1M characters gave a **502** after about 13 s (the
  BFF answers an oversized frame with a plain 413 `payload_too_large`, gateway `docs/HPKE.md`).
  Superseded by the per-request cap: since 2026-10-24 the hosted gateway publishes
  `max_text_chars=14000` (infra `docs/reports/2026-10-24-chunk-size.md`), and the node sends parts
  of 12 000. Smoke 2026-10-24 (server 2026.10.24.4): 40 067 characters in 4 parts, about 48 s.
- Detection quirks are server-side, not client bugs: "Janez Novak wrote from ..." and
  "Marko Horvat (...)" were not tagged PERSON; "Ana Kovač" was tagged as only "Kovač"; with a
  PERSON-only filter, "IBAN SI56" was tagged PERSON.
- **Identifier checksums are validated server-side** (probed 2026-10-06 with synthetic numbers through
  Detect): EMŠO, OIB, the Slovenian tax number and IBAN (spaced and compact) were detected with a
  valid check digit and ignored with the last digit changed. The old local `privacy-gateway` checkout
  (`ff46e51`) shows bare digit patterns; it predates this, so do not judge production by it. A spaced
  IBAN came back as `IBAN`, but the catalog also maps `IBAN_CODE`, so docs check both.
- `GET /health` is public and returns 200 with an empty body. Never use it to test anything.
- Not yet exercised live: `hpke_stale`, `hpke_replay`, 429, `busy`, a key rotation mid-run.

### Keyconfig and capabilities caches

Module-level `Map`s keyed by base URL and the pinned roots (so a test seam never shares state with
production), with `Date.now()` (timers are banned); they live for the n8n process.

- **Keyconfig:** the raw JSON is cached for 10 minutes and **re-verified on every use** (time
  windows, key expiry, the serial floor), never trusted as stored; an entry that no longer verifies
  is dropped and fetched once. A failed config is never cached. Acquisitions are serialised (one at
  a time per process). A rotation retry (`hpke_unknown_key` / `hpke_key_expired`) forces one
  refetch.
- **Capabilities:** a verified document is reused for 5 minutes (re-checked against its time window
  and the floor on every use); after a failed attempt the next one waits 5 minutes, and a cached
  document that still verifies is kept meanwhile. A missing credential (n8n's own error, nothing
  sent) or a 3xx, 401 or 403 is **not an attempt**: it returns the cached document (or `null`) and
  starts no backoff, because the cache is per process and shared by every credential. This goes
  further than the extension, which skips the backoff only for `auth_required` (not signed in). The
  cost: a deployment whose `/v1/capabilities` keeps answering 3xx/401/403 gets one capabilities GET
  per item. `fetchCapabilities` never throws.
- `effectiveMaxTextChars(caps)` = `min(max_text_chars, floor((max_body_bytes - 8192) / 6))` when
  that lies in [10 000, 1 000 000], else the bundled 10 000 (= `MIN_TEXT_CHARS`, so it never
  exceeds a cap a server publishes). Lives in `shared/limits.ts` (shared by `gateway.ts` and
  `chunker.ts`) and is re-exported from `gateway.ts`; `partTarget(caps)` = min(that - 2000, 100000).
- `clearGatewayCaches()` resets all of it (tests).

