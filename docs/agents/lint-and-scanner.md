# Lint and scanner gotchas, dependencies

_Moved out of `AGENTS.md` (2026-11-05). Section names quoted in the text may now live in a sibling file under `docs/agents/`; `AGENTS.md` has the index._

## Lint and scanner gotchas

These were all found by hitting real failures. Do not undo them.

- **Local lint is not the gate; the scanner is.** Local `n8n-node lint` uses lint plugin 0.35.0;
  the scanner (0.40.0, checked 2026-10-22) uses 0.37.0. A codex with `"Developer Tools"` passes local lint and fails the
  scanner's `valid-node-categories`. Valid categories: `Data & Storage`, `Finance & Accounting`,
  `Marketing & Content`, `Productivity`, `Miscellaneous`, `Sales`, `Development`, `Analytics`,
  `Communication`, `Utility`. Run `npm run scan` before every release; override the scanner
  version with `SCAN_VERSION`.
- **The scanner ignores `eslint-disable` comments** (`allowInlineConfig: false`). A suppression that
  makes local lint pass still fails verification. There are none in this repo; keep it that way.
- **`no-hardcoded-secrets` checks names, not just values.** A constant whose name contains
  `key`, `auth`, `token`, `secret`, `cert`, `password` or similar, holding a 16+ character
  base64/hex-looking string, fails. `ROOT_PUBLIC_KEYS = ['lgcs...']` fails; `TRUST_ROOTS_B64URL`
  passes. A plain string constant trips it too: `KEYCONFIG_HEADER = 'pgw-keyconfig-v2'` failed and is
  `KC_DOCUMENT_HEADER`.
  The same goes for the DER prefixes (`X25519_SPKI_PREFIX`, `ED25519_SPKI_PREFIX`) and any test
  vector that would ever live under `nodes/`.
- **Banned globals:** `globalThis`, `global`, `process`, `setTimeout`, `setInterval`,
  `setImmediate` and their `clear*`, `__dirname`, `__filename`. Use `sleep` from `n8n-workflow` for
  the retry pause. `Buffer`, `TextEncoder`, `BigInt` and `URL` are fine. The scanner checks `dist/`
  too.
- **`require-node-api-error` (scanner plugin 0.35.0 and later) flags any `throw` written lexically inside a
  `catch`, in any file under `nodes/`,** unless it throws `NodeApiError` or `NodeOperationError`.
  Helpers record the failure in a variable inside the catch and throw after it (see `send`,
  `sealFor` in `gateway.ts`, and the JSON parse in `placeholderMap.ts`).
- **`no-dangerous-functions`** bans `eval`, `new Function` and `child_process` in `nodes/`. Tests
  load the extension's scripts with `node:vm`, which is fine because `test/` is not scanned.
- **`missing-paired-item`**: every returned item carries `pairedItem: { item: itemIndex }`.
- **`n8n.strict: true`** makes `n8n-node lint` compare `eslint.config.mjs` against the CLI's default.
  `eslint.config.mjs` and `tsconfig.json` are byte-for-byte judgment's (and the CLI template's); do
  not edit them.
- **Icon paths resolve relative to the referencing file:** `file:../../icons/...` in the node,
  `file:../icons/...` in the credential. Light and dark must be different files.
- **`documentationUrl` must be a full URL** (the README's `#credentials` anchor), not a slug.
- **The AI tool variant may run without `getNode`.** Every error builds its node through
  `errorNode(this)`, which falls back to a stub descriptor instead of throwing
  "this.getNode is not a function" from inside the error handler.
- **Dynamic multiOptions have naming rules.** A `loadOptionsMethod` multiOptions must have a
  display name ending in "Names or IDs" (hence "Entity Type Names or IDs") and a description ending
  in "Choose from the list, or specify IDs using an
  <a href=\"https://docs.n8n.io/code/expressions/\">expression</a>." The parameter name and values
  stay `entityTypes` and the row ids. Return the options sorted by name.
- **Read collections whole.** `getNodeParameter('options.x')` does not work; read `options` and index
  it, comparing booleans with `=== true`.
- **The codex is what verification review bounces on.** Since August 2026 the reviews of
  pdf-redaction, trustguard and judgment each came back for exactly the codex `node` id (must be
  `<package>.<node>`) or an undocumented category (`AI`, `Developer Tools`, `Security`). Both are
  pinned by `test/scaffold.test.mjs`. `alias` is a valid codex field (`CodexData.alias?: string[]`
  in `n8n-workflow`; the scanner accepts it) and only feeds panel search.
- **Comments must be in English.** Manual review once rejected Miravig's submission (verified since) for non-English
  inline comments, a rule the scanner does not check. Keep every comment in `nodes/`, `credentials/`,
  `scripts/` and `test/` in English, including in code ported from the extension.
- **The credential test request needs `disableFollowRedirect: true`** and `responseCode` rules for
  302, 401 and 403. Without them an invalid key passes the test, or fails with n8n's unhelpful
  "Found". n8n 2.x applies `authenticate` to the test request; the header is repeated in `test`
  anyway for versions that build it from the request object alone.
- **Testing the credential over REST needs the stored data.** `POST /rest/credentials/test` with
  `data: {}` reports "API key rejected" for a good key, because n8n only fills in the stored secret
  when the request marks the field as hidden. Fetch the credential with `?includeData=true` first and
  send that back, as the editor does. On n8n 2.41.7 and 2.44.5 the endpoint works (judgment's note that it is
  broken applies to 2.39.6).

## Dependencies and the security posture

The package ships no runtime dependencies: no `dependencies` field, `peerDependencies` is only
`n8n-workflow: "*"` (n8n supplies it; pinning it would fight the host), and `dist/` requires only
`n8n-workflow` and `node:crypto`. The scanner is not a devDependency: `scripts/scan.mjs` installs it
once into `node_modules/.cache/scan-community-package-<version>` (or uses `SCAN_PACKAGE_DIR`), since
it pins its own eslint and TypeScript.

`npm audit` findings in the build toolchain or nested inside `n8n-workflow` are upstream concerns.
Do not run `npm audit fix` (in judgment it downgraded `@n8n/node-cli` to 0.1.0 and broke lint) and do
not add `overrides` (rejected by `no-overrides-field`). The check that matters is what `dist/`
imports.

