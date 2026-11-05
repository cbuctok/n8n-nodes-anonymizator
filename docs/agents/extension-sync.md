# Keeping the port in sync with the extension

_Moved out of `AGENTS.md` (2026-11-05). Section names quoted in the text may now live in a sibling file under `docs/agents/`; `AGENTS.md` has the index._

The engine and the gateway client are a port of the Anonymizator Chrome extension (checkout
`/home/ubuntu/repos/prosecco37/anonymizator-chrome`, extension files under
`anonymizator-chrome-ext/`; remote `git.pushin.eu:prosecco-37/anonymizator-chrome`). **`lib/anonymizer.js`
there is a byte-for-byte mirror of the public CDN copy** (`get.prosecco37.com/pgw/anonymizer.js`,
also loaded by the anon.prosecco37.com demo), so upstream treats it as frozen and changes it
deliberately. The gateway side of the contract is `docs/HPKE.md` in the gateway repository
(`/home/ubuntu/repos/prosecco37/anonymizator`), especially "Client conformance (third-party ports,
e.g. the n8n node)"; the vectors in `test/fixtures/` are copied byte for byte from its
`tests/vectors/`.

Ported from extension **2026.10.19.1**, repository HEAD `74dc94b` (2026-10-21). The extension's
history was rewritten on 2026-10-19, so the old `a4c773b` (0.15.0) baseline no longer exists. The
long-text parts (chunker) were ported on 2026-10-24 from `origin/dev` at `de85568` (extension
2026.10.24.2); read the extension with `git show origin/dev:<path>` when the local checkout is behind.
Last upstream commit per source file at port time:

| Extension file | Ported to | Upstream commit |
| --- | --- | --- |
| `lib/anonymizer.js` (sha256 `0df5204e...`) | `shared/anonymizer.ts` | `967b3ec` (2026-10-09) |
| `lib/hpke.js` (sha256 `ee0f1f54...`) | `shared/hpke.ts`, `shared/keyconfig.ts`, `shared/capabilities.ts` | `1c35fbd` (2026-10-09) |
| `lib/gateway.js` (keyconfig acquisition, analyze, status handling) | `shared/gateway.ts`, `shared/errors.ts` | `3656111` (2026-10-19) |
| `lib/capabilities.js`, `lib/entities.js` | `shared/gateway.ts` (`fetchCapabilities`), `shared/entities.ts` | `3e50316` (2026-10-19) |
| `lib/chunker.js` (body identical to the web app's `demo/js/engine/pgw-chunker.js`), `lib/messages.js` (`analyzePart`, `runProtectParts`), `lib/gateway.js` (`MAX_TEXT_CHARS` 10 000, `codePointLength`, `effectiveMaxTextChars`) | `shared/chunker.ts`, `analyze` in `shared/gateway.ts`, `shared/limits.ts` | `1488b79` (2026-10-24, on `origin/dev`) |
| `lib/id-model.js`, `lib/id-rules.js`, `lib/id-names.js` | `shared/idModel.ts` | `3e50316` (2026-10-19) |
| `lib/extra-detect.js` | `shared/extraDetect.ts` | `3e50316` (2026-10-19) |
| `sidepanel/sidepanel-idfile.js` | `shared/placeholderMap.ts` | `3e50316` (2026-10-19) |
| `lib/id-edits.js`, `lib/id-possible.js`, `lib/messages.js` (Protect handler) | `shared/protectPipeline.ts`, `shared/possible.ts`, `actions/protect.ts` | `3656111` (2026-10-19) |
| `sidepanel/sidepanel-constants.js` (error wording) | `shared/gatewayMessages.ts` | `fc77565` (2026-10-16) |
| `lib/constants.js` (`ROOT_KEYCONFIG_PUBKEYS`) | `TRUST_ROOTS_B64URL` in `shared/keyconfig.ts` | `b87ce42` (2026-10-08) |

`lib/id-set.js` (`isValidKey`, `mask`) from the 0.15.0 port is still in `shared/anonymizer.ts`.

To check for drift:

```
git -C /home/ubuntu/repos/prosecco37/anonymizator-chrome log --oneline 74dc94b..HEAD -- \
  anonymizator-chrome-ext/lib anonymizator-chrome-ext/sidepanel/sidepanel-idfile.js \
  anonymizator-chrome-ext/sidepanel/sidepanel-constants.js
npm test   # the differential and interop cases load the extension's current files
```

and, for the protocol, `git -C /home/ubuntu/repos/prosecco37/anonymizator log -- docs/HPKE.md
tests/vectors` (re-copy changed vectors byte for byte).

Port every behavioural change, add the extension's new test cases to `test/`, and update the table
above. Deliberate differences are listed in the headers of `shared/anonymizer.ts`,
`shared/protectPipeline.ts`, `shared/idModel.ts` and `shared/entities.ts`. These change no result
for valid input: `randomInt` instead of a modulo over random bytes, a `Map` for the reverse index
(so "constructor" never resolves to a prototype member), own-property lookups, the 9-digit cap on
sequential counters, a word-run lookup in `revealText` and `mintedInClear`, an `isSkipped`
predicate instead of the stored skipped/ignored lists, and these performance guards: `revealText`
skips the `Object.keys` emptiness check (seconds on a 900k-key map), `pgwSpansFromTable` and the
possible-ID searches skip a value whose first letter/digit run is not a whole run of the text
before compiling its regex, the possible-ID case-form rule looks words up by stem instead of
testing every name token, and `anonymizeReserved` tests each ASCII word run on its own with an
anchored pattern and skips runs longer than 82 characters (the longest mintable key: 64-character
type, `_`, 9 digits, `_SURNAME`) instead of running the extension's `\b` pattern over the whole
text, which backtracks quadratically. These do change results, on inputs the extension never meets:
`fromV1` turning a value under several keys into reveal-only aliases and keeping name parts
protected, `flatTypeFromKey`, `extraBlockTest`, the `entityFilter` rule above, and the Share Map
merge rules. Not ported: storage,
locks, rev/dirty/epoch bookkeeping, the session queue, the side panel, the `opt_in` default and
stored entity deviations, OIDC refresh, the extension's `self`/`window` globals, and from the
long-text run its progress in `chrome.storage.session`, `CANCEL_PROTECT` and the service-worker
keepalive (an n8n item has no panel to report to; the chunker's `headingEnds` option is ported but
unused, since the node's input is plain text). The chunker's error texts say `chunker` instead of
`anonChunker`, and its exports are not frozen.

