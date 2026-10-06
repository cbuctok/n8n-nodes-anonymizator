# n8n-nodes-anonymizator verification submission

Cover note, reviewer notes and video outline for the community node verification request. This file
is not part of the npm package (`files` lists only `dist` and `NOTICE`).

## What to submit

| Field | Value |
| --- | --- |
| Package | `n8n-nodes-anonymizator` |
| Version | `0.1.1`, **pending**: cut it with `npm run release` and approve the staged version on npmjs.com, so it carries a provenance attestation from GitHub Actions. Also the version installed in the video. |
| Repository | https://github.com/cbuctok/n8n-nodes-anonymizator |
| Video | `<link>` |
| Node API version | 1 |
| Credential type | `anonymizatorApi` |
| Reviewer API key | TODO(reviewer-key): how the reviewer gets a working key |

**Do not submit `0.1.0`.** It was published by hand (npm only lets a trusted publisher be added to a
package that already exists), so it has no provenance attestation. Every later version is staged by
`publish.yml` from a tag.

Before sending, check:

- `npm view n8n-nodes-anonymizator@0.1.1 dist.attestations` is not empty;
- the README's Credentials section names where to get a key (TODO(api-key-portal));
- the reviewer has a key (TODO(reviewer-key)).

## Cover note

> Hello,
>
> Attached is the walkthrough video for `n8n-nodes-anonymizator`, plus the notes below on what it
> demonstrates and how it was verified.
>
> The node keeps personal data out of LLM prompts. **Protect** finds names, email addresses, IBANs,
> national ID numbers and similar data in a text and replaces them with placeholders such as
> `[PERSON_a7k2q]`; **Reveal** puts the real values back into the model's answer; **Detect** reports
> what a text contains without changing it, for routing. Detection runs on the Anonymizator privacy
> gateway operated by Prosecco 37: the text is HPKE-encrypted to the gateway, which answers with
> positions only. The placeholders, the map and Reveal are computed inside n8n.
>
> The video installs version 0.1.1 from npm through **Settings → Community Nodes**, creates the
> credential and runs its test, then runs the example workflow from the repository (Protect, a Basic
> LLM Chain, Reveal) and shows the round trip. Nothing is loaded from a local folder and nothing is
> patched on the instance.
>
> Happy to answer anything about the design, the encryption or the parts the video does not cover.
>
> Greg Evseev
> greg@digitaliziran.si

## How it differs from the built-in Guardrails node

The verification guidelines ask that a node not duplicate an existing one. Guardrails' **Sanitize
Text** overlaps in purpose, not in function (checked against `@n8n/n8n-nodes-langchain` 2.41.5):

- **Detection.** Guardrails' PII check is 36 regular expressions with no validation (no Luhn or
  mod-97 check), and none of its types is a person name; a name is caught only by a custom regex that
  lists it. Its LOCATION type is a street-suffix pattern. Anonymizator uses named-entity recognition
  on the gateway for names and locations, and recognisers for regional identifiers that Guardrails
  does not cover (Slovenian EMŠO, tax and ZZZS numbers, Croatian OIB, Austrian social insurance
  number). NER is statistical and can miss a name; the README says so.
- **Reversibility.** Guardrails replaces every value of a type with the same tag (`<EMAIL_ADDRESS>`)
  and has no restore step; it does list the matched originals in its `checks` output. Anonymizator
  gives each value its own placeholder, outputs a placeholder map, and has a Reveal operation that
  runs without a credential or network access. Masking styles (`[PERSON]`, `[REDACTED]`) exist too.
- **Where things run.** Guardrails' Sanitize Text runs inside n8n and sends nothing (its LLM-based
  checks are in Check Text for Violations and use the connected chat model). Anonymizator sends the
  encrypted text to its gateway for detection; the map is created and kept inside n8n.

## Similar verified community nodes

Each sentence is from reading the published package; none is a criticism.

- **Privent** (`n8n-nodes-privent`): offers a local regex mode and cloud modes that by default send
  the text over TLS to its backend, where the API-key mode also keeps the values; Anonymizator always sends
  the text HPKE-encrypted to a gateway that returns positions only, and keeps the map on the n8n item
  where it can be continued, shared across items or exported as an ID file.
- **Miravig** (`n8n-nodes-miravig`): detects entirely inside n8n with checksum-validated patterns and
  masks detected personal data with fixed tokens (its Unmask restores user-supplied glossary terms);
  Anonymizator sends text to a remote gateway for NER-based detection of names and locations and
  pseudonymises the detected values reversibly.
- **doccape** (`@scitlab/n8n-nodes-doccape`): its server performs the anonymisation and returns the
  result; Anonymizator's gateway returns positions only, and substitution, the map and the restore
  step run inside n8n.
- **PromptLock Guard** (`n8n-nodes-promptlock-guard`): scores text for compliance and prompt-injection
  risk, routes it to four outputs and redacts server-side with type tags; Anonymizator does no risk
  scoring or injection screening and focuses on reversible pseudonymisation with a local Reveal.

## Notes for the reviewer

- **Scope**: no runtime dependencies. `dist/` requires only `n8n-workflow` and Node.js's built-in
  `node:crypto`; `npm pack` yields 51 files (117 kB). No `eslint-disable` comments anywhere. The
  scanner (`@n8n/scan-community-package` 0.38.0) runs in CI on the source and on the packed tarball.
- **Transport**: every request goes through `helpers.httpRequestWithAuthentication`, so n8n's proxy
  settings and timeouts apply. There is no base URL field: the node only talks to
  `https://anon.prosecco37.com`, because it only trusts keys signed by a pinned root.
- **Encryption, fail closed**: the text is sealed with HPKE (RFC 9180, X25519 / HKDF-SHA256 /
  AES-256-GCM) to the gateway's current key and padded to fixed size buckets. The key configuration
  must carry an Ed25519 signature by the pinned trust root; if it does not (for example behind a
  TLS-inspecting proxy), nothing is sent and the item stops with an explanation. The implementation
  is checked against the RFC 9180 test vector and an independent HPKE recipient in the unit tests.
- **Ranges only, stateless gateway**: the gateway receives the encrypted text (and an optional
  entity-type filter) and answers with entity types, positions and scores. It never sees placeholders
  or the map. The README's "What leaves n8n" section lists every field sent.
- **Credential test**: `GET /v1/keyconfig` with redirects disabled. The gateway's front end answers
  a bad key with a 302 to its login page (or 401 when JSON is asked for), so the test maps 302 and
  401 to "API key rejected" and 403 to "no access to Anonymizator"; following the redirect would
  make a bad key look valid.
- **Reveal needs no credential**: the credential is declared only for Protect and Detect
  (`displayOptions`, as n8n's own Crypto node does), and Reveal makes no request.
- **Tool use**: `usableAsTool: true`. Everything a tool returns goes back to the model, so Protect
  has an **Include Placeholder Map** option (on by default for normal workflows): turned off, the
  tool returns only placeholders. Detect returns no values unless **Include Values** is on. Reveal
  carries a notice not to expose it as a tool where the agent's output leaves the user's control.
  The README has a safe recipe; the recommended layout is Protect before the agent and Reveal after.
- **Cost**: one gateway request per item for Protect and Detect (plus a key fetch at most every ten
  minutes); Reveal is free and offline. Items run one after another.
- **Execution data**: n8n stores the original text and the map in execution data like any output;
  the Protect notice says so, and the example workflow does not save successful production runs.

## Measured checks

Run on the commit to be tagged:

- `npm run lint`, `npx tsc --noEmit -p .`, `node scripts/check-node-fields.mjs`: pass.
- `npm test`: unit tests against `dist/`, including the RFC 9180 vector, a fake HPKE gateway for
  every status path, and differential tests against the Anonymizator browser extension's engine.
- `npm run scan`: `[PASS] source` and `[PASS] packed tarball`.
- `npm run smoke`: the built node against the production gateway with synthetic data (Protect in
  every style, Detect, Ignore Terms, Include Placeholder Map off, Reveal, a rejected key).
- `npm run e2e`: a real n8n 2.41.7 in Docker runs a 19-node workflow covering every operation and
  option, checks the credential test and the tool variant, and imports the example workflow.

## Video outline

1. **Install**: Settings → Community Nodes → Install → `n8n-nodes-anonymizator` (version 0.1.1).
   Show the node in the nodes panel (search "PII" or "anonymize").
2. **Credential**: create an **Anonymizator API** credential, paste the key, save, and show the
   successful test. Optionally show a wrong key giving "API key rejected".
3. **Example workflow**: import `examples/protect-llm-reveal/workflow.json`, select the credential
   on *Protect* and an OpenAI credential on the chat model.
4. **Run**: open *Protect* and show `protectedText` with placeholders and the `placeholderMap`; open
   *Draft Reply* and show the model saw only placeholders; open *Reveal* and show `revealedText`
   with the real values and an empty `unresolvedPlaceholders`.
5. **Detect**: add a Detect node on the same text and show `hasPersonalData` and `countsByType`.
6. **Tool use (short)**: attach Anonymizator to an AI Agent as a tool with Include Placeholder Map
   off and show the tool output carries no map.

## Placeholders to replace before sending

- `<link>`: the video URL.
- TODO(api-key-portal): where users and reviewers get an API key (also in the README and the
  credential).
- TODO(reviewer-key): a working key for the reviewer, and how it is delivered.
- If the video was recorded against a version other than 0.1.1, correct the version row.
