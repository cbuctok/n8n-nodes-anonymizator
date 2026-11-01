# Changelog

## 0.4.0 - 2026-11-01

### Added

- Added an EXPERIMENTAL, off-by-default credential option, **Post-Quantum Encryption
  (Experimental)**, shown only after **Show Experimental Options** is turned on. With both on,
  **Protect** and **Detect** encrypt the text with the gateway's experimental protocol version 3
  (X-Wing: X25519 and ML-KEM-768) and fail, sending nothing, when the gateway does not offer it,
  instead of using standard encryption. The ML-KEM-768 and SHA-3 code is a vendored subset of
  `@noble/post-quantum` 0.7.1 and `@noble/hashes` 2.4.0 (MIT); the package still has no runtime
  dependencies. Off, nothing changes.

### Removed

- Removed the error codes `text_too_large` and `hpke_bad_keyconfig`, left over from the gateway's
  protocol v1 and no longer produced; the gateway has dropped protocol v1 and serves only the v2
  key configuration, which this node already used exclusively. The test vectors were copied again
  from the gateway without their v1 parts.

## 0.3.0 - 2026-10-24

The hosted gateway now accepts at most 14,000 characters per request, so that every request finishes
within its time budget; clients split longer texts. This node now does, in the same way as the
Anonymizator web app and browser extension, and is meant as the reference for calling the API
directly (README, "Long texts: how the node splits them").

### Changed

- **Protect** and **Detect** no longer refuse a long text. A text longer than the gateway's
  per-request limit is cut at line ends into parts 2,000 characters below that limit (12,000 on the
  hosted gateway), the parts are analysed one after another, each encrypted separately, and the
  results are put back together over the whole text, so a value cut at a part boundary is still
  protected whole and one value keeps one placeholder across all parts. If any part fails, the item
  fails as a single request would, with no partial output, and the message names the part.
- A part of a long text that the gateway rate-limits is sent again after the wait the gateway asks
  for (at most three times, at most 60 seconds each). A short text still stops at once with "Too
  many requests".
- The built-in per-request limit, used when the gateway's signed capabilities cannot be loaded or
  checked, went from 120,000 to 10,000 characters, the smallest limit the node accepts from a
  gateway, so the node never sends more than a gateway takes.
- The node waits up to 60 seconds (was 30) for each analysis request, as long as the gateway's CDN
  does.
- "The text is too long" became "Part of the text was too long for one request"; it names no limit
  and no longer tells you to split the text into items.

## 0.2.0 - 2026-10-22

Brought in line with the Anonymizator browser extension 2026.10.19.1, as listed below.

The `0.1.2` tag was created by mistake: a bug in the release script turned the chosen minor bump
into a patch bump. 0.1.2 was never published to npm; this release contains its changes.

### Added

- Added the **Additionally Protect** option to **Protect**: **All Numbers**, **All Currency
  Values** and **Company Names (With Legal Suffixes Only)**, worked out inside n8n and never sent.
- Added the **Include Possible IDs** option to **Protect** and **Detect**. **Protect** lists text
  left in clear that you may want to check (a surname, "Mr. Zupan", a Slovene case form such as
  "Luki", a company name without its legal form) and, like **Detect**, what the gateway flags for
  review when it offers that. Possible IDs are a prompt to look, not a score; they are never
  replaced.

### Changed

- **Protect** and **Detect** switched to version 2 of the gateway's encryption protocol; version 1
  is no longer used. The gateway's key configuration is now checked through a signed chain from two
  root keys built into the node (a primary and a backup) to keys with a signed expiry, and nothing is
  sent when the check fails.
- The **Entity Types** list (now titled **Entity Type Names or IDs**) uses the browser extension's
  names and also shows the types the gateway's signed capabilities add, such as `IT_FISCAL_CODE`, so
  new types appear without a node update. If the list cannot be loaded or checked, the built-in one
  is used. Saved selections keep working.
- In **Protect** and **Detect**, selecting every built-in entity type now means **All Types**, so
  the types the gateway adds (`IT_FISCAL_CODE`, `SOCIAL_HANDLE`) are detected too. Any other
  selection sends exactly the selected types.
- **Protect** and **Detect** refuse a text over the gateway's limit (120,000 characters, or the
  limit its signed capabilities state) before the text is sent, and the message names the limit.
- **Protect** uses the browser extension's placeholder prefixes: `[EMAIL_x7gs2]`, `[PHONE_…]`,
  `[IBAN_…]`; **Type Only** prints `[EMAIL]`, `[PHONE]`, `[IBAN]`. The `entityType` output is
  unchanged (`EMAIL_ADDRESS`), and maps with the older keys (`EMAIL_ADDRESS_…`) still reveal and can
  be continued.
- **Protect** turns a found name followed by a legal form (d.o.o., d.d., s.p., GmbH, AG, Ltd, Inc.,
  LLC and similar) into one `[COMPANY_…]`, and protects the same name without the legal form
  elsewhere in the text as a company too. Placeholders already in the text, your own or another
  tool's, are left as they are.
- **Detect** reports such a name as one `COMPANY`, legal form included, as **Protect** replaces it,
  also when part of the name is an **Ignore Terms** entry, and trims spaces off the edges of every
  detection and possible ID.
- The placeholder styles are named as in the browser extension: **Random**, **Numbers in Order**,
  **Type Only** and **Redacted**. Saved workflows are unaffected.
- **Include ID File** writes ID file version 2, with types and groups, still only for **Random** and
  **Numbers in Order**. **Reveal** and **Existing Placeholder Map** read ID file versions 1 and 2.
- **Reveal** and **Existing Placeholder Map** given a whole **Protect** output item use its ID file
  when it is current, so groups and types are kept, and otherwise its `placeholderMap`, also when
  the item carries ID file fields copied from its input.
- **Ignore Terms** in **Protect** now also covers company names, **Additionally Protect** matches
  and possible IDs; values of an existing map are still replaced.
- An existing map with one value under two placeholders no longer stops **Include ID File**: the
  first placeholder protects the value and the other only reveals it.
- **Share Map Across Items** merges whole ID sets, groups and name parts included, and accepts the
  same value under different placeholders in different items: the first placeholder protects it,
  the other only reveals it.
- **Additionally Protect** set by an expression ignores case and spaces, and an unknown value stops
  the item before anything is sent instead of being ignored.
- Error messages follow the browser extension's wording, cover every gateway answer, and never show
  text sent by the server. Each analysis is sent at most twice, freshly encrypted each time: again
  after a key rotation, or a second later after a server error, never after a refused repeat, a rate
  limit or a wrong clock. Refused entity types still lead to one more try with all types.
- Emoji are no longer replaced by spaces before the text is sent; the gateway's positions are
  converted instead, and an answer with a position outside the text is refused rather than used.
- **Detect** reports a detection whose type the gateway sent malformed as `PII`.

### Fixed

- **Protect** and **Detect** inside n8n report a network failure or timeout as "offline" or
  "timeout" again, instead of n8n's generic request error.
- **Protect** and **Detect** no longer resend an analysis when the gateway's encrypted answer came
  with a server-error status but reports a refusal, such as an invalid payload.
- A rejected API key or a missing credential no longer stops the gateway's entity type list from
  loading for every other credential in the n8n process for 5 minutes.
- "The text is too long" names the character limit only when the node refused the text itself; a
  refusal from the gateway no longer claims a limit the text had already passed.
- **Include Input Fields** in **Protect** no longer copies `possibleIds`, `possibleIdsTruncated`,
  `entityFilterIgnored` or `idFile` from the input item, and in **Detect** no longer copies
  `possibleIds`, `possibleIdsTruncated` or `entityFilterIgnored`, so they never describe another text.
- **Protect** with an **Existing Placeholder Map** that is a flat map protects everything it holds:
  name parts of a person whose placeholder has no generated suffix (`PERSON_CEO_SURNAME`), name parts
  of a full name listed under an earlier placeholder, and name parts with no full name beside them.
  A flat map's placeholders keep their type, so types the gateway adds (`[SOCIAL_HANDLE_…]`) are no
  longer turned into `[CUSTOM]`.
- **Reveal** and **Existing Placeholder Map** accept a map with a value written in brackets, such
  as `"[ACME]"`, instead of calling it reversed.
- **Additionally Protect** with **All Numbers** no longer cuts into placeholders an earlier
  **Protect** wrote for types the gateway adds, such as `[SOCIAL_HANDLE_1]`.
- **Share Map Across Items** protects a value again when a later item's map holds it under a
  placeholder that an earlier item had only as reveal-only, and a name part whose person became
  reveal-only no longer makes every later item fail.
- **Protect** with a large existing or shared map, with **All Numbers**, with many names and
  **Include Possible IDs**, or with a crafted long word no longer takes seconds per item, and the
  possible IDs are worked out only when **Include Possible IDs** is on.
- **Reveal** with a placeholder map of hundreds of thousands of entries no longer spends seconds
  before it starts.

## 0.1.1 - 2026-10-06

- Added the **Detect** operation: it runs the same gateway detection as **Protect** without changing
  the text and returns `hasPersonalData`, `entityCount`, `countsByType` and the entities with
  offsets into the original text, for routing before an LLM call. The matched values are added only
  with the new **Include Values** option.
- Added the **Include Placeholder Map** option to **Protect** (on by default, so existing workflows
  behave as before). Turned off, the output carries no `placeholderMap` and no `idFile`, for use as
  an AI Agent tool where the map would hand the real values back to the model.
- Added the **Ignore Terms** option to **Protect** and **Detect**: detections equal to a listed term,
  such as a company or product name, are left alone. Values already in an existing placeholder map
  are still replaced.
- **Reveal** now warns that its output holds the real values and should not be given to an AI agent
  whose output leaves your control, and hints at the usual Text and Placeholder Map expressions.
- Added an importable example workflow (Protect, Basic LLM Chain, Reveal), a "What leaves n8n"
  section, a safe AI tool recipe and a corrected comparison with the Guardrails node to the README,
  plus `SECURITY.md` and search aliases for the nodes panel.

## 0.1.0 - 2026-10-05

- First release of the **Anonymizator** node and the **Anonymizator API** credential.
- **Protect** detects personal data through the Anonymizator privacy gateway and replaces it with
  placeholders locally. The text is HPKE-encrypted to the gateway, whose signed key configuration is
  checked against a pinned trust root before anything is sent; the gateway returns positions only.
- Four placeholder styles: **Random** (`[PERSON_a7k2q]`, default), **Sequential** (`[PERSON_1]`),
  **Type Only** (`[PERSON]`) and **Redacted** (`[REDACTED]`).
- Detect all supported types or a selection of 16, including person names, IBANs and Slovenian,
  Croatian and Austrian identifiers. Person names also get first-name and surname placeholders.
- Options to continue an existing placeholder map, share one map across all items of an execution,
  include an ID file for the Anonymizator browser extension, and include the input fields.
- **Reveal** puts the original values back from a placeholder map or an extension ID file, entirely
  inside n8n with no credential, and lists any placeholders it could not resolve.
- Usable as an AI Agent tool.
- No runtime dependencies: the node is built only against `n8n-workflow` and Node.js's built-in
  `crypto`.
