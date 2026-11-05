# Placeholders, maps and the extension

_Moved out of `AGENTS.md` (2026-11-05). Section names quoted in the text may now live in a sibling file under `docs/agents/`; `AGENTS.md` has the index._

### The ID set and the Protect pipeline

Protect works on an **ID set** (`PipelineState` = the extension's state v2 content, `idModel.ts`):
`ids` (records `{value, key, type, mine, main}`, newest first; `main: false` marks other members of
a group), `subKeys` (PERSON name parts `{of, value, rec}`), `aliases` (reveal-only placeholders),
`used` (retired keys) and `numbering`. `protect(state, text, spans, {extra, detected, isSkipped,
findPossible})`
in `protectPipeline.ts` is the extension's `anonIdEdits.anonymize`, in its order: companies by legal
form (`companySpans`), skipped values dropped, Additionally Protect spans merged with the gateway and
table spans (`mergeExtra`), prefixes (`withPrefixes`), `anonymizeReserved` around the CDN-mirrored
`anonymizeFromSpans`, new records stored, one relabel / mask splice, then the possible IDs
(skipped with `findPossible: false`, which Protect passes when Include Possible IDs is off; the
default is on, as in the extension). It mutates the state in place; `revealTable(state)` is the reveal table. The item's state is the ID
file's set when Existing Placeholder Map is an ID file, else `fromFlatMap` (= `anonIdModel.fromV1`)
of the flat map; **the node's Placeholder Style always wins** over a file's `numbering` (the
extension locks numbering per set instead), and a masked style drops reveal-only aliases.

### Placeholder styles

`random` (default, display name **Random**, `[PERSON_a7k2q]`: 5 characters a-z0-9, lowercase so the
suffix never reads as part of the uppercase type), `sequential` (**Numbers in Order**, `[PERSON_1]`,
continuing the counters already in the set), `typed` (**Type Only**, `[PERSON]`, masking) and
`redacted` (**Redacted**, `[REDACTED]`, masking). Placeholders use the extension's **prefixes**:
`EMAIL_ADDRESS` -> `[EMAIL_x7gs2]`, `PHONE_NUMBER` -> `[PHONE_...]`, `IBAN_CODE` -> `[IBAN_...]`,
otherwise the type code; Type Only prints `[EMAIL]`, `[PHONE]`, `[IBAN]`, `[COMPANY]`. The output
`entityType` stays the record type (`EMAIL_ADDRESS`), and old keys such as `EMAIL_ADDRESS_x` in an
existing map still work. Masked styles **mint records too** (random internal keys, as the extension
does) but print `[PREFIX]` / `[REDACTED]` and output `placeholderMap: {}`; Include ID File writes
nothing for them (as before the parity work), so a workflow saved with Type Only or Redacted and
Include ID File on never starts to output the real values. PERSON entries also mint `KEY_NAME` (first token) and `KEY_SURNAME` (the rest) after
stripping leading titles (Mr, Dr, Herr, gospa, `g.`, ...), so "Janez" alone later reveals correctly.
Sub-keys never overwrite an existing entry.

**Companies.** A found PERSON or LOCATION followed by a legal form (d.o.o., d.d., s.p., GmbH, AG,
Ltd, Inc., LLC, Corporation, S.p.A., ...) becomes one `[COMPANY_...]`; the same name without the
form elsewhere in the text is a COMPANY too, with its own ID. Companies get no `_NAME` / `_SURNAME`
parts. **Own and foreign-minted placeholders** already in the text (`[PERSON_1]`, `[PERSON_a7k2q]`)
are left alone (`ownPlaceholderTest`, `FOREIGN_MINTED_RE`), and a key the text already spells is
never minted (`mintedInClear`, here with a word-run lookup). Additionally Protect uses a wider test,
`extraBlockTest`: it also leaves alone a placeholder minted for **any** entity type code with a
digit-bearing suffix (`[SOCIAL_HANDLE_1]`, `[IT_FISCAL_CODE_a1b2c]`), where the extension's NUMBER
rule would cut it into `[SOCIAL_HANDLE_[NUMBER_1]]`. Gateway spans and minting keep the extension's
`ownPlaceholderTest`; malformed tokens such as `[EMAIL_1x]` are still cut, as in the extension.

**Additionally Protect** (`extraDetect.ts`, option values `NUMBER`, `AMOUNT`, `COMPANY`; local only,
never sent): NUMBER is every token holding a digit (K101, INV-2024-118, 15.5.2026; side effect: in
`info@acme2.si` the part `acme2.si`), AMOUNT an amount with €, $, £, EUR, USD, CHF or GBP before or
after it (4.800,00 EUR, €4.800, CHF 300), COMPANY one to four name words plus a legal suffix
(Modra Vila d.o.o.). Matchers are atomic: a run is taken whole or not at all. `readExtra` trims and
upper-cases each value (a list, or comma/space-separated text from an expression); blank, `null` or
`[]` means off, and anything else (an unknown value, a non-text entry, a number or object) is a
NodeOperationError naming Additionally Protect, before anything is sent.

**Possible IDs** (`possible.ts`, option `includePossibleIds`, Protect and Detect): in Protect,
variants of IDs in the set left in clear (company name without its legal form, surname,
title + surname "Mr. Zupan", Slovene case forms "Luki", "Zupanu" for tokens of 4+ letters) plus the
gateway's review-only `possible` spans (`detectedValues`, kind `detected`); never replaced; sorted,
no overlaps, capped at 50 (`possibleIdsTruncated`). Computed only with the option on
(`findPossible: false` otherwise). Output `{start, end, value, kind, type}` with
offsets into `protectedText`; the kinds that occur are `company-name`, `surname`, `title-surname`,
`case-form` and `detected` (the `number` / `amount` / `company` kinds exist in the port but the node
never passes the extension's typed-after-Protect extras). In Detect, only the gateway's spans:
`{entityType, start, end}` (+ `value` with Include Values), original-text offsets, never counted in
`entityCount` / `countsByType`. `"possible": true` is requested only when the option is on **and**
the verified capabilities list possible types (none in production on 2026-10-21). Wording, from the
extension: "a prompt to look, not a score". There is no confidence field; do not add one.

### Accepted map formats (`parsePlaceholderMap`)

One normaliser serves Reveal's Placeholder Map and Protect's Existing Placeholder Map:

- a JSON string of any of the below (a json parameter set by expression may arrive as either);
- an extension ID file, version 2 or 1, validated with the extension's own rules in the same order
  (its sentence first, then a detail that never repeats a value; a wrong version gives "Only
  versions 1 and 2 are supported."). v1 values are trimmed, and values differing only by spaces are
  duplicates. The result carries `set` (records with type / mine / main, name parts, reveal-only
  aliases, used, numbering) besides `table` (main values, then name parts, then reveal-only), `used`
  and `mine`; group members other than the main are only in `set`. A masked file keeps its table;
  Placeholder Style wins;
- an array of `{placeholder, value}` (or `{key, value}`; `addedByYou` is honoured);
- a plain object with bare (`PERSON_a7k2q`) or bracketed (`[PERSON_a7k2q]`) keys;
- a whole Protect output item (`{ placeholderMap, idFile? }`, also only `{ idFile }`), in this
  order: its nested `idFile` when that parses and **covers** the `placeholderMap` (every map entry
  reveals the same, every used key is known), because it is lossless (groups, types); else its
  `placeholderMap`; an `idFile` that does not parse is reported only when there is no
  `placeholderMap`. Only an object with neither is read by its top-level `format` (an ID file) or
  as a flat map. The coverage check keeps a stale `idFile` (or top-level ID file fields such as
  `format` and `ids`, which Include Input Fields can copy from an input file) from winning over the
  item's newer map. A bare `placeholderMap` holds only each group's main value, so group members
  from an extension ID file are lost when only it is chained; the README tells users to chain the
  `idFile` or the whole item.

Every key must pass `isValidKey`: `^[A-Z][A-Za-z0-9_]*$` with at most 9 trailing digits. The digit
cap is a DoS guard: the extension's sequential counter loops forever on a key like
`PERSON_99999999999999999999`, which loses integer precision. Empty or whitespace values are
**tombstones**: they go to `used` (never re-minted) and never into the reveal table, where they
would erase text. Reversed maps (`{"Janez Novak": "PERSON_x"}`) get a specific error. A bracketed
value counts as reversed only when the key is not a valid placeholder, or the value looks minted
(`TYPE_suffix`) and the key does not: `{"Janez": "[PERSON_1]"}` is refused, while an ID written in
brackets (`"[ACME]"` under `CUSTOM_ab12c`), which Protect itself writes into its map, is accepted. Error messages
name valid keys and entry positions but **never echo values**, which are the protected data: an
invalid key is named by its entry number (it may be a real value in a reversed or mangled map), and
a JSON syntax error reports only the line and column, never V8's own message, which quotes a slice of
the input for an unexpected token. Insertion order is preserved, because the first key for a value
wins.

Protect's output `placeholderMap` is `revealTable(state)` (each main value with its name parts,
oldest first, then the reveal-only placeholders) plus every retired key (tombstone) with an empty
value, so a map passed back in as Existing Placeholder Map keeps them retired; `{}` for masked
styles. The ID file is built from the set (its `usedPlaceholders` carries the tombstones), because
the extension refuses blank values. A flat map with one value under two keys converts with the
`fromV1` rule: the first key protects, the others become reveal-only aliases, so Include ID File no
longer refuses it. Name parts never lose protection in `fromV1`: a key with `_NAME` / `_SURNAME`
parts is a PERSON whatever its suffix (`PERSON_CEO`), a part whose person is not a live PERSON
record (its key became an alias) joins the PERSON record holding that person's value, and a part
with no such record becomes a PERSON record of its own; only a part whose value a record already
holds becomes reveal-only.

Values already in the set are matched in the text as exact, Unicode word-bounded terms
(`pgwSpansFromTable`), so they are replaced even when the gateway does not detect them. A record's
type comes from its key's prefix (`EMAIL` -> `EMAIL_ADDRESS`). In a flat map (`fromV1` only,
`flatTypeFromKey`) a `TYPE_suffix` key keeps any entity type code as its type, so server-only types
survive the round trip (`SOCIAL_HANDLE_o1b30` is SOCIAL_HANDLE) and hand-written keys follow the
same rule (`CASE_1` is CASE, not CUSTOM, a deliberate deviation); a key that does not parse as
`TYPE_suffix` is `CUSTOM`. ID files carry their types and are unaffected. Protect's `entities` hold only `{entityType, placeholder, start, end,
score}`, never `value` or `key`.

### Reveal

Every ASCII word run in the text, bracketed (`[KEY]`) **or bare and word-bounded (`KEY`)**, is looked
up in the table through a replacement callback (so `$&` in a value is literal). The extension
instead compiles all keys, longest first, into one regex alternation; because every valid key is a
single word run the results are identical, but that pattern made V8 abort the whole n8n process
(uncatchable) at a few hundred thousand keys, so do not port it back. The bare form is inherited from
the extension; it means a user key such as `CLIENT` is also replaced where the LLM writes the word
`CLIENT`.
`unresolvedPlaceholders` lists bracketed tokens matching `\[[A-Z][A-Za-z0-9_]*\]` in the **input**
text that the map does not resolve (so masked `[PERSON]` / `[REDACTED]` show up, and a revealed value
that happens to contain brackets does not).

### ID file interop

With Include ID File, Protect adds `idFile`, a **version 2** file the extension's **Load IDs**
accepts, written exactly like its `anonSerializeIdFile`: `{format: 'anonymizator-id-file',
version: 2, name, numbering, ids: [{value, placeholder: '[KEY]', type, addedByYou, main?}] (newest
first), nameParts: [{placeholder, value, of, from}], revealOnly: [{placeholder, value, of}],
usedPlaceholders}`. Minted records get `addedByYou: false`; records the user marked as their own in
an input ID file keep `true`. `toIdFile(state)` validates the set with the extension's rules
(`IdRules.validateSet` and the v2 parser) before returning and throws `PlaceholderMapError`, shown as
"Include ID File: ...", where the extension would refuse the file. It is written only for **Random and
Numbers in Order** (never for Type Only or Redacted), whenever the set has records, and still needs
Include Placeholder Map. With the masked styles excluded and the merge rules below, no input is
known to reach the "Include ID File: ..." wrapping any more; it stays as a guard but is untested. A v1
writer (`toIdFileV1`) is kept but not used for output. The interop tests parse files produced by the
extension's real `sidepanel/sidepanel-idfile.js` (with `lib/id-model.js`) in ours, and feed ours to
its parser and `IdRules.validateSet`.

### Share Map Across Items

Off by default. When on, one running ID set serves every item of the execution, so the same value
gets the same placeholder in every item. Each item's Existing Placeholder Map (as a whole set:
records, group members, name parts, reveal-only placeholders, used keys) is merged into it first;
the same key with the same value is kept once, and a key that already stands for a different value
is a `NodeOperationError` for that item (nothing is merged then; a reused name-part or reveal-only
key counts too). `mergeState` applies the `fromV1` rules across items, so the merged set stays one
the extension would load: a value the shared set already holds under another key keeps that key and
the incoming key becomes reveal-only for it (its group members and name parts move to that key); a
live incoming key the shared set has only as reveal-only takes it back (the extension's reclaim);
a group keeps its shared main value and type; name parts and reveal-only placeholders without a
live owner are dropped; the incoming `used` keys stay retired. Each item
outputs the map as it stands after that item, so the last item's map reveals all of them. Items run
one after another, which makes the shared state safe. When off, every item starts from its own
Existing Placeholder Map.

### Include Placeholder Map

Protect option, default `true`. Off, `placeholderMap` and `idFile` are deleted from the output json
after Include Input Fields is merged, so a map copied from the input item is removed too. Off
together with Include ID File is a `NodeOperationError` raised before the gateway call (the ID file
holds the same values); this was chosen over silently dropping the file. The map is still built and,
with Share Map Across Items, still shared; it just is not output. Its purpose is AI tool use: a tool's
output goes back into the model, and the map holds the real values.

### Ignore Terms

Protect and Detect option (`shared/ignoreTerms.ts`). Comma- or newline-separated, or an array from
an expression, whose entries are taken whole (the only way to give a term containing a comma). A
value is ignored when its trimmed text equals a term after NFC normalisation and `toLowerCase()`
(locale-independent on purpose; `toLocaleLowerCase` would depend on the host). Only whole values are
compared. In Protect the terms become the pipeline's `isSkipped` test (the extension's skipped
values): it drops gateway spans after companies are typed, Additionally Protect matches and possible
IDs, while values of the existing or shared set are still replaced by `pgwSpansFromTable`: the map
wins. In Detect, `filterIgnoredSpans` drops gateway spans and possible IDs.

### Detect

`actions/detect.ts`. Same `analyze` call as Protect (same credential, same filter, same error
mapping through `gatewayFailure`), then the steps Protect applies to gateway spans, in its order:
`companySpans` (a PERSON or LOCATION followed by a legal form becomes one COMPANY span including the
form, and other detected spans with that name become COMPANY too), then Ignore Terms (so an ignored
"Modra" never hides "Modra d.o.o."), then `nonOverlappingSpans(text, spans)`: the overlap rule of
`anonymizeFromSpans` (sorted by start, longest first, overlapping spans skipped) with its edge
trimming (whitespace-only spans dropped). Possible spans are trimmed the same way. Offsets are the
gateway spans converted to UTF-16 by `codePointSpansToUtf16`, which index the **original** text.
Types outside the TYPE grammar are reported as `PII` (`pgwEntityType`). No table matches, Additionally
Protect or local possible IDs. Include Input Fields drops the input's `possibleIds`,
`possibleIdsTruncated` and `entityFilterIgnored` (`withoutFields`, `DETECT_FIELDS`); Protect also
drops `idFile` (`PROTECT_FIELDS`). Scores are rounded to two decimals like Protect's. `value` is added only with
Include Values. Detect never reads `existingPlaceholderMap` (n8n keeps hidden parameter values, so
a test makes sure a stale one is ignored): it reports gateway findings only. Blank text makes no
request.

### Entity catalog and filter

`entities.ts` ports the extension's `lib/entities.js`: the 16 bundled rows (`ENTITY_CATALOG`, the
extension's ids, English labels and groups; IBAN sends `IBAN, IBAN_CODE`) and groups (`general`,
`finance`, `tech`, `si`, `hr`, `at`, `us`), `mergeCatalog` (= `anonMergeCatalog`) and `entityFilter`
(= `anonEntityFilter`). `entityTypes` is a multiOptions with `loadOptionsMethod: 'getEntityTypes'`:
the verified capabilities merged with the bundled rows (`null` -> bundled only; no credential
selected yet -> bundled only without a request, because a failed attempt would hold the bundled list
for the 5-minute retry interval). Option name = the English label (the type id when the server
sends none), value = the row id (unchanged, so saved workflows keep working), description = group
labels and server type codes; sorted by name. A verified document only adds: bundled rows always
stay and always send their own types; an uncovered server type becomes a server-only row (today
`IT_FISCAL_CODE`, group `it`, and `SOCIAL_HANDLE`); `possible` types never become rows.

At execution the capabilities are fetched (cached) and the selection is the set of enabled ids:
Detect = All Types, nothing selected (or only ids that are not TYPE-shaped), or **every bundled row
selected**, whatever server-only rows exist and whichever of them are selected, omits `entities`,
so the server default stays authoritative and new server types are picked up without a release
(fail open to full protection, never to none). A saved "every built-in type" selection therefore
means All Types with or without a verified document, and a failed capabilities fetch cannot change
detection. Otherwise the field is **exactly what is selected**: the sorted, unique types of the
selected bundled rows plus the selected other ids; an unknown but TYPE-shaped id (a server type seen earlier,
or one given by expression) is sent too, and the gateway's `invalid_entities` retry covers it.
`entityTypes` is read only when `detect` is `selected`, because n8n keeps values of hidden
parameters. The `opt_in` default and stored deviations are not ported: a selection in n8n is
explicit. **Deliberate deviation from `anonEntityFilter`** (n8n stores no explicit "off" for a
server-only row): with every bundled row selected the node omits the field even when a server-only
type defaults to `opt_in` (the extension then sends a filter), and a partial selection (say every
bundled row but URL) sends only the selected types, where the extension also sends the server-only
types that default to on. The extension-comparison test in `test/entities.test.mjs` carves out
exactly these cases.

