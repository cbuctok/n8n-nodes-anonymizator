# n8n-nodes-anonymizator

This is an n8n community node that keeps personal data out of your prompts. **Protect** finds names,
email addresses, bank accounts, national ID numbers and other personal data in text and replaces
them with placeholders such as `[PERSON_a7k2q]` before the text goes to an LLM. **Reveal** puts the
original values back into the LLM's answer, using the placeholder map Protect produced. **Detect**
reports what personal data a text contains without changing it, for routing before an LLM call.

Detection runs on the Anonymizator privacy gateway (`anon.prosecco37.com`), operated by Prosecco 37.
Names, locations and similar free-text data are found with **named-entity recognition (NER)**, a
statistical model that recognises them from their context in the sentence rather than from a fixed
pattern; regional identifiers such as EMŠO, OIB and IBAN are found by recognisers that validate the
number. The text is end-to-end encrypted (HPKE) to the gateway, which returns only the positions of
what it found and keeps nothing. Everything else happens inside n8n: the placeholders, the map,
masking, the optional extra rules for numbers, amounts and company names, and Reveal. Reveal never
contacts the gateway and needs no credential. [What leaves n8n](#what-leaves-n8n) lists
exactly what is sent.

The node name is **Anonymizator**; the credential is **Anonymizator API**.

[n8n](https://n8n.io/) is a [fair-code licensed](https://docs.n8n.io/n8n-community-license)
workflow automation platform.

- [Installation](#installation)
- [Operations](#operations)
- [Credentials](#credentials)
- [Compatibility](#compatibility)
- [Usage](#usage)
- [Which placeholders to use](#which-placeholders-to-use)
- [Placeholder maps and the browser extension](#placeholder-maps-and-the-browser-extension)
- [What leaves n8n](#what-leaves-n8n)
- [Privacy notes](#privacy-notes)
- [How it differs from the Guardrails node](#how-it-differs-from-the-guardrails-node)
- [Resources](#resources)
- [Support](#support)
- [Licence](#licence)
- [Version history](#version-history)

## Installation

Follow the [installation guide](https://docs.n8n.io/integrations/community-nodes/installation-and-management/gui-installation)
in the n8n community nodes documentation.

The package name to install is:

```
n8n-nodes-anonymizator
```

Enter it exactly as written in **Settings → Community Nodes → Install** on a self-hosted instance.
It is unscoped, so there is no `@org/` prefix. Once n8n has verified the node, it can also be added
straight from the nodes panel, including on n8n Cloud; until then, install it as above.

## Operations

### Protect

Detects personal data in a text and replaces it with placeholders. Needs the **Anonymizator API**
credential.

| Parameter | Notes |
| --- | --- |
| **Text** | The text to protect. Usually an expression such as `{{ $json.body }}`. |
| **Detect** | **All Types** (default) or **Selected Types**. All Types lets the gateway use every type it supports, including types added later. |
| **Entity Type Names or IDs** | Shown for Selected Types. The node's built-in types, with the browser extension's names: Names, Email addresses, Phone numbers, Credit cards, Bank accounts (IBAN), US SSN, API keys, URLs, EMŠO (personal ID), Tax number (davčna), OIB (HR personal ID), AT SVN (insurance no.), ZZZS (health insurance no.), Birth dates, Places / locations, IP addresses. When the gateway supports more types than this version of the node knows, they appear in the list too, with the gateway's name for them and the type code in the description (in October 2026: "Codice fiscale (IT)", `IT_FISCAL_CODE`, and "Social handles", `SOCIAL_HANDLE`); the list is signed by the gateway and checked by the node before it is used. If it cannot be loaded or checked, the built-in list is used. Selecting every built-in type is the same as All Types: types the gateway adds are then detected too, whether or not they are ticked. Any other selection detects exactly the ticked types, so a type the gateway adds later is not detected until you tick it. |
| **Placeholder Style** | **Random** (default), **Numbers in Order**, **Type Only** or **Redacted**. See [Which placeholders to use](#which-placeholders-to-use). |

Options:

| Option | Default | Notes |
| --- | --- | --- |
| **Additionally Protect** | none | More to protect besides what the gateway finds, worked out inside n8n; the choices are never sent. **All Numbers** covers every number left in the text, including numbers inside codes such as K101, INV-2024-118 or 15.5.2026 (each as one `[NUMBER_…]`); a side effect is that in `info@acme2.si` the part `acme2.si` is protected too. **All Currency Values** covers amounts with a currency before or after them, such as 4.800,00 EUR, €4.800 or CHF 300 (`[AMOUNT_…]`). **Company Names (With Legal Suffixes Only)** covers names that end in a legal form such as d.o.o., d.d., GmbH or Ltd (`[COMPANY_…]`). Set by expression, it takes a list or comma-separated text of `NUMBER`, `AMOUNT` and `COMPANY` in any case; any other value stops the item before anything is sent. |
| **Existing Placeholder Map** | empty | Continue an earlier map. Values it already holds keep their placeholders (and are replaced wherever they appear, even if the gateway would not have detected them or they are listed in Ignore Terms), new placeholders never collide with it, and Numbers in Order carries on counting. Accepts every [map format](#accepted-map-formats), including an ID file from the browser extension (version 1 or 2). To continue a Protect node's map with nothing lost, pass its ID file or the whole item (`{{ $('Protect').item.json }}`) rather than `placeholderMap` alone: the flat map holds only the value each group of IDs reveals to, so the other values of a group (from an extension ID file) are not protected again. |
| **Ignore Terms** | empty | Terms that are never treated as personal data, such as your company or product names, separated by commas or new lines (a term that itself contains a comma, such as "Acme, Inc.", can be given in an array set by expression, for example `{{ ["Acme, Inc.", "Orion"] }}`). A detection is dropped when its whole text equals a term, ignoring case ("Acme" drops a detected "ACME", not "Acme Cloud"); the same goes for company names, Additionally Protect matches and possible IDs. The terms never leave n8n; the text is still sent whole. Values in the Existing Placeholder Map are replaced anyway: the map wins. |
| **Share Map Across Items** | off | One running map for all items of the execution, so the same person gets the same placeholder in every item. Each item outputs the map as it stands after that item. A placeholder that stands for different values in two items' existing maps stops the item with an error. The same value under different placeholders in two items' maps is accepted: the first placeholder keeps protecting it, and the other still reveals it. |
| **Include ID File** | off | Adds an `idFile` field (ID file version 2: values, placeholders, types and groups) the browser extension can open with **Load IDs**. To save it, use **Convert to File → Convert to Text File** with **Text Input Field** set to `idFile` (Convert to JSON would wrap it in the item, and the extension refuses that file). Added only for Random and Numbers in Order, and only when there are IDs (something was found or an Existing Placeholder Map was given); Type Only and Redacted add no file. The file holds the real values, so it needs Include Placeholder Map on. |
| **Include Input Fields** | off | Copies the input item's fields into the output item, except `idFile`, `possibleIds`, `possibleIdsTruncated` and `entityFilterIgnored`: Protect writes these itself when they apply, and copied ones would describe another text. |
| **Include Placeholder Map** | on | Turn it off when the output goes back to an LLM, for example when an AI agent calls Protect as a tool: the map holds the real values, and returning it would hand them to the model. Without the map the protected text **cannot be revealed later**. When off, the output has no `placeholderMap` and no `idFile` (also not copied from the input by Include Input Fields), and turning on Include ID File as well stops the item with an error before anything is sent. |
| **Include Possible IDs** | off | Adds `possibleIds`: text left in clear that you may want to check, such as "Luki" next to the ID "Luka Zupan", "Mr. Zupan", or "Modra Vila" without its d.o.o. They are worked out inside n8n from the IDs in the map, plus what the gateway flags for review when it offers that (as of October 2026 it offers nothing to review). Possible IDs are a prompt to look, not a score: they are never replaced, there are no confidence numbers, and text that is not listed can still hold personal data. Limits: only names of 4 letters or more are matched in other case forms ("Ana" / "Ano" is not), a vowel that drops out ("Peter" / "Petra") is not recognised, an ordinary word can be flagged now and then ("Luke" next to "Luka"), and at most 50 are listed. |

Output, one item per input item:

```json
{
  "protectedText": "Hello, my name is [PERSON_6kltt] and my email is [EMAIL_r01q2].",
  "placeholderMap": {
    "PERSON_6kltt": "Janez Novak",
    "PERSON_6kltt_NAME": "Janez",
    "PERSON_6kltt_SURNAME": "Novak",
    "EMAIL_r01q2": "ana.kovac@example.com"
  },
  "entities": [
    { "entityType": "PERSON", "placeholder": "[PERSON_6kltt]", "start": 18, "end": 32, "score": 0.85 },
    { "entityType": "EMAIL_ADDRESS", "placeholder": "[EMAIL_r01q2]", "start": 49, "end": 62, "score": 1 }
  ]
}
```

| Field | Notes |
| --- | --- |
| `protectedText` | The text with placeholders. |
| `placeholderMap` | The complete map needed to reveal this text: the existing map plus the new placeholders. Person names also get `_NAME` and `_SURNAME` entries, so an answer that mentions only "Janez" is revealed too. Retired placeholders from the existing map are kept with an empty value, so they stay retired when you pass the map back in. Empty (`{}`) for Type Only and Redacted. Left out when Include Placeholder Map is off. **It holds the real values.** |
| `entities` | What was replaced: `entityType` (the type, such as `EMAIL_ADDRESS`, even where the placeholder is shorter), `placeholder`, `start`/`end` offsets into `protectedText`, and `score`. Never the real value. |
| `entityFilterIgnored` | Present (`true`) only when the gateway refused the selected types and the node detected all types instead. |
| `idFile` | Present only with Include ID File, for Random and Numbers in Order, and only when there is at least one ID. |
| `possibleIds` | Present only with Include Possible IDs: `start`, `end` (offsets into `protectedText`), `value`, `kind` (`company-name`, `surname`, `title-surname`, `case-form`, or `detected` for what the gateway flagged) and `type` (the kind of ID it may be, or `null`). The values are text that is still in clear in `protectedText`. |
| `possibleIdsTruncated` | Present (`true`) only when there were more than 50 possible IDs and the list was cut. |

Placeholders use the browser extension's prefixes: `[PERSON_…]`, `[EMAIL_…]`, `[PHONE_…]`, `[IBAN_…]`,
`[COMPANY_…]`, and the type code for the rest (`[EMSO_…]`). A name the gateway finds followed by a
legal form (d.o.o., d.d., s.p., GmbH, AG, Ltd, Inc., LLC and similar) is protected as one
`[COMPANY_…]`, and the same name without the legal form elsewhere in the text becomes a company ID of
its own. Placeholders already in the text, your own or another tool's (`[PERSON_1]`,
`[PERSON_a7k2q]`), are left as they are, and a new placeholder never repeats one the text already
contains. Maps with the longer keys earlier versions of the node made (`EMAIL_ADDRESS_r01q2`) still
reveal and can still be continued.

### Detect

Runs the same detection as Protect but changes nothing: it reports what personal data the text
contains. Use it to route items, for example with an IF node on `hasPersonalData` before an LLM
call. Needs the **Anonymizator API** credential, and sends the text to the gateway exactly as Protect
does.

| Parameter | Notes |
| --- | --- |
| **Text** | The text to check. |
| **Detect** / **Entity Type Names or IDs** | As in Protect. |

Options:

| Option | Default | Notes |
| --- | --- | --- |
| **Ignore Terms** | empty | As in Protect: detections and possible IDs equal to a term are not reported. |
| **Include Input Fields** | off | Copies the input item's fields into the output item, except `possibleIds`, `possibleIdsTruncated` and `entityFilterIgnored`: Detect writes `possibleIds` and `entityFilterIgnored` itself when they apply, and copied ones would describe another text. |
| **Include Possible IDs** | off | Adds `possibleIds`: text the gateway flags for review without counting it as personal data (for example an organisation name), when the gateway offers that (as of October 2026 it offers nothing to review, so the list stays empty). A prompt to look, not a score: they are not in `entities`, `entityCount` or `countsByType`, and text that is not listed can still hold personal data. |
| **Include Values** | off | Adds the matched text to each entity as `value`. These are the personal data themselves: leave this off when the output goes to an LLM, an AI agent or a log. |

Output:

```json
{
  "hasPersonalData": true,
  "entityCount": 2,
  "countsByType": { "PERSON": 1, "EMAIL_ADDRESS": 1 },
  "entities": [
    { "entityType": "PERSON", "start": 18, "end": 29, "score": 0.85 },
    { "entityType": "EMAIL_ADDRESS", "start": 46, "end": 67, "score": 1 }
  ]
}
```

| Field | Notes |
| --- | --- |
| `hasPersonalData` | `true` when at least one entity was found. |
| `entityCount` / `countsByType` | How many entities were found, in total and per type. |
| `entities` | `start` and `end` are offsets into the **original** text, in JavaScript string units (UTF-16), so `text.slice(start, end)` is the value. Leading and trailing spaces are trimmed off, and a detection of only spaces is dropped. Of overlapping detections, the one starting first (the longest, at the same start) is kept. A name the gateway finds followed by a legal form ("Modra d.o.o.") is reported as one `COMPANY`, legal form included, as Protect replaces it, and so is the same detected name elsewhere in the text; this happens before Ignore Terms, so an ignored "Modra" does not hide "Modra d.o.o.". A detection whose type the gateway sent malformed is reported as `PII`. |
| `entityFilterIgnored` | As in Protect. |
| `possibleIds` | Present only with Include Possible IDs: `entityType`, `start`, `end` (offsets into the original text), and `value` only with Include Values. |

Detect reports what the gateway found, with company names typed as Protect types them, nothing
else: there is no placeholder map and no Additionally Protect, so it does not know about values that
only an Existing Placeholder Map or those rules would have matched, and its counts can differ from
what Protect replaces.

### Reveal

Puts the original values back. Runs entirely inside n8n: nothing is sent anywhere, and no credential
is needed.

| Parameter | Notes |
| --- | --- |
| **Text** | The text containing placeholders, usually the LLM's answer. |
| **Placeholder Map** | The map Protect produced, for example `{{ $('Protect').item.json.placeholderMap }}`. Accepts every [map format](#accepted-map-formats). |
| **Include Input Fields** (option) | Copies the input item's fields into the output item. |

Output:

| Field | Notes |
| --- | --- |
| `revealedText` | The text with the original values. |
| `unresolvedPlaceholders` | Bracketed placeholders such as `[PERSON_x9y8z]` that the map could not resolve, for example because the LLM invented one or the text was masked. Empty when everything was revealed. |

Reveal's output contains the real values. Do not give Reveal to an AI agent as a tool when what the
agent produces leaves your control: whatever the tool returns goes back into the model's context.

Reveal replaces bracketed placeholders (`[PERSON_6kltt]`) and also the same key written without
brackets as a whole word (`PERSON_6kltt`), because LLMs sometimes drop the brackets. If you add your
own keys to a map, avoid ordinary words: a key `CLIENT` would also replace the word "CLIENT" in the
answer.

## Credentials

You need an Anonymizator API key. API keys are created and managed in the Prosecco 37 Anonymizator
user portal. Paste the key into the credential's **API Key** field.
<!-- TODO(api-key-portal): add the user portal URL (where to get a key) once it is public. -->

| Field | Required | Notes |
| --- | --- | --- |
| API Key | Yes | Stored as a password field and sent as a bearer token. Only Protect and Detect use it. |
| Show Experimental Options | No | Off by default. Shows the experimental option below. |
| Post-Quantum Encryption (Experimental) | No | Off by default. See [Experimental: post-quantum encryption](#experimental-post-quantum-encryption). |

There is no base URL field: the node always talks to `https://anon.prosecco37.com`, because it only
trusts encryption keys signed through a chain from the Anonymizator root keys built into the node.

The credential test calls `GET https://anon.prosecco37.com/v1/keyconfig`, so a problem shows up when
you save the credential rather than on the first run:

- **API key rejected**: the key is wrong, expired or revoked.
- **The key is valid but has no access to Anonymizator (missing role)**: check in the user portal
  that the key belongs to an account with Anonymizator access.

### Experimental: post-quantum encryption

Not for production use. With **Show Experimental Options** and **Post-Quantum Encryption
(Experimental)** both on, Protect and Detect encrypt the text with the gateway's experimental
protocol version 3, which adds a post-quantum key exchange (X-Wing: X25519 together with
ML-KEM-768) to protect recorded traffic against a future quantum computer. Everything else stays
the same. The protocol, its wire format and this option may change or go away.

- If the gateway does not offer it, the item fails with "Post-quantum encryption is on, but the
  Anonymizator gateway doesn't offer it, so nothing was sent". The text is **never** sent with
  standard encryption instead. Turn the option off to use standard encryption.
- The credential test checks standard encryption only, so it can pass while the option fails.
- The post-quantum part (ML-KEM-768 and SHA-3) is a vendored copy of the `@noble/post-quantum` and
  `@noble/hashes` libraries, which have not been independently audited for this use; the X25519
  part uses Node.js's own crypto, as standard encryption does.
- Turning **Show Experimental Options** off also turns the option off.

## Compatibility

- Tested end to end on n8n 2.44.5 (self-hosted, Docker). The node
  uses the community-node API version 1 and Node.js's built-in `crypto`. It also relies on features
  of recent n8n releases (themed icons, `NodeConnectionTypes`, tool usage), so old 1.x releases are
  not expected to work; a minimum version has not been established.
- No runtime dependencies.
- The n8n host must reach `https://anon.prosecco37.com` over HTTPS, and its clock must be right to
  within a minute: requests carry a timestamp and the gateway refuses stale ones.
- Usable as an AI Agent tool (`usableAsTool`). n8n 2.x generates the tool variant automatically; no
  environment variable is needed (old n8n 1.x releases needed
  `N8N_COMMUNITY_PACKAGES_ALLOW_TOOL_USAGE=true`). Read [As an AI Agent tool](#as-an-ai-agent-tool)
  first.

## Usage

### Protect, ask the LLM, Reveal

The usual shape is three nodes:

```
[Trigger] → Anonymizator: Protect → LLM (any chat model or AI Agent) → Anonymizator: Reveal
```

1. **Protect** (rename the node to `Protect`): Text `{{ $json.body }}`, Placeholder Style Random.
2. **LLM**: send `{{ $json.protectedText }}` and tell the model to keep placeholders as they are,
   for example: *"Text in square brackets such as [PERSON_a7k2q] are placeholders for personal data.
   Keep them exactly as written, including the brackets, and never guess what they stand for."*
3. **Reveal**: Text is the model's answer (for example `{{ $json.output }}` after an AI Agent), and
   Placeholder Map is `{{ $('Protect').item.json.placeholderMap }}`.

The model only ever sees placeholders. Check `unresolvedPlaceholders` after Reveal if the answer is
going to a person: a non-empty list means the model altered or invented a placeholder.

A ready-made version of this flow, with a Basic LLM Chain and sticky notes, is in
[`examples/protect-llm-reveal`](examples/protect-llm-reveal/README.md); import its `workflow.json`
with **Import from File**. A Basic LLM Chain outputs only `text` and drops every other field, which
is why Reveal reads the map from the Protect node by name rather than from `$json`.

### Detect, then route

To decide what to do before anything reaches a model, put **Detect** first and an IF node on
`{{ $json.hasPersonalData }}`: for example, send texts without personal data straight to the LLM and
the rest through Protect, or to a person. `countsByType` lets you route on specific kinds, such as
`{{ (($json.countsByType.IBAN ?? 0) + ($json.countsByType.IBAN_CODE ?? 0)) > 0 }}` (the gateway can
report an IBAN as either type, so check both). Detect and Protect each call the gateway, so this costs two
requests for texts that go on to Protect.

### As an AI Agent tool

The node can be attached to an AI Agent as a tool. Everything a tool returns goes back into the
model's context, so:

- **Protect as a tool:** turn **Include Placeholder Map** off, or use the **Type Only** or
  **Redacted** style, whose map is empty and which add no ID file. With the map on, the real values
  would be returned to the model, which defeats the purpose. Without the map, the model's answer cannot be revealed later.
- **Detect as a tool:** leave **Include Values** off; the counts and types are enough for the model
  to decide.
- **Keep the real text out of the tool's input and output:** leave **Include Input Fields** off
  (it would copy the original text field back into the result), and set **Text** from workflow
  data, not with `$fromAI()`: text the model fills in is text the model has already seen.
- **Reveal as a tool:** avoid it. Its output is the real values, shown to the model.
- The safest layout is not a tool at all: run Protect as a normal node **before** the agent and
  Reveal **after** it, as in the flow above. The tool variant has been checked to load in n8n, not
  yet run with an agent.

### Many items

Each item is protected separately and gets its own map. Turn on **Share Map Across Items** when
items are related (for example messages in one thread) and you want the same person to get the same
placeholder in all of them; then reveal with the map from the last item.

To keep placeholders stable across executions, store the map (or the ID file) somewhere private and
pass it back in as **Existing Placeholder Map** next time.

### Size and speed

There is no length limit per item. The gateway accepts a limited amount of text per request (14,000
characters on the hosted gateway, published in its signed capabilities), so the node sends a longer
text in parts, one after another, and puts the results back together; see
[Long texts](#long-texts-how-the-node-splits-them). A short text is one request. Each part takes
roughly 1 second per 1,000 characters on the hosted gateway (a 40,000-character text, four parts,
took about 48 seconds when measured), and each request may take up to 60 seconds before the node
gives up. The gateway also limits how many requests an account can make per minute: a text in
several parts waits out a refusal itself (up to three times, as long as the gateway asks, at most
60 seconds each), while a one-request text stops at once with "Too many requests" (enable
**Retry On Fail** with a wait between tries). Detection quality depends on the gateway's models.
NER is statistical: it can miss a name or tag only part of one, especially in unusual sentence
structures, so always review protected text before relying on it for anything sensitive. Values already in an Existing Placeholder Map are always
replaced, whether or not the gateway detects them.

### Long texts: how the node splits them

This node is the reference implementation for calling the Anonymizator API directly. The gateway
answers one `text` per request and refuses a text longer than its per-request limit, so a client
has to split. The node does it the way the Anonymizator web app and browser extension do
(`nodes/Anonymizator/shared/chunker.ts` and `analyze` in `shared/gateway.ts`):

1. **The per-request limit** is `max_text_chars` from the gateway's signed capabilities document
   (`GET /v1/capabilities`), further capped by `floor((max_body_bytes - 8192) / 6)`, and used only
   when it lies between 10,000 and 1,000,000. Without a verified document the node assumes 10,000,
   the bottom of that range, so it never sends more than any gateway it accepts would take. The
   hosted gateway publishes 14,000.
2. **The part size** is that limit minus 2,000, at most 100,000 (12,000 on the hosted gateway),
   counted in Unicode code points, as the gateway counts (Python `len`), not JavaScript string
   length.
3. **Where to cut.** The text is cut only at line ends (`\n`), never at a tab (table cells), and
   lines are packed greedily; a cut after an empty line is preferred when one lies in the last
   quarter of a part. A single line longer than a part is cut after the last sentence end (`.`, `!`
   or `?` followed by whitespace) within its final 2,000 code points, else at the last whitespace,
   else exactly at the part size; the next part then starts 256 code points earlier, so a value cut
   in two is seen whole in that overlap.
4. **Sending.** The parts go out one after another, each as its own freshly encrypted request (a new
   HPKE context and frame every time; a resent frame is refused as a replay). The entity-type
   filter and the review-only flag are the same for every part. If the gateway refuses the type
   filter, the whole text is sent again from the first part without it. A rate-limited part
   waits as long as `Retry-After` says (5 s when absent), at most three times and at most 60 s
   each, then is sent again.
5. **Merging.** The gateway answers each part with code-point offsets into that part. The node
   converts them to JavaScript (UTF-16) offsets against the exact part it sent, then shifts them by
   the part's UTF-16 start offset in the whole text. All spans are sorted by start, longer first;
   exact duplicates (same start, end and type) are dropped, as is a span lying inside a span from
   another part; two spans from different parts that overlap only partly (a value cut at a part
   boundary) become their union, so a cut never leaves part of a value in clear. Review-only spans
   are merged the same way and dropped where they touch a detected value.
6. **Fail closed.** If any part fails, after the usual retries, the whole item fails as a single
   request would, and the message says which part (for example "This was part 2 of 3 of the text;
   no partial result is output."). Nothing from the other parts is used or output.
7. **Then the local steps run once** over the whole text with the merged spans: placeholders,
   Additionally Protect, possible IDs and the map. One value keeps one placeholder across every part.

## Which placeholders to use

No placeholder style is "compliant" or "non-compliant" by itself. What matters under the GDPR is
whether the output can still be linked back to a person, and who holds the key.

| Style | Example | Can you tell people apart? | Reveal | What it is |
| --- | --- | --- | --- | --- |
| Random | `[PERSON_a7k2q]` | Yes | Yes, with the placeholder map | Pseudonymisation (GDPR Art. 4(5)) |
| Numbers in Order | `[PERSON_1]` | Yes, and it shows the order values were found | Yes | Pseudonymisation |
| Type Only | `[PERSON]`, `[PHONE]` | No, only what kind of value was there | No | Masking (typed generic) |
| Redacted | `[REDACTED]` | No | No | Masking / redaction |

- **Random and Numbers in Order** give the same person the same placeholder, so the LLM can still
  follow who did what, and Reveal puts the values back. The text stays **personal data**: the
  placeholder map and ID files are the re-identification key. Keep them private and away from the
  LLM provider. For a recipient with no realistic means to re-identify, such as the LLM provider, it
  may not be personal data (CJEU, *EDPS v SRB*, 2025). For you, the key holder, it still is. Random
  is the default because maps from separate runs do not collide the way `[PERSON_1]` would.
- **Type Only and Redacted** remove linkability from the text: the model cannot tell the values
  apart, so the protected text cannot be revealed and the placeholder map is empty (`{}`). Include
  ID File adds no file for them. Data minimisation
  (Art. 5(1)(c)) and privacy by design (Art. 25) favour them when the task does not need to know who
  is who, such as classification, summarising or sentiment; the model's answers may be worse because
  it cannot tell who is who. Values from an Existing Placeholder Map are masked too (as their type,
  such as `[COMPANY]`, or `[CUSTOM]`).
- **Type Only** is usually the better non-linkable choice: "[PERSON] approved the invoice" reads far
  better, to a model and to people, than "[REDACTED] approved the invoice", and revealing that
  something was a person is a negligible risk.
- **Redacted** leaks almost nothing, not even the kind of value. Use it for the most sensitive text
  and for anything published.
- **No style makes text anonymous.** The node replaces what the gateway detects, what Additionally
  Protect finds and what your existing map holds. Job titles, dates, places, rare events and writing style can still identify
  people, so do not call the output anonymised.
- **Document the choice per data flow.** ISO/IEC 27701 expects you to state which de-identification
  technique applies to which flow; ISO/IEC 27002:2022 control 8.11 (data masking) and ISO/IEC 20889
  are the references.

## Placeholder maps and the browser extension

### Accepted map formats

Reveal's **Placeholder Map** and Protect's **Existing Placeholder Map** accept the same inputs, as a
JSON object or as JSON text:

| Format | Example |
| --- | --- |
| Object with bare keys (what Protect outputs) | `{"PERSON_a7k2q": "Janez Novak"}` |
| Object with bracketed keys | `{"[PERSON_a7k2q]": "Janez Novak"}` |
| List of pairs | `[{"placeholder": "[PERSON_a7k2q]", "value": "Janez Novak"}]` |
| A whole Protect output item: its `idFile` when it has a current one (lossless: groups and types kept), else its `placeholderMap` | `{{ $('Protect').item.json }}` |
| An Anonymizator browser extension ID file, version 2 or 1 | `{"format": "anonymizator-id-file", "version": 2, ...}` |

Placeholders start with a capital letter and contain only letters, digits and underscores. An entry
with an empty value is treated as retired: its placeholder is never reused, and it is never
revealed. Error messages name the offending placeholder or entry number but never repeat a value.

### Working with the Anonymizator browser extension

The node uses the same placeholders and the same ID file format as the Anonymizator Chrome
extension:

- **From n8n to the browser:** turn on **Include ID File** (Random or Numbers in Order), then add **Convert to File → Convert to
  Text File** with **Text Input Field** set to `idFile`, and open the file in the extension with
  **Load IDs**. The extension then reveals answers you paste into it. Load IDs opens a file into an
  empty Current IDs only; files are never merged, so use **Clear all** there first. (Convert to JSON
  writes the whole item, with `idFile` nested inside it, and the extension refuses that file.)
- **From the browser to n8n:** pass an ID file saved with **Export IDs** (read it with **Extract from
  File**, or paste its contents) as Reveal's Placeholder Map or Protect's Existing Placeholder Map.
  Files from older versions of the extension (version 1) are read too. The node's Placeholder Style
  setting is used for new placeholders, not the style recorded in the file. IDs grouped as one in
  the extension reveal to the value chosen there.

ID files hold the real values. Keep them as private as the data itself.

## What leaves n8n

Only **Protect** and **Detect** make network requests, and only to `https://anon.prosecco37.com`,
through n8n's own HTTP helper (so n8n's proxy settings apply). There is no telemetry, analytics or
any other endpoint.

| Sent to the gateway | When | Notes |
| --- | --- | --- |
| `GET /v1/keyconfig` with your API key as `Authorization: Bearer ...` | When you test or save the credential; otherwise at most once every 10 minutes per n8n process (sooner when the cached copy no longer checks out), plus once more when the gateway rotates its key, one retry after a server error, and one more two seconds later when the gateway is part-way through renewing its signing key (a failed answer is never cached, so it is fetched again for the next item) | No body. The answer is the gateway's signed key configuration, checked through a signed chain from the root keys built into the node before anything else is sent. |
| `GET /v1/capabilities` with your API key as `Authorization: Bearer ...` | When Protect or Detect runs with non-blank text, and when the editor loads the **Entity Type Names or IDs** list once a credential is selected (without one the built-in list is shown and nothing is sent); at most once every 5 minutes per n8n process, and after a failed attempt not again for 5 minutes (a rejected API key or a missing credential does not count as an attempt, so it does not hold back other credentials) | No body. The answer is the gateway's signed list of supported entity types, their names and groups, the text limit and the review-only types, checked through the same chain. It can only add types to the node's built-in list; if it cannot be loaded or checked, the built-in list and limit are used and nothing else changes. |
| `POST /v1/analyze` with your API key as `Authorization: Bearer ...` | Once per item with non-blank text, or once per part for a text longer than the gateway's per-request limit (parts are sent one after another, each encrypted separately; see [Long texts](#long-texts-how-the-node-splits-them)), and once more for a part the gateway rate-limited, after the wait it asks for; a second time, freshly encrypted, after a key rotation or a server error (one second later; an encrypted answer is retried only when it says the gateway was busy or failed internally); once more without the type list when the gateway refuses the selected types | The body is HPKE-encrypted (RFC 9180) to the verified key. |
| Inside the encrypted body | | The **Text** parameter exactly as given (or, for a long text, one part of it); with Selected Types (unless every built-in type is selected), exactly the selected entity types; with **Include Possible IDs**, and only when the gateway's capabilities list review-only types, the flag `"possible": true`. Padded with spaces to a fixed size bucket, so the body length does not track the text length. |
| In the clear, in the request frame | | A version byte, the gateway key id, the current time in seconds (the gateway refuses stale requests) and a one-time public key (with the experimental post-quantum option, the 1,120-byte X-Wing key encapsulation instead, and up to one more resend after the gateway answers that it does not accept protocol version 3). |
| In the clear, as HTTP headers | | `Content-Type`, `Accept`, `Authorization`, and the standard headers n8n's HTTP helper adds. |

Never sent anywhere:

- the placeholders and the placeholder map, including the **Existing Placeholder Map** you pass in;
- **Ignore Terms** (they are applied after detection, inside n8n);
- **Additionally Protect** and what it finds, and the possible IDs worked out from your IDs (both
  inside n8n);
- ID files;
- anything **Reveal** reads or writes: Reveal makes no network request and needs no credential;
- the other fields of the input item, and blank text.

The gateway answers with entity types, positions and scores (and, when asked, the types and
positions of review-only spans), encrypted with a key only this request can derive. It returns no
text, no placeholders and no map. The gateway is operated by Prosecco 37,
which states that it is stateless and keeps nothing. The node cannot verify what happens on the
server; what it can guarantee is the list above.

## Privacy notes

- **What leaves n8n:** only the text of Protect and Detect, encrypted with HPKE (RFC 9180) to the
  gateway's current key; see [What leaves n8n](#what-leaves-n8n) for the details. Network
  intermediaries, including the CDN in front of the gateway, see ciphertext; they still see the
  API key, the timing and the approximate size of each request and answer (bodies are padded to
  coarse size classes). Before sending, the node checks the gateway's key through a signed chain
  from the Anonymizator root keys built into the node (a primary and a backup); if the check fails,
  nothing is sent and the item stops with an explanation (this can mean a TLS-inspecting proxy is
  intercepting the connection).
- **What the gateway returns:** positions and types of what it found. It never sees placeholders or
  maps and keeps nothing.
- **Where the map lives:** Protect creates the placeholder map inside n8n and outputs it, so the map
  and the real values are in the Protect output item, like any other n8n data. Treat that output as
  personal data; turn off **Include Placeholder Map** where it should not travel further.
- **What stays in n8n:** the placeholder map and everything Reveal does. Reveal makes no network
  request.
- **n8n stores execution data.** Saved executions contain the original text and the placeholder map.
  For workflows that protect sensitive text, turn off saving successful executions (and, where
  possible, failed ones) in the
  [workflow settings](https://docs.n8n.io/build/manage-workflows/configure-workflow-settings), or
  restrict who can view executions.
- **AI Agent tools see their results.** If an agent calls Protect as a tool with the map included,
  `placeholderMap` with the original values goes back into the model's context, which defeats the
  purpose. See [As an AI Agent tool](#as-an-ai-agent-tool) for the safe settings.

## How it differs from the Guardrails node

n8n's built-in [Guardrails](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-langchain.guardrails)
node can sanitize personal data. Its PII check uses regular expressions only and replaces each match
with a type tag such as `<EMAIL_ADDRESS>`; there is no step that restores the values (the node does
list the matched originals in its `checks` output). Anonymizator is for a different job:

| | Guardrails (Sanitize Text) | Anonymizator |
| --- | --- | --- |
| How data is found | Regular expressions only (its LLM-based checks, such as jailbreak and NSFW, belong to the Check Text for Violations operation and do not redact) | Named-entity recognition (NER) on the gateway for names, locations and similar free text, plus recognisers that validate structured identifiers |
| Person names | Not detected: none of its 36 built-in types is a name (only a custom regex listing specific names would match) | Detected by NER (statistical, so it can miss one), with extra first-name and surname placeholders |
| Locations | A street-suffix pattern (`… Street`, `St`, `Ave`, `Rd`, `Dr` …); no cities or countries | Detected by NER |
| Regional identifiers | 36 fixed, unvalidated patterns (US, UK, ES, IT, PL, SG, AU, IN, FI), no Slovenian, Croatian or Austrian IDs, plus your own custom regex | Slovenian EMŠO, tax and ZZZS numbers, Croatian OIB, Austrian social insurance number, IBAN and more |
| Reversible | No: every value of a type becomes the same tag (for example `<EMAIL_ADDRESS>`), and there is no restore step | Yes: unique placeholders per value, a placeholder map, and Reveal. Masking is available too. |
| Where detection runs | Inside n8n | On the Anonymizator gateway, over an HPKE-encrypted channel; the gateway returns positions only |
| Where the map is made and kept | n/a | Inside n8n: the map, with the real values, is created locally and is part of the Protect output; the gateway never sees or stores it |
| Browser extension interop | n/a | Shares placeholders and ID files with the Anonymizator Chrome extension |

Guardrails' Sanitize Text needs no account and sends nothing anywhere; its LLM-based checks
(jailbreak, NSFW, topical alignment and custom checks) are in Check Text for Violations and send the
text to whichever chat model you connect. Anonymizator needs an API key and sends the encrypted text
to the gateway for detection. Neither makes text anonymous on its own.

## Resources

- [n8n community nodes documentation](https://docs.n8n.io/integrations/community-nodes)
- Anonymizator gateway: `https://anon.prosecco37.com` (sign-in required; API keys come from the
  Anonymizator user portal, see [Credentials](#credentials))
- [Example workflow: Protect, ask an LLM, Reveal](examples/protect-llm-reveal/README.md)
- [RFC 9180: Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180)
- [Changelog](CHANGELOG.md)

## Support

- Bugs and feature requests: [GitHub issues](https://github.com/cbuctok/n8n-nodes-anonymizator/issues).
- Security issues: report them privately, as described in [SECURITY.md](SECURITY.md).
- Questions about n8n itself: the [n8n community forum](https://community.n8n.io/).
- API keys and the gateway: the Prosecco 37 Anonymizator user portal (see [Credentials](#credentials)).

## Licence

[MIT](LICENSE.md), © 2026 Greg Evseev. Portions are ported from the Anonymizator browser extension,
© 2026 Prosecco 37 d.o.o., and contributed under the MIT licence with permission; see
[NOTICE](NOTICE).

## Version history

- **0.4.0** (2026-11-01): an experimental, off-by-default **Post-Quantum Encryption (Experimental)**
  credential option behind **Show Experimental Options** (the gateway's protocol version 3, X-Wing;
  no runtime dependencies); the last remnants of the gateway's protocol v1 removed.
- **0.3.0** (2026-10-24): **Protect** and **Detect** split a text longer than the gateway's per-request
  limit into parts and analyse them one after another, so there is no length limit per item any
  more; the node is the reference for API callers ([Long texts](#long-texts-how-the-node-splits-them)).
- **0.2.0** (2026-10-22): brought in line with the Anonymizator browser extension 2026.10.19.1: the
  gateway's protocol version 2, the entity type list from the gateway's signed capabilities, the
  extension's placeholder prefixes and company names, **Additionally Protect** and **Include
  Possible IDs** options, ID file version 2, the extension's error wording.
- **0.1.1** (2026-10-06): **Detect** operation; **Include Placeholder Map** and **Ignore Terms** options;
  an importable example workflow; documentation of exactly what leaves n8n.
- **0.1.0** (2026-10-05): first release. Protect and Reveal, four placeholder styles, map
  continuation and sharing across items, extension ID files.
