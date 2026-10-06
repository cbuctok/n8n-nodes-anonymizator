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
what it found and keeps nothing. Everything else happens inside n8n: the placeholders, the map, masking and Reveal.
Reveal never contacts the gateway and needs no credential. [What leaves n8n](#what-leaves-n8n) lists
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
| **Entity Types** | Shown for Selected Types. Person names, email addresses, phone numbers, credit card numbers, bank accounts (IBAN), US Social Security numbers, API keys, URLs, Slovenian personal ID (EMŠO), Slovenian tax number, Slovenian health insurance number (ZZZS), Croatian personal ID (OIB), Austrian social insurance number, birth dates, locations, IP addresses. Selecting every type is the same as All Types. |
| **Placeholder Style** | **Random** (default), **Sequential**, **Type Only** or **Redacted**. See [Which placeholders to use](#which-placeholders-to-use). |

Options:

| Option | Default | Notes |
| --- | --- | --- |
| **Existing Placeholder Map** | empty | Continue an earlier map. Values it already holds keep their placeholders (and are replaced wherever they appear, even if the gateway would not have detected them or they are listed in Ignore Terms), new placeholders never collide with it, and Sequential numbering carries on. Accepts every [map format](#accepted-map-formats), including an ID file from the browser extension. |
| **Ignore Terms** | empty | Terms that are never treated as personal data, such as your company or product names, separated by commas or new lines (a term that itself contains a comma, such as "Acme, Inc.", can be given in an array set by expression, for example `{{ ["Acme, Inc.", "Orion"] }}`). A detection is dropped when its whole text equals a term, ignoring case ("Acme" drops a detected "ACME", not "Acme Cloud"). The terms never leave n8n; the text is still sent whole. Values in the Existing Placeholder Map are replaced anyway: the map wins. |
| **Share Map Across Items** | off | One running map for all items of the execution, so the same person gets the same placeholder in every item. Each item outputs the map as it stands after that item. A placeholder that stands for different values in two items' existing maps stops the item with an error. |
| **Include ID File** | off | Adds an `idFile` field the browser extension can open with **Load IDs**. To save it, use **Convert to File → Convert to Text File** with **Text Input Field** set to `idFile` (Convert to JSON would wrap it in the item, and the extension refuses that file). Random and Sequential styles only. Not added when the map is empty (nothing was detected and no Existing Placeholder Map was given). |
| **Include Input Fields** | off | Copies the input item's fields into the output item. |
| **Include Placeholder Map** | on | Turn it off when the output goes back to an LLM, for example when an AI agent calls Protect as a tool: the map holds the real values, and returning it would hand them to the model. Without the map the protected text **cannot be revealed later**. When off, the output has no `placeholderMap` and no `idFile` (also not copied from the input by Include Input Fields), and turning on Include ID File as well stops the item with an error before anything is sent. |

Output, one item per input item:

```json
{
  "protectedText": "Hello, my name is [PERSON_6kltt] and my email is [EMAIL_ADDRESS_r01q2].",
  "placeholderMap": {
    "PERSON_6kltt": "Janez Novak",
    "PERSON_6kltt_NAME": "Janez",
    "PERSON_6kltt_SURNAME": "Novak",
    "EMAIL_ADDRESS_r01q2": "ana.kovac@example.com"
  },
  "entities": [
    { "entityType": "PERSON", "placeholder": "[PERSON_6kltt]", "start": 18, "end": 32, "score": 0.85 },
    { "entityType": "EMAIL_ADDRESS", "placeholder": "[EMAIL_ADDRESS_r01q2]", "start": 49, "end": 70, "score": 1 }
  ]
}
```

| Field | Notes |
| --- | --- |
| `protectedText` | The text with placeholders. |
| `placeholderMap` | The complete map needed to reveal this text: the existing map plus the new placeholders. Person names also get `_NAME` and `_SURNAME` entries, so an answer that mentions only "Janez" is revealed too. Retired placeholders from the existing map are kept with an empty value, so they stay retired when you pass the map back in. Empty (`{}`) for Type Only and Redacted. Left out when Include Placeholder Map is off. **It holds the real values.** |
| `entities` | What was replaced, with `start`/`end` offsets into `protectedText`. |
| `entityFilterIgnored` | Present (`true`) only when the gateway refused the selected types and the node detected all types instead. |
| `idFile` | Present only with Include ID File, and only when `placeholderMap` has at least one value. |

### Detect

Runs the same detection as Protect but changes nothing: it reports what personal data the text
contains. Use it to route items, for example with an IF node on `hasPersonalData` before an LLM
call. Needs the **Anonymizator API** credential, and sends the text to the gateway exactly as Protect
does.

| Parameter | Notes |
| --- | --- |
| **Text** | The text to check. |
| **Detect** / **Entity Types** | As in Protect. |

Options:

| Option | Default | Notes |
| --- | --- | --- |
| **Ignore Terms** | empty | As in Protect: detections equal to a term are not reported. |
| **Include Input Fields** | off | Copies the input item's fields into the output item. |
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
| `entities` | `start` and `end` are offsets into the **original** text, in JavaScript string units (UTF-16), so `text.slice(start, end)` is the value. Overlapping detections are resolved the way Protect resolves them. |
| `entityFilterIgnored` | As in Protect. |

Detect reports what the gateway found, nothing else: there is no placeholder map, so it does not
know about values that only an Existing Placeholder Map would have matched.

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

There is no base URL field: the node always talks to `https://anon.prosecco37.com`, because it only
trusts encryption keys signed by the Anonymizator trust root.

The credential test calls `GET https://anon.prosecco37.com/v1/keyconfig`, so a problem shows up when
you save the credential rather than on the first run:

- **API key rejected**: the key is wrong, expired or revoked.
- **The key is valid but has no access to Anonymizator (missing role)**: check in the user portal
  that the key belongs to an account with Anonymizator access.

## Compatibility

- Tested end to end on n8n 2.41.7 (self-hosted, Docker), the only version tested so far. The node
  uses the community-node API version 1 and Node.js's built-in `crypto`. It also relies on features
  of recent n8n releases (themed icons, `NodeConnectionTypes`, tool usage), so old 1.x releases are
  not expected to work; a minimum version has not been established.
- No runtime dependencies.
- The n8n host must reach `https://anon.prosecco37.com` over HTTPS and have a correct clock: requests
  carry a timestamp and the gateway refuses stale ones.
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
  **Redacted** style, which keep no map. With the map on, the real values would be returned to the
  model, which defeats the purpose. Without the map, the model's answer cannot be revealed later.
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

One gateway request per item. Keep each text under about 100,000 characters (that size takes around
5 seconds); much larger texts can fail on the gateway. Split long documents into several items.
Detection quality depends on the gateway's models. NER is statistical: it can miss a name or tag
only part of one, especially in unusual sentence structures, so always review protected text before
relying on it for anything sensitive. Values already in an Existing Placeholder Map are always
replaced, whether or not the gateway detects them.

## Which placeholders to use

No placeholder style is "compliant" or "non-compliant" by itself. What matters under the GDPR is
whether the output can still be linked back to a person, and who holds the key.

| Style | Example | Can you tell people apart? | Reveal | What it is |
| --- | --- | --- | --- | --- |
| Random | `[PERSON_a7k2q]` | Yes | Yes, with the placeholder map | Pseudonymisation (GDPR Art. 4(5)) |
| Sequential | `[PERSON_1]` | Yes, and it shows the order values were found | Yes | Pseudonymisation |
| Type Only | `[PERSON]`, `[PHONE_NUMBER]` | No, only what kind of value was there | No, nothing is kept | Masking |
| Redacted | `[REDACTED]` | No | No, nothing is kept | Masking / redaction |

- **Random and Sequential** give the same person the same placeholder, so the LLM can still follow
  who did what, and Reveal puts the values back. The text stays **personal data**: the placeholder
  map is the re-identification key. Keep maps private and away from the LLM provider. Random is the
  default because maps from separate runs do not collide the way `[PERSON_1]` would.
- **Type Only and Redacted** remove linkability: no map is produced, so there is nothing to reveal.
  Data minimisation (Art. 5(1)(c)) and privacy by design (Art. 25) favour them when the task does
  not need to know who is who, such as classification, summarising or sentiment.
- **Type Only** is usually the better non-linkable choice: "[PERSON] approved the invoice" reads far
  better, to a model and to people, than "[REDACTED] approved the invoice".
- **Redacted** leaks almost nothing, not even the kind of value. Use it for the most sensitive text
  and for anything published.
- **No style makes text anonymous.** The node replaces what the gateway detects and what your
  existing map holds. Job titles, dates, places, rare events and writing style can still identify
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
| A whole Protect output item | `{{ $('Protect').item.json }}` |
| An Anonymizator browser extension ID file | `{"format": "anonymizator-id-file", "version": 1, ...}` |

Placeholders start with a capital letter and contain only letters, digits and underscores. An entry
with an empty value is treated as retired: its placeholder is never reused, and it is never
revealed. Error messages name the offending placeholder or entry number but never repeat a value.

### Working with the Anonymizator browser extension

The node uses the same placeholders and the same ID file format as the Anonymizator Chrome
extension:

- **From n8n to the browser:** turn on **Include ID File**, then add **Convert to File → Convert to
  Text File** with **Text Input Field** set to `idFile`, and open the file in the extension with
  **Load IDs**. The extension then reveals answers you paste into it. (Convert to JSON writes the
  whole item, with `idFile` nested inside it, and the extension refuses that file.)
- **From the browser to n8n:** pass an ID file saved with **Save IDs** (read it with **Extract from
  File**, or paste its contents) as Reveal's Placeholder Map or Protect's Existing Placeholder Map.
  The node's Placeholder Style setting is used for new placeholders, not the style recorded in the
  file.

ID files hold the real values. Keep them as private as the data itself.

## What leaves n8n

Only **Protect** and **Detect** make network requests, and only to `https://anon.prosecco37.com`,
through n8n's own HTTP helper (so n8n's proxy settings apply). There is no telemetry, analytics or
any other endpoint.

| Sent to the gateway | When | Notes |
| --- | --- | --- |
| `GET /v1/keyconfig` with your API key as `Authorization: Bearer ...` | When you test or save the credential; otherwise at most once every 10 minutes per n8n process, plus once more when the gateway rotates its key and one retry after a server error (a failed answer is never cached, so it is fetched again for the next item) | No body. The answer is the gateway's signed public key, checked against the pinned trust root before anything else is sent. |
| `POST /v1/analyze` with your API key as `Authorization: Bearer ...` | Once per item with non-blank text; at most a few times when the gateway asks for a retry (a 5xx answer, a key rotation, or a refused entity filter) | The body is HPKE-encrypted (RFC 9180) to the verified key. |
| Inside the encrypted body | | The **Text** parameter, with each half of an emoji (UTF-16 surrogate) replaced by a space so that positions line up, and, with Selected Types, the list of entity types. Padded with spaces to a fixed size bucket, so the body length does not track the text length. |
| In the clear, in the request frame | | A version byte, the gateway key id, the current time in seconds (the gateway refuses stale requests) and a one-time public key. |
| In the clear, as HTTP headers | | `Content-Type`, `Accept`, `Authorization`, and the standard headers n8n's HTTP helper adds. |

Never sent anywhere:

- the placeholders and the placeholder map, including the **Existing Placeholder Map** you pass in;
- **Ignore Terms** (they are applied after detection, inside n8n);
- ID files;
- anything **Reveal** reads or writes: Reveal makes no network request and needs no credential;
- the other fields of the input item, and blank text.

The gateway answers with entity types, positions and scores, encrypted with a key only this request
can derive. It returns no text, no placeholders and no map. The gateway is operated by Prosecco 37,
which states that it is stateless and keeps nothing. The node cannot verify what happens on the
server; what it can guarantee is the list above.

## Privacy notes

- **What leaves n8n:** only the text of Protect and Detect, encrypted with HPKE (RFC 9180) to the
  gateway's current key; see [What leaves n8n](#what-leaves-n8n) for the details. Network
  intermediaries, including the CDN in front of the gateway, see ciphertext. Before
  sending, the node checks that the gateway's key is signed by the pinned Anonymizator trust root;
  if it is not, nothing is sent and the item stops with an explanation (this can mean a
  TLS-inspecting proxy is intercepting the connection).
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

- **0.1.1** (2026-10-06): **Detect** operation; **Include Placeholder Map** and **Ignore Terms** options;
  an importable example workflow; documentation of exactly what leaves n8n.
- **0.1.0** (2026-10-05): first release. Protect and Reveal, four placeholder styles, map
  continuation and sharing across items, extension ID files.
