# n8n-nodes-anonymizator

This is an n8n community node that keeps personal data out of your prompts. **Protect** finds names,
email addresses, bank accounts, national ID numbers and other personal data in text and replaces
them with placeholders such as `[PERSON_a7k2q]` before the text goes to an LLM. **Reveal** puts the
original values back into the LLM's answer, using the placeholder map Protect produced.

Detection runs on the Anonymizator privacy gateway (`anon.prosecco37.com`), operated by Prosecco 37.
Names, locations and similar free-text data are found with **named-entity recognition (NER)**, a
statistical model that recognises them from their context in the sentence rather than from a fixed
pattern; regional identifiers such as EMŠO, OIB and IBAN are found by recognisers that validate the
number. The text is end-to-end encrypted (HPKE) to the gateway, which returns only the positions of
what it found and keeps nothing. Everything else happens inside n8n: the placeholders, the map, masking and Reveal.
Reveal never contacts the gateway and needs no credential.

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
- [Privacy notes](#privacy-notes)
- [How it differs from the Guardrails node](#how-it-differs-from-the-guardrails-node)
- [Resources](#resources)
- [Licence](#licence)
- [Version history](#version-history)

## Installation

Follow the [installation guide](https://docs.n8n.io/integrations/community-nodes/installation-and-management/gui-installation)
in the n8n community nodes documentation.

The package name to install is:

```
n8n-nodes-anonymizator
```

Enter it exactly as written in **Settings → Community Nodes → Install**. It is unscoped, so there is
no `@org/` prefix.

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
| **Existing Placeholder Map** | empty | Continue an earlier map. Values it already holds keep their placeholders (and are replaced wherever they appear, even if the gateway would not have detected them), new placeholders never collide with it, and Sequential numbering carries on. Accepts every [map format](#accepted-map-formats), including an ID file from the browser extension. |
| **Share Map Across Items** | off | One running map for all items of the execution, so the same person gets the same placeholder in every item. Each item outputs the map as it stands after that item. A placeholder that stands for different values in two items' existing maps stops the item with an error. |
| **Include ID File** | off | Adds an `idFile` field the browser extension can open with **Load IDs**. To save it, use **Convert to File → Convert to Text File** with **Text Input Field** set to `idFile` (Convert to JSON would wrap it in the item, and the extension refuses that file). Random and Sequential styles only. Not added when the map is empty (nothing was detected and no Existing Placeholder Map was given). |
| **Include Input Fields** | off | Copies the input item's fields into the output item. |

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
| `placeholderMap` | The complete map needed to reveal this text: the existing map plus the new placeholders. Person names also get `_NAME` and `_SURNAME` entries, so an answer that mentions only "Janez" is revealed too. Retired placeholders from the existing map are kept with an empty value, so they stay retired when you pass the map back in. Empty (`{}`) for Type Only and Redacted. |
| `entities` | What was replaced, with `start`/`end` offsets into `protectedText`. |
| `entityFilterIgnored` | Present (`true`) only when the gateway refused the selected types and the node detected all types instead. |
| `idFile` | Present only with Include ID File, and only when `placeholderMap` has at least one value. |

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

Reveal replaces bracketed placeholders (`[PERSON_6kltt]`) and also the same key written without
brackets as a whole word (`PERSON_6kltt`), because LLMs sometimes drop the brackets. If you add your
own keys to a map, avoid ordinary words: a key `CLIENT` would also replace the word "CLIENT" in the
answer.

## Credentials

You need an Anonymizator API key. API keys are created and managed in the Prosecco 37 Anonymizator
user portal. Paste the key into the credential's **API Key** field.
<!-- TODO: add the user portal URL once it is public. -->

| Field | Required | Notes |
| --- | --- | --- |
| API Key | Yes | Stored as a password field and sent as a bearer token. Only Protect uses it. |

There is no base URL field: the node always talks to `https://anon.prosecco37.com`, because it only
trusts encryption keys signed by the Anonymizator trust root.

The credential test calls `GET https://anon.prosecco37.com/v1/keyconfig`, so a problem shows up when
you save the credential rather than on the first run:

- **API key rejected**: the key is wrong, expired or revoked.
- **The key is valid but has no access to Anonymizator (missing role)**: check in the user portal
  that the key belongs to an account with Anonymizator access.

## Compatibility

- Verified end to end on n8n 2.41.7 (self-hosted, Docker). The node uses only the standard
  community-node API (nodes API version 1) and Node.js's built-in `crypto`.
- No runtime dependencies.
- The n8n host must reach `https://anon.prosecco37.com` over HTTPS and have a correct clock: requests
  carry a timestamp and the gateway refuses stale ones.
- Usable as an AI Agent tool (`usableAsTool`). n8n 2.x generates the tool variant automatically; no
  environment variable is needed (old n8n 1.x releases needed
  `N8N_COMMUNITY_PACKAGES_ALLOW_TOOL_USAGE=true`). Read the [tool caveat](#privacy-notes) first.

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

## Privacy notes

- **What leaves n8n:** only Protect's text, encrypted with HPKE (RFC 9180) to the gateway's current
  key. Network intermediaries, including the CDN in front of the gateway, see ciphertext. Before
  sending, the node checks that the gateway's key is signed by the pinned Anonymizator trust root;
  if it is not, nothing is sent and the item stops with an explanation (this can mean a
  TLS-inspecting proxy is intercepting the connection).
- **What the gateway returns:** positions and types of what it found. It never sees placeholders or
  maps and keeps nothing.
- **What stays in n8n:** the placeholder map and everything Reveal does. Reveal makes no network
  request.
- **n8n stores execution data.** Saved executions contain the original text and the placeholder map.
  For workflows that protect sensitive text, turn off saving successful executions (and, where
  possible, failed ones) in the
  [workflow settings](https://docs.n8n.io/build/manage-workflows/configure-workflow-settings), or
  restrict who can view executions.
- **AI Agent tools see their results.** If an agent calls Protect as a tool, the tool's output,
  including `placeholderMap` with the original values, goes back into the model's context, which
  defeats the purpose. Run Protect as a normal node **before** the agent instead. The same applies
  to Reveal as a tool: whatever it reveals is shown to the model.

## How it differs from the Guardrails node

n8n's built-in [Guardrails](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-langchain.guardrails)
node can sanitize personal data. Its PII check uses regular expressions only, and it masks values
for good. Anonymizator is for a different job:

| | Guardrails (Sanitize) | Anonymizator |
| --- | --- | --- |
| How data is found | Regular expressions only | Named-entity recognition (NER) for names, locations and similar free text, plus validated recognisers for structured identifiers |
| Person names | Not detected (no pattern can match a name) | Detected by NER, with extra first-name and surname placeholders |
| Regional identifiers | A fixed pattern list | Slovenian EMŠO, tax and ZZZS numbers, Croatian OIB, Austrian social insurance number, IBAN and more |
| Reversible | No, values are masked for good | Yes: pseudonymise, keep the map locally, and Reveal the answer offline. Masking is available too. |
| Where detection runs | Inside n8n | On the Anonymizator gateway, over an HPKE-encrypted, ranges-only channel; the map never leaves n8n |
| Browser extension interop | n/a | Shares placeholders and ID files with the Anonymizator Chrome extension |

Guardrails needs no account and sends nothing anywhere; Anonymizator needs an API key and sends the
(encrypted) text to the gateway for detection. Neither makes text anonymous on its own.

## Resources

- [n8n community nodes documentation](https://docs.n8n.io/integrations/community-nodes)
- Anonymizator gateway: `https://anon.prosecco37.com` (sign-in required; API keys come from the
  Anonymizator user portal, see [Credentials](#credentials))
- [RFC 9180: Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180)
- [Changelog](CHANGELOG.md)

## Licence

[MIT](LICENSE.md), © 2026 Greg Evseev. Portions are ported from the Anonymizator browser extension,
© 2026 Prosecco 37 d.o.o., and contributed under the MIT licence with permission; see
[NOTICE](NOTICE).

## Version history

- **0.1.0** (2026-10-05): first release. Protect and Reveal, four placeholder styles, map
  continuation and sharing across items, extension ID files.
