# Changelog

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
