# Changelog

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
