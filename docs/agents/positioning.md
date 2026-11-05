# Positioning: Guardrails and similar community nodes

_Moved out of `AGENTS.md` (2026-11-05). Section names quoted in the text may now live in a sibling file under `docs/agents/`; `AGENTS.md` has the index._

Researched 2026-10-06 and re-checked 2026-10-22 against `@n8n/n8n-nodes-langchain` 2.44.3 (the
version n8n 2.44.5 ships) and the latest published packages of similar nodes. Facts worth keeping, so docs never overclaim:

- **Guardrails, Sanitize Text** (the overlap a reviewer will ask about): its PII check is 36
  unvalidated regexes (US, UK, ES, IT, PL, SG, AU, IN, FI; no SI/HR/AT IDs) plus custom regex; no
  built-in type is a person name; LOCATION is a street-suffix regex (no cities); every value of a
  type becomes the same `<TYPE>` tag; there is no restore step, but the matched originals are listed
  in its `checks` output. Sanitize sends nothing; the LLM-based checks (jailbreak, NSFW, topical,
  custom) are in Check Text for Violations and use the connected chat model.
- **Not unique to us**, do not claim them as such: NER or ML detection (doccape, Privent's API mode,
  PII Guardrails' server, several unverified nodes), heuristic name detection inside n8n (Miravig,
  eu-pii-redact), reversible numbered placeholders with a map (PII Guardrails, eu-pii-redact,
  anymize), reversible placeholders with a restore step and offline, credential-free restore
  (Privent's Local Detokenize, eu-pii-redact, rehydra), checksum-validated EMŠO, OIB and Austrian
  SVNR (Miravig validates all three; eu-pii-redact covers 21 EU/EEA national IDs),
  a node ported from its own browser extension (Miravig), zero runtime dependencies, provenance,
  `usableAsTool`, returning spans and offsets, a detect-only operation.
- **Defensible**: HPKE application-layer encryption with pinned, fail-closed trust roots (a signed
  delegation chain to keys with a signed expiry) and a ranges-only, stateless gateway (every compared remote node sends plaintext over TLS); local
  substitution and map; random, non-guessable placeholders; Share Map Across Items and map
  continuation; `_NAME`/`_SURNAME` entries; `unresolvedPlaceholders`; the extension ID file and the
  extension's engine; an entity list from a signed server document; a credential test that tells a
  bad key from a missing role.
- Name competitors only in `docs/verification-submission.md`, one neutral sentence each; the README
  compares only with the built-in Guardrails node.

