# Security policy

## Reporting a vulnerability

Please report security issues privately, not in a public issue:

- through GitHub's private vulnerability reporting: **Security → Report a vulnerability** on
  <https://github.com/cbuctok/n8n-nodes-anonymizator>, or
- by email to greg@digitaliziran.si.

Include the package version, the n8n version, and steps to reproduce. Use synthetic data only; never
send real personal data or API keys in a report. You should get an answer within a few working days.

## Scope

In scope is everything in this repository and the published `n8n-nodes-anonymizator` package, in
particular:

- the HPKE encryption of requests and responses (`nodes/Anonymizator/shared/hpke.ts`);
- the key configuration check: the pinned trust root, the signature verification and its fail-closed
  behaviour (`shared/keyconfig.ts`, `shared/gateway.ts`);
- anything that could send personal data, a placeholder map or an API key somewhere it should not
  go, or put a protected value into an error message or log;
- placeholder map and ID file parsing, and Reveal.

Issues in the Anonymizator gateway itself (`anon.prosecco37.com`), its sign-in or the Anonymizator
user portal belong to Prosecco 37, which operates them. If you are not sure where an issue belongs,
report it here and it will be forwarded.

## Supported versions

Fixes are released for the latest published version only.
