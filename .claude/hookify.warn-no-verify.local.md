---
name: warn-no-verify
enabled: true
event: bash
action: warn
pattern: git\s+(commit|push|merge)\b[^;&|]*--no-verify
---

⚠️ **Don't bypass repo hooks.** Fix what the hook reports, or ask the user. The only
accepted exception is a docs-only commit the user explicitly OK'd.
