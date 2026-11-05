---
name: block-commit-tfstate
enabled: true
event: bash
action: block
pattern: git\s+add\b[^;&|]*tfstate
---

🛑 **Never commit tfstate.** State files contain secrets (credentials, keys, IPs).
Keep them out of git; check `.gitignore` covers `*.tfstate*`.
