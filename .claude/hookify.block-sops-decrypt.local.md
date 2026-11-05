---
name: block-sops-decrypt
enabled: true
event: bash
action: block
pattern: (^|[\s;&|(`])sops\s+(-d\b|--decrypt\b|decrypt\b|-i\s+-d\b)
---

🛑 **Never decrypt `.env.enc` — not to a file, not piped, not "just to check a key".**

Use instead:

```bash
./sops list                 # key names only
./sops list --has KEY       # does KEY exist?
./sops <cmd> ...            # run a command with secrets in its env
./scripts/env-set KEY value # add / change a value (repos that have it)
```

If a task truly needs a plaintext value, write the exact command for the user to run.
