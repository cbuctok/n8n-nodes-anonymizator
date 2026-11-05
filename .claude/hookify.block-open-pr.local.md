---
name: block-open-pr
enabled: true
event: bash
action: block
pattern: \b(gh|pun|tea)\s+pr\s+create\b|(-X\s*POST|--method\s+POST)[\s\S]*/pulls\b|/pulls\b[\s\S]*(-X\s*POST|--method\s+POST)
---

🛑 **Never open pull requests.**

pushin.eu cannot close or delete PRs, and this workflow doesn't use them. Land work
locally: squash the feature branch, `git merge --no-ff <branch>` into `dev`, then
promote `dev` to `main` (`make land BR=<branch>`).
