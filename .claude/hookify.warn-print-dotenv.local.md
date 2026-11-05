---
name: warn-print-dotenv
enabled: true
event: bash
action: warn
pattern: \b(cat|less|more|head|tail|bat|grep|rg|awk|sed)\b[^|;&]*(^|[\s/'"])\.env(\.local)?(\s|$|['"])
---

⚠️ **Don't print or search `.env`.** The user drops short-lived secrets there and has
forbidden reading it. Use it only via scripts (`set -a; . ./.env; set +a` inside a
script) and delete it when the task is done.
