---
name: block-ai-attribution
enabled: true
event: bash
action: block
pattern: git\s+(commit|merge|tag|notes)\b[\s\S]*(co-authored-by:\s*claude|generated\s+with\s+\[?claude|noreply@anthropic\.com)
---

🛑 **No AI attribution in commits, merges, tags or notes.**

The user has asked for this repeatedly, and purged history on 2026-10-19. Remove the
`Co-Authored-By: Claude` / "Generated with Claude" / anthropic noreply trailer and
retry. This applies to messages you write yourself, in heredocs or `-m`.
