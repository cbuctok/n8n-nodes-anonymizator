---
name: warn-pkill-self
enabled: true
event: bash
action: warn
pattern: \bpkill\s+(-\w+\s+)*-f\s+['"]?[^\['"\s]
---

⚠️ **`pkill -f <pattern>` usually kills its own shell** (the pattern matches the calling
command line → exit 144). Use the bracket trick `pkill -f '[u]vicorn ...'`, or save
the PID (`echo $! > pidfile`) and `kill "$(cat pidfile)"`.
