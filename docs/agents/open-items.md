# Open items

_Moved out of `AGENTS.md` (2026-11-05). Section names quoted in the text may now live in a sibling file under `docs/agents/`; `AGENTS.md` has the index._

- **API key portal URL.** Keys are created and managed in the Prosecco 37 Anonymizator user portal
  (decided 2026-10-05), which has no public URL yet. The links belong where the
  `TODO(api-key-portal)` markers are: the README's Credentials section, the credential's
  `properties` (description or `hint`), the example's README and the submission note.
- **Reviewer key** for the verification video and review: `TODO(reviewer-key)` in
  `docs/verification-submission.md`.
- **Submit 0.2.0 or later**, once it is staged by CI with provenance and approved. Never 0.1.0 (no
  provenance), and not 0.1.1 either: 0.1.x speak only the gateway's protocol v1, which the gateway
  stops accepting before 2027-02-16 (`docs/HPKE.md` in the gateway repository).
- **AI tool usage (critique O6), partly resolved.** Include Placeholder Map lets a tool call return
  no real values, Detect returns no values by default, Reveal carries an agent warning, and the
  README has a safe recipe. The tool variant has still only been checked as loaded in e2e, never run
  with an agent; do that before recording the video.
- **Example canvas screenshot.** The Creator Hub rules want a `canvas.png` beside a community-node
  template; it needs a browser, so the example has none yet. Keep images out of `files`.
- **e2e before each release.** The parity branch passed `npm run n8n:reset && npm run e2e` on
  2026-10-22 (all 19 nodes, `getEntityTypes` with server-only rows); run it again before releasing.
- **Possible types.** Production lists none (2026-10-21), so the gateway half of Include Possible IDs
  (`"possible": true`, kind `detected`, Detect's `possibleIds`) has only been tested against the
  vectors and the fake gateway. Re-run the smoke scenario when the gateway adds some.
- **e2e with the Encryption setting.** Not run for the Automatic change (2026-11-05: the host's
  disk was full, so the n8n 2.44.5 image could not be pulled). Run `npm run n8n:reset && npm run
  e2e` before releasing; also open the credential in the editor once to see the **Encryption**
  dropdown (boolean option values) and check which Node.js the n8n image runs (`docker exec
  n8n-anonymizator-dev node -v`), since that decides what Automatic does there.
- **Company spans tagged as LOCATION.** The gateway tagged "Modra Vila d.o.o." as LOCATION including
  the legal form; `companySpans` (like the extension) does not retype it. A server-side or
  extension-side decision, not a node fix.

