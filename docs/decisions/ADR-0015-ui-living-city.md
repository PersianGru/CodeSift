# ADR-0015: `sift ui` — local server, vendored three.js, token model, city design

- Status: accepted
- Date: 2026-11-14
- Related: [ADR-0004](ADR-0004-stdlib-only-runtime.md) (no Python dependency; the 3D library is a
  static browser asset), [ADR-0006](ADR-0006-scan-pipeline.md) (finding schema the UI shows)

## Context

Fix runs are long and have many moving parts (stages, backends, gates). The owner wants to *watch*
them, in a form that is pleasant to leave open: a top-down neon "living city" where files are
buildings and findings are bugs. First-person views and flat linear layouts were rejected.

## Decision

1. **Server**: `http.server.ThreadingHTTPServer`, bound to `127.0.0.1` only (any other bind address
   is refused), random port unless `--port`.
2. **Token model**: a random 128-bit+ token is printed once in the start URL; the first request with
   it sets an `HttpOnly; SameSite=Strict` cookie and redirects to a token-less URL. Every request needs
   the cookie (compared in constant time) and a `Host` of `127.0.0.1:<port>` or `localhost:<port>`.
   POST needs a matching `Origin` and a custom header (CSRF).
3. **Headers**: strict CSP (`default-src 'self'`, no inline script/style), `nosniff`,
   `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.
4. **No external requests**: three.js r128 (MIT) is vendored with its licence and sha256 recorded in
   `THIRD_PARTY.md`; a test verifies the hash and that no served file references an external URL.
5. **Data**: the engine's `events.jsonl` is the only contract. The UI replays it (`--run DIR`),
   tails it live (server-sent events), or plays a synthetic stream (`--demo`, no scan, no VM).
6. **Decisions**: `POST /api/decision` (approve / reject / retry + note) only appends to the run's
   `decisions.json`. It never applies a patch or touches the project.
7. **City design**: buildings = files grouped into districts by path prefix (configurable via
   `[ui.districts]`); bug characters by class (SQL injection, XSS, command injection, path traversal,
   secrets, vulnerable dependency, generic); an ops centre with the command tower, oracle (triage),
   three fixer stations, checkpoint (policy), quarantine lab (sandbox), courthouse (re-scan + PoC),
   landfill (rejected) and limbo (inconclusive). Traffic, drones and rain keep it alive; reduced
   motion is respected; pause and speed controls.
8. **Plain dashboard** with the same data and actions: the default without WebGL, on small screens,
   and in CI mode; keyboard accessible; colour is never the only signal.

## Consequences

- The UI shows only metadata and, when the user opens it, the patch diff. Never secrets or source
  beyond that diff.
- If the vendored library is missing, the dashboard still works.
