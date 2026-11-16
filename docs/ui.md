# `sift ui`

```bash
sift ui                 # follow your scans and fixes live
sift ui --demo          # a synthetic run: no scan, no VM, no model
sift ui --run DIR       # replay one run folder (with events.jsonl)
sift ui --port 8765 --open --ci
```

`sift ui` prints a one-time URL like `http://127.0.0.1:<port>/?token=…`. Opening it sets an
HttpOnly, SameSite=Strict cookie and redirects to `/`. Press Ctrl-C to stop the server.

## Security model ([ADR-0015](decisions/ADR-0015-ui-living-city.md); the city became the system map)

- **Network**: binds to `127.0.0.1` only (any other bind address is refused) and makes no external
  requests. three.js r128 and its add-ons are vendored and their sha256 are recorded in
  `src/codesift/ui/static/vendor/THIRD_PARTY.md`.
- **Request checks**: every request needs the cookie and a `Host` of `127.0.0.1:<port>` or
  `localhost:<port>`. POST also needs a matching `Origin` and `X-CodeSift-CSRF: 1`.
- **Headers**: `Content-Security-Policy: default-src 'self'` (no inline script or style), `nosniff`,
  `no-referrer`, `no-store`.
- **Decisions**: Approve / Reject / Retry-with-note only append to the run's `decisions.json`.
  **Nothing is ever applied.**
- **Content**: no secrets and no source code are shown, apart from the patch diff you open yourself.

## The live system map

The map shows the machines and services that really take part in a run, and the real traffic
between them. **Nothing is invented**: every node comes from the run's topology (recorded when the
run starts), and every moving packet is one event from the run's `events.jsonl`. With no events,
nothing moves except the slowly turning camera.

- **This machine**: the CodeSift core and one column per scanner of the run. A column is grey while
  queued, amber while running, green when done (its height grows with the number of findings) and
  red on an error. The label shows findings and time. Findings orbit the core as small crystals,
  coloured by severity.
- **LLM gateway**: the gateway host and one glass orb per model (primary and fallback). An orb
  glows and its ring spins while a request is in flight. The label shows calls, tokens in/out and
  the average answer time.
- **Sandbox VM**: `user@host · runtime` and the image. Every command CodeSift sends over SSH (image
  check, free memory, list jobs, job) blinks the host. A job appears as a container labelled with
  its real name (`sift-<id>`); it turns green (rc 0) or red, with its time, and fades after 30 s.
- **Packets**: blue = a scanner started or reported; amber = a request to a model (bigger = longer
  prompt); light amber = the answer (bigger = more tokens); green = a VM command or job; red = a
  failed call, job or scanner.
- **Follow live**: the page lists scans and fixes, newest first, and switches to a new run as soon as
  it starts, unless you picked another run. *Follow live* goes back to following.
- **Click** the core, a scanner, a model or the VM for its numbers. Drag to orbit, wheel or `+`/`-` to
  zoom, arrow keys to turn. `prefers-reduced-motion` turns packets off (links light up instead).
- **Rendering**: three.js r128 plus its own bloom pass and studio-light reflections (vendored, see
  `vendor/THIRD_PARTY.md`); no external requests.

What is recorded is metadata only: scanner names, versions, counts and times; model ids, prompt size
in characters, token counts, answer times and error codes; VM operation names, job ids, exit codes,
sizes and times. Never a prompt, an answer, a command line or any output.

## Plain dashboard

The plain dashboard is a table of findings with stage, backend, outcome and gate results (✓, ✗ or
*unavailable* in words), plus the same review actions.
- **Default** when WebGL is unavailable, on small screens, and with `--ci`.
- **Accessibility**: keyboard accessible, and colour is never the only signal.
- **Text alternative**: the 3D view keeps a text summary up to date for screen readers.

## `sift top`: the terminal view

`sift top` follows the newest scan or fix in the terminal, with no browser and very little memory.
It reads the same `events.jsonl` as the web UI, so it shows only what really happened:

| Panel | Shows |
|---|---|
| Header | project, scan or fix, LIVE / VICTORY / MONSTERS REMAIN, elapsed time, and a threat bar by severity |
| Party | one hero per scanner (Rogue = gitleaks, Mage = opengrep, Ranger = trivy, Knight = bandit, Barbarian = ruff, Scout = osv-scanner, Cleric = zizmor, ...): fighting, found N, at camp (skipped) or fallen (error) |
| Bestiary | one monster per finding, by severity (Skeleton Lord = critical ... Bones = info), with its file and its fate in a fix run (slain = fixed and verified, wounded = fixed but unproven, escaped = rejected) |
| Oracle tower | the LLM gateway host and models, calls (ravens), failures, tokens, and a latency graph |
| Dungeon | the sandbox VM, jobs, commands, failures and a job-time graph (scans never use it) |
| Battle log | every event in plain words, newest first |

Keys: `q` quits, `←`/`→` (or `[` `]`) step to older or newer runs, `f` follows the newest run again,
`p` pauses. `--once` prints one frame and exits; `--ascii` swaps box drawing for plain ASCII.
`NO_COLOR` turns colour off.
