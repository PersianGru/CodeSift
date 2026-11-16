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

## Three views: 3D, 2D and Table

The buttons at the top switch between three views of the same run; the choice is remembered in
this browser. All three are built only from the run's own `events.jsonl` and report. **Nothing is
invented**: every place comes from the run's topology (recorded when the run starts), and every
moving thing is one real event. With no events, nothing moves.

### 3D: the realm (fantasy view)

| In the realm | Is really |
|---|---|
| The **CodeSift castle** and its crystal | this machine; the crystal spins faster with activity and turns green (exit 0) or red at the end |
| A **hero** in the courtyard | one scanner of the run: Rogue = gitleaks, Mage = opengrep, Ranger = trivy, Knight = bandit, Barbarian = ruff, Scout = osv-scanner, Cleric = zizmor, Alchemist = pip-audit, Bard = composer-audit, Monk = govulncheck |
| A hero riding out to **the wilds** and fighting there | that scanner running; it comes back when it reports. Sitting at camp = skipped, lying down = error |
| A **skeleton** rising in the wilds | one finding: Skeleton Lord = critical, Warrior = high, Rogue = medium, Minion = low, small Minion = info. In a fix run a champion (the fix backend) fights it; it falls when the fix is verified |
| The **oracle tower** and an oracle per model | the LLM gateway and each model (primary and fallback); an oracle casts while a call is in flight |
| A **raven of light** | one real call or reply: violet = request (bigger = longer prompt), gold = answer (bigger = more tokens), teal = a scanner, blue = the VM, red = a failure |
| **The dungeon** and its lit cells | the sandbox VM; a cell glows while a job runs and flashes green (rc 0) or red. Scans never enter it |

Click the castle, a hero, a skeleton, an oracle, the tower or the dungeon for its real numbers.
Drag to orbit, wheel or `+`/`-` to zoom, arrow keys to turn. Labels are HTML, so they stay sharp.
three.js and the models load only when this view is chosen (about 6 MB, from this package).
Models: KayKit by Kay Lousberg (CC0), see `vendor/THIRD_PARTY.md`; `scripts/pack_kaykit.py`
rebuilds them from the free packs.

### 2D: the light map

A flat map drawn on a plain canvas: no WebGL and no three.js, so it suits old laptops and low
memory. This machine with its scanners, the LLM gateway with one orb per model, and the sandbox VM
with its jobs; dots travel along the links for each real event, and findings sit under the core as
diamonds coloured by severity. When nothing moves it redraws only a few times a second. It is the
default on small screens and where WebGL is missing.

### Table

The plain findings table (see below), for CI and screen readers.

### Following runs

The page lists scans and fixes, newest first, and switches to a new run as soon as it starts,
unless you picked another run. *Follow live* goes back to following. `prefers-reduced-motion`
stops the camera turning.

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
