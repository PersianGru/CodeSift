# `sift ui`

```bash
sift ui                 # follow your scans and fixes live
sift ui --demo          # a synthetic run (about 2.5 min, every kind of event): no scan, no VM, no model
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

One small island at night: the castle on its hill, a river with a bridge, the wizard's tower on a
knoll, the dungeon pit against a hillside, and a graveyard (the wilds) across the river. Every road
joins two places.

| In the realm | Is really |
|---|---|
| The **CodeSift castle**, its crystal and the beacon on the keep | this machine; the crystal spins faster with activity, and the beacon burns green (exit 0) or red when the run ends |
| A **hero** in the courtyard | one scanner of the run: Rogue = gitleaks, Mage = opengrep, Ranger = trivy, Knight = bandit, Barbarian = ruff, Scout = osv-scanner, Cleric = zizmor, Alchemist = pip-audit, Bard = composer-audit, Monk = govulncheck |
| A hero walking out over the bridge and **searching the wilds** | that scanner running; it walks home when it reports. Sitting at camp = skipped, lying down = error |
| A **skeleton** rising in the wilds | one finding: Skeleton Lord = critical, Warrior = high, Rogue = medium, Minion = low, small Minion = info. Past forty, the rest are counted on banners by severity |
| A **champion** duelling a skeleton | a fix backend working on that finding. Each proof result is a blow: green when a gate passes, red when it fails |
| The skeleton's **fate** | lies still = fixed and verified; sits = fixed, unproven; stands and taunts = not fixed; wrapped in fog = inconclusive |
| The **oracle tower**, an oracle and an orb per model | the LLM gateway and each model (primary and fallback); the orb and the rune ring spin up while a call is in flight |
| A **raven** | one LLM call: violet out (bigger = longer prompt), gold back (bigger = more tokens). A raven that turns grey and falls is a failed call |
| A **rune** running along the dungeon road | one command to the sandbox VM: blue out, green back, red on failure |
| **The dungeon** and its five cells | the sandbox VM; a cell is blue while a job runs, then green (rc 0) or red. Scans never enter it |
| The dungeon's **wards** | the sandbox isolation self-test: cyan when it holds, flickering red when it fails |

Click the castle, a hero, a champion, a skeleton, an oracle, the tower or the dungeon for its real
numbers; hover names it. Drag to orbit, wheel or `+`/`-` to zoom, arrow keys to turn, `Home` to
reset. The camera eases toward the action and back by itself; touching it stops that for 20 seconds,
and it never moves by itself under `prefers-reduced-motion`. Labels are HTML, so they stay sharp.
three.js and the models load only when this view is chosen (about 6 MB, from this package). The
land, trees, bridge and towers are built in code (`realm-kit.js`); characters and props are KayKit
by Kay Lousberg (CC0), see `vendor/THIRD_PARTY.md`; `scripts/pack_kaykit.py` rebuilds them from the
free packs.

### 2D: the light map

The same realm seen from above, drawn on a plain canvas: no WebGL and no three.js, so it suits old
laptops, phones and low memory. Heroes are lettered tokens that walk the road, findings are shapes
by severity in the wilds (the same shapes as the counters in the status strip), ravens fly between
the keep and the tower, runes run to the dungeon, and the cells and wards light as in 3D. The land
is painted once; when nothing moves the map redraws only a few times a second. It is the default
on small screens and where WebGL is missing.

### The status strip and panels

Over every view: the run's state (running, victory, or not clean with the exit code) and what it is
doing right now, the findings by severity, and three lamps that light while scanners, LLM calls or
VM commands are in flight. The event log shows two lines until opened; the details drawer opens
when something is clicked, and offers the patch review for a finished finding.

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
`p` pauses. `--demo` plays the same synthetic run as `sift ui --demo`. `--once` prints one frame and exits; `--ascii` swaps box drawing for plain ASCII.
`NO_COLOR` turns colour off.
