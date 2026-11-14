# `sift ui`

```bash
sift ui                 # browse your validate/fix runs
sift ui --demo          # a synthetic run: no scan, no VM, no model
sift ui --run DIR       # replay one run folder (with events.jsonl)
sift ui --port 8765 --open --ci
```

`sift ui` prints a one-time URL like `http://127.0.0.1:<port>/?token=…`. Opening it sets an
HttpOnly, SameSite=Strict cookie and redirects to `/`. Press Ctrl-C to stop the server.

## Security model ([ADR-0015](decisions/ADR-0015-ui-living-city.md))

- **Network**: binds to `127.0.0.1` only (any other bind address is refused) and makes no external
  requests. three.js r128 is vendored and its sha256 is recorded in
  `src/codesift/ui/static/vendor/THIRD_PARTY.md`.
- **Request checks**: every request needs the cookie and a `Host` of `127.0.0.1:<port>` or
  `localhost:<port>`. POST also needs a matching `Origin` and `X-CodeSift-CSRF: 1`.
- **Headers**: `Content-Security-Policy: default-src 'self'` (no inline script or style), `nosniff`,
  `no-referrer`, `no-store`.
- **Decisions**: Approve / Reject / Retry-with-note only append to the run's `decisions.json`.
  **Nothing is ever applied.**
- **Content**: no secrets and no source code are shown, apart from the patch diff you open yourself.

## The living city

The city is a top-down neon night city of your project:

- **Buildings and districts.** Buildings are files, grouped in districts by path prefix:
  - *db/ Data Vault*
  - *web/ Neon Market*
  - *tools/ Workshop Row*
  - *uploads/ Storage Yard*
  - *config/ Config Bank*
  - *vendor/ Supply Docks*
  - *Annex*

  Configure the districts with `[ui.districts]`. A district shows at most 9 buildings and folds the
  rest into a "+N files" block.
- **Building states:**

  | State | Look |
  |---|---|
  | healthy | normal |
  | latent | infection not yet visible |
  | infected | red edges, flag, smoke |
  | repair | amber scaffold, sparks |
  | fixed | green |

- **Bugs.** Findings appear as bug characters:

  | Character | Finding |
  |---|---|
  | Syringe leech | SQL injection |
  | Mask imp | XSS |
  | Shell wraith | command injection |
  | Tunnel worm | path traversal |
  | Key thief | secret |
  | Rotten crate | vulnerable dependency |
  | Glitch | anything else |

  Bugs are sized by severity, and critical ones get a red beam.
- **Ops centre** on the pentagon ring road:

  | Station | Role |
  |---|---|
  | Command tower | scanner sweep and globe |
  | The Oracle | triage |
  | Local garage | gateway fixer |
  | Claude forge | Claude CLI fixer |
  | Relay tower | Claude API fixer |
  | Checkpoint | patch policy |
  | Quarantine lab | sandbox |
  | Courthouse | re-scan and PoC |
  | Landfill | rejected findings |
  | Limbo yard | inconclusive findings |

- **Driven by real events.** Bugs walk to the stations in event order. `fixed_*` bugs walk home as
  citizens and their building is repaired. Rejected bugs go to the landfill, inconclusive ones to
  limbo. City health = buildings that are not infected or repairing ÷ all buildings.
- **Always alive.** Two-lane traffic, drones, rain, pings, flickering beacons and smoke, rotating
  dishes and gears, fire glow.
  - `prefers-reduced-motion` reduces all of it.
  - The top bar has Pause and Speed controls.
  - Drag to orbit, use the wheel or `+`/`-` to zoom, and arrow keys to turn.
  - Browsers pause animation while the tab is hidden.

## Plain dashboard

The plain dashboard is a table of findings with stage, backend, outcome and gate results (✓, ✗ or
*unavailable* in words), plus the same review actions.
- **Default** when WebGL is unavailable, on small screens, and with `--ci`.
- **Accessibility**: keyboard accessible, and colour is never the only signal.
- **Text alternative**: the 3D view keeps a text summary up to date for screen readers.
