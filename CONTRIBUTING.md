# Contributing to CodeSift

Read [RULES.md](RULES.md) first: it lists what CodeSift must never do, and a change that breaks one
of those rules is a bug. Then [README.md](README.md) and [docs/architecture.md](docs/architecture.md).

## Development setup

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"      # Linux/macOS: .venv/bin/python
.venv/Scripts/python -m pytest
.venv/Scripts/python -m mypy
.venv/Scripts/python -m ruff check .
.venv/Scripts/python -m black --check .
```

All four must be clean before a commit. `black` line length is 110; `mypy` is `--strict`.

## Conventions

- Runtime code uses the standard library only (`urllib`, `json`, `tomllib`, `subprocess`). Adding a
  runtime dependency needs an ADR in `docs/decisions/`.
- Every string that can reach a report, log, raw output or LLM prompt goes through
  `codesift.redact.Redactor`.
- Write text files with `encoding="utf-8"` and `newline="\n"`.
- Test fixtures must not contain secret-shaped strings; generate fake secrets at test time in a temp
  dir.
- Tests never touch the real network; offline tests block sockets.
- Real decisions get an ADR (`docs/decisions/ADR-NNNN-title.md`); user-visible changes go in
  `CHANGELOG.md`.
- Never commit credentials, venvs, caches or scan outputs. Keep your own `gateway.env` outside the
  repository (or in a git-ignored folder).
- Never name a specific LLM gateway product in user-facing text (RULES.md rule 20).
- Tests never contact a real VM: use `tests/fake_vm.py` (it also checks every command against the
  gate's allow-list). The live test runs only with `CODESIFT_LIVE_VM=1`.
- Untrusted code never runs locally, not even in tests; fixers in tests are fakes.

## Refreshing pinned tools (maintainers)

```bash
.venv/Scripts/sift update                                 # what is outdated (7-day cooldown)
.venv/Scripts/sift update --apply --lock tools.lock.json  # rewrite the checkout's locks + rules/
```

Review the diff of `tools.lock.json`, `requirements.lock` and `rules/` before committing.

## Re-evaluating the LLM

After changing the triage prompt (bump `PROMPT_VERSION`), the models or the model server, re-run
`python scripts/bakeoff.py` (needs gateway credentials) and update `docs/model-eval.md`. Never edit
the corpus in a way that hints at the answer (file names, comments).

## Reporting security problems

Privately, as described in [SECURITY.md](SECURITY.md).
