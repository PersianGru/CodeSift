# Prompts: scan, fix and patch any project

Copy-paste prompts for Claude Code in **any** project. They assume CodeSift is installed on the
machine (`sift doctor` is green). They work for any language or stack: CodeSift detects what the
project uses.

The work is split across **two chats** so each step uses the right model:

| Chat | Model | Does | Changes the project? |
|---|---|---|---|
| **Chat 1 — Scan** | Sonnet (cheaper) | setup, scan, triage, writes the hand-off file | no (only `.codesift.toml`, with your OK) |
| **Chat 2 — Fix** | Opus (stronger) | re-checks the hard items, fixes, tests, verifies, closes out | yes, on its own branch |

Pick the model in the chat's model selector before you paste the prompt. The two chats never need to
share context: Chat 1 writes everything Chat 2 needs into **`triage.md`**.

## How everything stays organised

- **Scan results live outside the project**, in `~/.codesift/runs/<project>-<hash>/<timestamp>/`.
  Each project has its own folder, so projects never overwrite each other.
- **The hand-off lives there too**: Chat 1 writes `triage.md` next to the scan's `summary.md`;
  Chat 2 adds `fix-log.md` beside it. Later scans create new timestamp folders, so the hand-off is
  never overwritten. Chat 2 finds it as "the newest run folder of this project that has a
  `triage.md`".
- **Nothing extra goes into the project** except the fixes and, when you agree, `.codesift.toml`
  and `.codesift-baseline.json` (both meant to be committed).
- **Fixes go on their own branch** (`security/sift-YYYY-MM-DD`), one commit per issue, so your
  current work is never mixed in and every fix can be reviewed or dropped on its own.
- **No global changes**: the prompts never edit `~/.codesift/config`, other projects, git settings,
  or anything outside the project folder. Secret values are never printed.

## Which prompt when

| Situation | Chat 1 (Sonnet) | Chat 2 (Opus) |
|---|---|---|
| New project, first time | 1A → 1B | 2A → 2B |
| Regular check | 1B | 2A → 2B |
| Before a release / after changing auth, payments, webhooks | 1B with the deep review | 2A → 2B |
| One go per chat | [Chat 1 all-in-one](#chat-1-all-in-one) | [Chat 2 all-in-one](#chat-2-all-in-one) |

Run Chat 2 only after Chat 1 has finished and you have read its table.

---

# Chat 1 — Scan (Sonnet)

## 1A. Set up the project (once)

```text
Set up CodeSift for this project. Do not change any code.

1. Run `sift doctor`. If anything is red, stop and show me the fix it prints.
2. If there is no `.codesift.toml` in the project root, run `sift init`.
3. Look at the project structure (directory names and entry points only, not every file) and
   propose `review.critical_paths` globs for the security-sensitive code: authentication,
   sessions, permissions, payments/billing, webhooks, file uploads, admin, crypto/token handling,
   database access, backup/restore, and anything that runs shell commands. Also propose
   `scan.exclude` globs for vendored code, generated code, build output and large test fixtures.
4. Show me the proposed `.codesift.toml` changes as a diff and wait for my OK before writing them.
5. Check that `.gitignore` does not ignore `.codesift.toml` or `.codesift-baseline.json`
   (both are meant to be committed).
6. Ask me whether to install the pre-push hook (`sift hook install`). Do not install it
   without my yes.
```

## 1B. Scan and triage (read-only)

```text
Run a CodeSift security scan of this project and write the hand-off for the fix chat. Do not
change any project files. Never print secret values: refer to them by file:line and type only.

1. Run `sift scan` from the project root in the background or with a long timeout (up to
   20 minutes). DEEP REVIEW: if I wrote "deep" at the end of this message and `.codesift.toml`
   has `review.critical_paths`, run `sift scan --review --review-all` instead (about 3-6
   minutes per 400 lines, stops itself after 45 minutes). Do not stop it early. If it fails, run
   `sift doctor` and show me the fix.
2. Read only the `summary.md` whose path the scan prints. Call its folder RUN_DIR.
3. For every critical, high and LLM-"unsure" item, and every item in "AI logic review —
   unverified", open the flagged lines with enough context and give a verdict:
   - REAL: clearly exploitable or clearly wrong as written;
   - FALSE POSITIVE: clearly safe, with the reason (e.g. input is a constant, test-only code);
   - DEEP CHECK: depends on code in other files (callers, middleware, guards, concurrency) or
     you are not sure. Do not guess: the fix chat (a stronger model) will trace it.
   - NEEDS ME: needs information only I have (is this key live? is this endpoint public?).
   The LLM verdicts in the summary are hints, not answers.
4. Write RUN_DIR/triage.md. It is the ONLY input of the fix chat, so it must stand on its own:
   - header: project path, date, scan command used, RUN_DIR, git branch and commit scanned;
   - table: #, finding ID, severity, kind (secret / dependency / code / workflow / container /
     logic), file:line, verdict, one-line reason;
   - for each REAL and DEEP CHECK item: the risk in one sentence, the suspected fix, the files
     involved, effort (small/medium/large), and whether the fix may change behaviour;
   - for each NEEDS ME item: the exact question for me;
   - "Not covered": the summary's warnings (scanners skipped, dependencies without a lockfile,
     items not triaged, files the review did not reach);
   - "Fix order": secrets first, then critical, high, medium; quick wins first within a severity.
5. Show me the table, the NEEDS ME questions and the fix order, and the full path of triage.md.
```

## Chat 1 all-in-one

```text
Do the scan half of a CodeSift security round on this project. Do not change any code; the only
project file you may write is `.codesift.toml`, and only after my OK. Never print secret values.

1. Run `sift doctor`; if anything is red, stop and show me the fix.
2. If `.codesift.toml` is missing, run `sift init`, then propose `review.critical_paths`
   (auth, sessions, permissions, payments, webhooks, uploads, admin, tokens/crypto, database,
   backup/restore, shell commands) and `scan.exclude` (vendored, generated, build output) as a
   diff. STOP and wait for my OK before writing them.
3. Run `sift scan` (with `--review --review-all` if critical_paths are set and I said "deep")
   in the background with a long timeout. Do not stop it early.
4. Read only the printed summary.md (its folder is RUN_DIR). For each critical, high,
   LLM-"unsure" and "AI logic review" item, open the flagged lines and give a verdict: REAL,
   FALSE POSITIVE (with reason), DEEP CHECK (depends on other files or you are unsure; do not
   guess), or NEEDS ME (with the exact question).
5. Write RUN_DIR/triage.md as a stand-alone hand-off for a separate fix chat: header (project
   path, date, scan command, RUN_DIR, branch and commit), the table (#, ID, severity, kind,
   file:line, verdict, reason), suspected fix + files + effort + behaviour change for each REAL
   and DEEP CHECK item, NEEDS ME questions, "Not covered" list, fix order (secrets, critical,
   high, medium).
6. Show me the table, the questions and the full path of triage.md.
```

---

# Chat 2 — Fix (Opus)

## 2A. Fix and verify

```text
Fix the security issues from the latest CodeSift triage of this project. My answers to the
NEEDS ME questions and items to skip (if any): <write them here or "none">

Setup:
1. Run `sift report` to see the latest summary path. In its parent folder (this project's
   runs folder), use the NEWEST timestamp folder that contains a `triage.md`; call it TRIAGE_DIR.
   If there is none, stop and tell me to run the scan chat first. Read TRIAGE_DIR/triage.md.
2. Check `git status`. If there are uncommitted changes, stop and ask me what to do with them.
   If the current commit differs from the one in the triage header, tell me and check that the
   flagged lines are still there.
3. Create a branch `security/sift-<today's date>` from the current branch.

Re-check first:
4. For each DEEP CHECK item, trace the code across files (callers, routes, middleware, guards,
   transactions, concurrency) and decide REAL or FALSE POSITIVE. Also sanity-check each REAL
   item; if you disagree with the triage, say so and why. Record your verdicts in
   TRIAGE_DIR/fix-log.md under "Re-check". Do not fix anything you judged a false positive.

Fix, for each REAL item in the triage's fix order (skip what I said to skip):
5. Make the smallest fix that removes the risk at its root cause. Keep the project's style,
   framework and conventions; do not refactor unrelated code; no new dependencies and no major
   upgrades without asking me.
6. Rules per kind:
   - Secret in code or git history: move it to an environment variable or the project's existing
     secret mechanism and add a placeholder to `.env.example` (or the equivalent). Tell me which
     key I must ROTATE: removing it from the code is not enough. Do not rewrite git history; tell
     me if you think it should be.
   - Vulnerable dependency: upgrade to the lowest fixed version and update the lockfile with the
     project's own package manager.
   - Missing lockfile: generate one with the project's package manager.
   - CI workflow: pin actions to a commit SHA (keep the version as a comment), minimal
     `permissions:`, never pass untrusted input straight into `run:`.
   - Container: non-root user, pinned base image, no secrets in layers.
   - Logic issue (race, missing auth check, trusted input): fix at the root cause and add a test
     that fails without the fix.
7. Run the project's existing tests, linters and type checks for what you touched. If they fail
   because of your change, fix it; if they were already failing, tell me and do not hide it.
8. Commit the fix alone: `security: <short description> (CodeSift <finding ID>)`.
9. Append to TRIAGE_DIR/fix-log.md: finding ID, what changed, files, tests run, commit hash, and
   follow-up for me (e.g. "rotate the key").

Verify:
10. Run `sift scan --no-llm`. Every fixed item must be gone and nothing new may appear; fix
    it or tell me why not. (This creates a new run folder; the triage stays where it is.)
11. Show me: fixed, judged false positive (with reason), skipped, left for me (key rotation,
    decisions), and the branch name. Do not push, open a PR or merge without my OK.
```

## 2B. Close out

```text
Close out the CodeSift round for this project.

1. Find TRIAGE_DIR as before (newest run folder of this project with a `triage.md`) and read
   triage.md and fix-log.md.
2. List every FALSE POSITIVE (from the triage and from your re-check) with its finding ID and
   reason. Accept only the ones I approve, with
   `sift baseline accept <ID> --reason "<reason>"` (add `--expires YYYY-MM-DD` for anything
   temporary). Never edit `.codesift-baseline.json` by hand.
3. Run `sift baseline prune` to drop entries that no longer match.
4. Run `sift scan` once more and confirm nothing at high or above is left except items I
   chose to keep.
5. Commit `.codesift.toml` and `.codesift-baseline.json` changes, if any, on the security branch:
   `security: CodeSift config and accepted findings`.
6. Write a pull-request description (do not open it): what was fixed, what was accepted and why,
   what I still have to do (key rotation, deploy steps), and what was not covered. Save it as
   TRIAGE_DIR/pr.md and show it to me. Ask me before pushing or opening the PR.
```

## Chat 2 all-in-one

```text
Do the fix half of a CodeSift security round on this project. Work only inside this project
folder; never change other projects, global git settings or ~/.codesift/config. Never print
secret values. Never push, open a PR or merge without my OK.
My answers to the NEEDS ME questions and items to skip (if any): <write them here or "none">

PHASE A - load and re-check
1. Run `sift report`; in the parent of the printed run folder, use the NEWEST timestamp
   folder that has a `triage.md` (TRIAGE_DIR). None: stop and tell me to run the scan chat.
2. If `git status` is not clean, ask me first. If the commit differs from the triage header,
   check the flagged lines still exist. Create branch `security/sift-<date>`.
3. Trace every DEEP CHECK item across files and decide REAL or FALSE POSITIVE; sanity-check the
   REAL ones and say where you disagree. Write your verdicts to TRIAGE_DIR/fix-log.md.

PHASE B - fix
4. For each REAL item in fix order: smallest root-cause fix in the project's own style; secrets
   go to env vars (+ placeholder in .env.example) and I am told which key to rotate (no history
   rewrite without asking); dependencies to the lowest fixed version with the lockfile updated
   by the project's package manager; workflows pinned to SHAs with minimal permissions;
   containers non-root with pinned bases; logic fixes get a test that fails without the fix.
   No new dependencies or major upgrades without asking.
5. After each fix: run the project's tests/linters for what changed, commit it alone as
   `security: <description> (CodeSift <ID>)`, append to TRIAGE_DIR/fix-log.md.
6. Run `sift scan --no-llm`; every fixed item must be gone and nothing new may appear.
STOP: show me fixed / false positives (with reasons) / skipped / left for me, and the branch.

PHASE C - close out (after my answers)
7. Accept only the false positives I approve with `sift baseline accept <ID> --reason "…"`,
   then `sift baseline prune`. Run `sift scan` once more: nothing at high or above left
   except what I chose to keep. Commit `.codesift.toml` / `.codesift-baseline.json`.
8. Write the PR description (fixed, accepted, my follow-ups, not covered) to TRIAGE_DIR/pr.md
   and show it to me. Ask before pushing.
```

## 3. Fix with proof (0.2.0: `sift fix` / `sift validate`)

Use this instead of 2A when `sift setup` has a sandbox VM and fixer backends. The assistant never
applies a patch or runs project code locally; CodeSift's sandbox and gates decide.

```
Run `sift doctor`. If the LLM gateway, sandbox VM or fixers are not configured, stop and ask me to
run `sift setup` (never type or print credentials).

1. `sift scan` (background, long timeout); read only the printed summary.md.
2. `sift fix --dry-run`; show me the plan: findings, PoCs available or not, backends and what each
   sends where. Wait for my OK.
3. `sift fix` with the scope I approve (e.g. `--finding F001,F004`, `--budget-minutes 30`).
4. Read fix-report.md. For each finding report the outcome as CodeSift states it:
   fixed_verified / fixed_unproven (say "no PoC or tests") / rejected_* (one line why) /
   inconclusive (never call it safe) / budget_exhausted.
5. Show me each fixed_* patch diff. Apply one only when I say so (`git apply <patch>` on a branch),
   then run `sift validate` and report its outcome.
Never: apply/merge/push without my OK, `--no-verify`, edit the baseline, run PoCs locally.
```
