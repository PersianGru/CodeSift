"""Patch policy: mechanical, no LLM (RULES.md rules 12 and 14).

Input is the output of `git diff --cached` in the workspace. A patch is rejected when it touches
files outside the finding's file (+ allowed paths), is too large, touches tests / lockfiles / CI /
CodeSift or scanner config / hooks, adds or removes files, changes modes, renames, adds binary
content or symlinks, adds a suppression comment (after Unicode normalisation), deletes the
vulnerable region without replacement, only changes whitespace or comments, or cannot be parsed.
Every rejection has a stable machine code and a one-line message."""

from __future__ import annotations

import fnmatch
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from pathlib import PurePosixPath

DEFAULT_MAX_LINES = 80
HARD_MAX_LINES = 400
MAX_FILES = 3
DELETION_RATIO = 0.8
DELETION_MIN_LINES = 4

TEST_GLOBS = ("*_test.*", "test_*.*", "*.spec.*", "*.test.*", "*Test.java", "*_spec.rb", "conftest.py")
TEST_DIRS = ("test", "tests", "__tests__", "spec", "specs", "testdata", "fixtures")
LOCKFILES = (
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
    "composer.lock",
    "go.sum",
    "poetry.lock",
    "pipfile.lock",
    "uv.lock",
    "cargo.lock",
    "gemfile.lock",
    "requirements.lock",
    "tools.lock.json",
)
MANIFESTS = (
    "package.json",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "pipfile",
    "composer.json",
    "go.mod",
    "cargo.toml",
    "gemfile",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
)
CI_PATHS = (
    ".github/",
    ".gitlab-ci.yml",
    ".gitlab/",
    ".circleci/",
    "azure-pipelines.yml",
    "jenkinsfile",
    ".travis.yml",
    ".buildkite/",
    "bitbucket-pipelines.yml",
    ".drone.yml",
    ".woodpecker/",
)
SCANNER_CONFIG = (
    ".codesift.toml",
    ".codesift-baseline.json",
    ".gitleaks.toml",
    ".gitleaksignore",
    ".semgrepignore",
    ".semgrep.yml",
    ".bandit",
    "bandit.yml",
    ".trivyignore",
    "trivy.yaml",
    ".eslintrc",
    ".eslintrc.js",
    ".eslintrc.json",
    ".eslintrc.yml",
    "eslint.config.js",
    "eslint.config.mjs",
    ".eslintignore",
    "ruff.toml",
    ".ruff.toml",
    ".flake8",
    "tox.ini",
    ".pylintrc",
    "mypy.ini",
    ".mypy.ini",
    "tsconfig.json",
    ".pre-commit-config.yaml",
    "sonar-project.properties",
    ".snyk",
    "osv-scanner.toml",
    "zizmor.yml",
    ".zizmor.yml",
)
HOOK_PATHS = (".husky/", ".githooks/", ".git/", "lefthook.yml", ".lefthook.yml")
SUPPRESSIONS = (
    "nosec",
    "noqa",
    "nosemgrep",
    "nosonar",
    "pragma:nocover",
    "eslint-disable",
    "@ts-ignore",
    "@ts-nocheck",
    "@ts-expect-error",
    "gitleaks:allow",
    "codesift:ignore",
    "type:ignore",
    "pylint:disable",
    "rubocop:disable",
    "nolint",
    "phpcs:ignore",
    "phpcs:disable",
    "istanbulignore",
    "c8ignore",
    "checkov:skip",
    "trivy:ignore",
    "semgrep:ignore",
    "safety:ignore",
    "noinspection",
    "suppresswarnings",
    "nosemgrep:",
    "gosec",
    "skipcq",
)
_ZERO_WIDTH = re.compile("[\u200b-\u200f\u2028-\u202f\u2060-\u206f\ufeff\u00ad]")
_COMMENT_LINE = re.compile(r"^\s*(#|//|/\*|\*|\*/|--|<!--|-->)")


@dataclass
class Violation:
    code: str
    message: str


@dataclass
class FileDiff:
    old_path: str = ""
    new_path: str = ""
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    new_file: bool = False
    deleted: bool = False
    mode_change: bool = False
    rename: bool = False
    binary: bool = False
    symlink: bool = False

    @property
    def path(self) -> str:
        return self.new_path or self.old_path


@dataclass
class PolicyResult:
    ok: bool
    violations: list[Violation] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    added: int = 0
    removed: int = 0

    def messages(self) -> list[str]:
        return [f"{v.code}: {v.message}" for v in self.violations]


class DiffParseError(ValueError):
    pass


def _strip_prefix(path: str, prefix: str) -> str:
    path = path.strip()
    if path.startswith('"'):
        raise DiffParseError("quoted (unusual) path in diff")
    return path[len(prefix) :] if path.startswith(prefix) else path


def parse_diff(text: str) -> list[FileDiff]:
    files: list[FileDiff] = []
    cur: FileDiff | None = None
    in_hunk = False
    for line in text.splitlines():
        if line.startswith("diff --git "):
            m = re.match(r"^diff --git a/(\S+) b/(\S+)$", line)
            if not m:
                raise DiffParseError("cannot parse a diff header")
            cur = FileDiff(old_path=m.group(1), new_path=m.group(2))
            files.append(cur)
            in_hunk = False
            continue
        if cur is None:
            if line.strip():
                raise DiffParseError("content before the first diff header")
            continue
        if line.startswith("@@"):
            if not re.match(r"^@@ -\d+(,\d+)? \+\d+(,\d+)? @@", line):
                raise DiffParseError("cannot parse a hunk header")
            in_hunk = True
            continue
        if in_hunk:
            if line.startswith("+"):
                cur.added.append(line[1:])
            elif line.startswith("-"):
                cur.removed.append(line[1:])
            elif line.startswith(" ") or line == "" or line.startswith("\\"):
                pass
            else:
                in_hunk = False
            if in_hunk:
                continue
        if line.startswith("new file mode"):
            cur.new_file = True
            cur.symlink = cur.symlink or line.endswith("120000")
        elif line.startswith("deleted file mode"):
            cur.deleted = True
        elif line.startswith(("old mode", "new mode")):
            cur.mode_change = True
            cur.symlink = cur.symlink or line.endswith("120000")
        elif line.startswith(("rename from", "rename to", "copy from", "copy to", "similarity index")):
            cur.rename = True
        elif line.startswith(("Binary files", "GIT binary patch")):
            cur.binary = True
        elif line.startswith("index "):
            cur.symlink = cur.symlink or line.endswith(" 120000")
        elif line.startswith("--- "):
            if line != "--- /dev/null":
                cur.old_path = _strip_prefix(line[4:], "a/")
        elif line.startswith("+++ "):
            if line != "+++ /dev/null":
                cur.new_path = _strip_prefix(line[4:], "b/")
        elif line.startswith(("dissimilarity index", "literal ", "delta ")):
            cur.binary = True
    return files


def _norm(text: str) -> str:
    """Normalise for suppression matching: NFKC, zero-width removed, lower case, no whitespace."""
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH.sub("", text)
    return "".join(text.lower().split())


def _suppression_counts(lines: list[str]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for line in lines:
        n = _norm(line)
        for token in SUPPRESSIONS:
            if token in n:
                counts[token] += n.count(token)
    return counts


def _code_only(lines: list[str]) -> list[str]:
    return ["".join(line.split()) for line in lines if line.strip() and not _COMMENT_LINE.match(line)]


def _match_any(path: str, globs: tuple[str, ...]) -> bool:
    name = PurePosixPath(path).name
    return any(fnmatch.fnmatch(name, g) or fnmatch.fnmatch(name.lower(), g.lower()) for g in globs)


def _category(path: str, finding_path: str) -> tuple[str, str] | None:
    low = path.lower()
    p = PurePosixPath(low)
    if any(part in TEST_DIRS for part in p.parts[:-1]) or _match_any(path, TEST_GLOBS):
        return "touches_tests", f"{path} is a test file - tests are never weakened by a fix"
    if p.name in LOCKFILES:
        return "touches_lockfile", f"{path} is a lockfile"
    if p.name in MANIFESTS and path != finding_path:
        return "touches_manifest", f"{path} is a dependency manifest (only allowed when the finding is in it)"
    if any(low == c.rstrip("/") or low.startswith(c) for c in CI_PATHS):
        return "touches_ci", f"{path} is CI configuration"
    if p.name in SCANNER_CONFIG or p.name.startswith(".codesift"):
        return "touches_scanner_config", f"{path} is scanner/linter/CodeSift configuration or a baseline"
    if any(low == h.rstrip("/") or low.startswith(h) for h in HOOK_PATHS):
        return "touches_hooks", f"{path} is a git hook"
    return None


def check_patch(
    diff_text: str,
    *,
    finding_paths: list[str],
    allowed_paths: list[str] | None = None,
    max_lines: int = DEFAULT_MAX_LINES,
) -> PolicyResult:
    max_lines = max(1, min(max_lines, HARD_MAX_LINES))
    try:
        files = parse_diff(diff_text)
    except DiffParseError as exc:
        return PolicyResult(False, [Violation("unparseable_diff", f"the diff cannot be parsed ({exc})")])
    if not files:
        return PolicyResult(False, [Violation("empty_diff", "the patch changes nothing")])
    allowed = set(finding_paths) | set(allowed_paths or [])
    violations: list[Violation] = []
    added = sum(len(f.added) for f in files)
    removed = sum(len(f.removed) for f in files)
    result = PolicyResult(True, violations, [f.path for f in files], added, removed)

    if len(files) > MAX_FILES:
        violations.append(Violation("too_many_files", f"touches {len(files)} files (max {MAX_FILES})"))
    if added + removed > max_lines:
        violations.append(Violation("too_large", f"{added + removed} changed lines (max {max_lines})"))
    for f in files:
        if f.old_path != f.new_path or f.rename:
            violations.append(Violation("rename", f"renames or copies {f.old_path} -> {f.new_path}"))
        if f.new_file:
            violations.append(Violation("adds_file", f"adds a new file {f.path}"))
        if f.deleted:
            violations.append(Violation("deletes_file", f"deletes {f.path}"))
        if f.mode_change:
            violations.append(Violation("mode_change", f"changes the file mode of {f.path}"))
        if f.symlink:
            violations.append(Violation("symlink", f"{f.path} is or becomes a symlink"))
        if f.binary:
            violations.append(Violation("binary", f"binary content in {f.path}"))
        if f.path not in allowed:
            violations.append(
                Violation("outside_scope", f"{f.path} is not the finding's file or an allowed path")
            )
        cat = _category(f.path, finding_paths[0] if finding_paths else "")
        if cat is not None:
            violations.append(Violation(*cat))
        added_s = _suppression_counts(f.added)
        removed_s = _suppression_counts(f.removed)
        new = sorted(t for t, n in added_s.items() if n > removed_s.get(t, 0))
        if new:
            violations.append(
                Violation("adds_suppression", f"adds a suppression ({', '.join(new)}) in {f.path}")
            )
        r, a = len(f.removed), len(f.added)
        if r >= DELETION_MIN_LINES and (r - a) / r >= DELETION_RATIO:
            violations.append(
                Violation(
                    "mass_deletion", f"deletes {r - a} of {r} touched lines in {f.path} without replacement"
                )
            )
        if (f.added or f.removed) and _code_only(f.added) == _code_only(f.removed):
            violations.append(Violation("cosmetic_only", f"only whitespace or comments change in {f.path}"))
    result.ok = not violations
    return result
