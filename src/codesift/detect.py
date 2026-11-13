"""Project detection: which files exist, which ecosystems apply, which scanners to run."""

from __future__ import annotations

import fnmatch
import json
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from codesift.gitutil import list_files

# Directory names never scanned by any tool.
DEFAULT_EXCLUDE_DIRS = (
    ".git",
    "node_modules",
    "bower_components",
    "vendor",
    ".venv",
    "venv",
    ".tox",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "site-packages",
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".svelte-kit",
    "coverage",
    "htmlcov",
    "target",
    ".terraform",
    ".gradle",
    ".idea",
    ".vscode",
)
# Excluded only for code-pattern scanners (opengrep, ruff, bandit): tests are full of deliberate
# "bad" code. Secret, dependency and config scanners still see them.
TEST_DIRS = ("test", "tests", "__tests__", "spec", "testdata", "fixtures")
TEST_FILE_GLOBS = ("*_test.go", "*.test.js", "*.test.ts", "*.test.tsx", "*.spec.js", "*.spec.ts", "test_*.py")
MAX_WALK_FILES = 200_000

PY_EXT = (".py", ".pyi")
JS_EXT = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte")
PHP_EXT = (".php", ".phtml")
GO_EXT = (".go",)
SHELL_EXT = (".sh", ".bash")
PY_MANIFESTS = (
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "pipfile",
    "pipfile.lock",
    "poetry.lock",
    "uv.lock",
)
JS_MANIFESTS = (
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "npm-shrinkwrap.json",
    "bun.lock",
)
LOCKFILES = (
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "composer.lock",
    "go.mod",
    "go.sum",
    "poetry.lock",
    "pipfile.lock",
    "uv.lock",
    "pdm.lock",
    "cargo.lock",
    "gemfile.lock",
    "pom.xml",
    "gradle.lockfile",
    "packages.lock.json",
    "pubspec.lock",
    "mix.lock",
    "conan.lock",
)


# manifest -> lockfiles that pin it (in the same directory). Without one, osv-scanner (which needs
# exact versions and does not resolve ranges, ADR-0006) cannot check those dependencies.
LOCK_FOR_MANIFEST = {
    "pyproject.toml": ("poetry.lock", "uv.lock", "pdm.lock", "pipfile.lock", "requirements.txt"),
    "package.json": ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"),
    "composer.json": ("composer.lock",),
}


def unlocked_manifests(files: list[str], root: Path | None = None) -> list[str]:
    """Manifests whose dependencies are not pinned by a lockfile next to them. With `root`, a
    manifest that declares no dependencies at all (e.g. a stdlib-only Python package) is skipped."""
    present = {f.lower() for f in files}
    out = []
    for rel in files:
        p = PurePosixPath(rel)
        locks = LOCK_FOR_MANIFEST.get(p.name.lower())
        if not locks:
            continue
        folder = p.parent.as_posix()
        prefix = "" if folder == "." else folder.lower() + "/"
        if any(prefix + lock in present for lock in locks):
            continue
        if root is not None and not _declares_dependencies(root / rel):
            continue
        out.append(rel)
    return out


def _declares_dependencies(path: Path) -> bool:
    """False only when the manifest parses and lists no runtime/dev dependencies."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        if path.name.lower() == "pyproject.toml":
            data = tomllib.loads(text)
            project = data.get("project") or {}
            poetry = (data.get("tool") or {}).get("poetry") or {}
            poetry_deps = {k for k in (poetry.get("dependencies") or {}) if k.lower() != "python"}
            groups = poetry.get("group") or {}
            return bool(
                project.get("dependencies")
                or project.get("optional-dependencies")
                or data.get("dependency-groups")
                or poetry_deps
                or any((g or {}).get("dependencies") for g in groups.values())
            )
        data = json.loads(text)
        keys = ("dependencies", "devDependencies", "optionalDependencies", "require", "require-dev")
        return any({k: v for k, v in (data.get(key) or {}).items() if k != "php"} for key in keys)
    except (OSError, ValueError, AttributeError, TypeError):
        return True  # unreadable or unusual: keep the warning


def is_requirements(name: str) -> bool:
    n = name.lower()
    return n.endswith(".txt") and (n.startswith("requirements") or n.endswith("requirements.txt"))


def is_dependency_file(rel: str) -> bool:
    name = PurePosixPath(rel).name.lower()
    return name in LOCKFILES or is_requirements(name) or name in ("composer.json", "pyproject.toml")


def is_dockerfile(name: str) -> bool:
    n = name.lower()
    return (
        n == "dockerfile" or n.startswith("dockerfile.") or n.endswith(".dockerfile") or n == "containerfile"
    )


def is_compose(name: str) -> bool:
    n = name.lower()
    return (n.startswith(("docker-compose", "compose"))) and n.endswith((".yml", ".yaml"))


def is_workflow(rel: str) -> bool:
    p = PurePosixPath(rel)
    return (
        len(p.parts) >= 3
        and p.parts[-3] == ".github"
        and p.parts[-2] == "workflows"
        and p.suffix
        in (
            ".yml",
            ".yaml",
        )
    )


def is_iac(rel: str) -> bool:
    p = PurePosixPath(rel)
    name = p.name.lower()
    if is_dockerfile(name) or p.suffix in (".tf", ".tfvars", ".bicep") or name.endswith(".tf.json"):
        return True
    if p.suffix in (".yml", ".yaml") and ("k8s" in p.parts or "kubernetes" in p.parts or "helm" in p.parts):
        return True
    return name == "chart.yaml"


@dataclass
class Detection:
    root: Path
    files: list[str]  # project-relative, forward slashes, after excludes
    ecosystems: set[str] = field(
        default_factory=set
    )  # python, js, php, go, docker, iac, compose, actions, shell, yaml
    from_git: bool = False

    def has(self, eco: str) -> bool:
        return eco in self.ecosystems

    def files_with(self, exts: tuple[str, ...]) -> list[str]:
        return [f for f in self.files if f.lower().endswith(exts)]


def path_excluded(rel: str, globs: list[str], exclude_tests: bool = False) -> bool:
    parts = PurePosixPath(rel).parts
    if any(p in DEFAULT_EXCLUDE_DIRS for p in parts[:-1]):
        return True
    if exclude_tests:
        if any(p.lower() in TEST_DIRS for p in parts[:-1]):
            return True
        if any(fnmatch.fnmatch(parts[-1], g) for g in TEST_FILE_GLOBS):
            return True
    for g in globs:
        if fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(rel, g.rstrip("/") + "/*"):
            return True
        if "/" not in g and any(fnmatch.fnmatch(p, g) for p in parts):
            return True
    return False


def _walk(root: Path) -> list[str]:
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames if d not in DEFAULT_EXCLUDE_DIRS and not os.path.islink(Path(dirpath, d))
        ]
        base = Path(dirpath).relative_to(root)
        for name in filenames:
            out.append((base / name).as_posix() if str(base) != "." else name)
            if len(out) >= MAX_WALK_FILES:
                return sorted(out)
    return sorted(out)


def detect(root: Path, exclude_globs: list[str]) -> Detection:
    listed = list_files(root)
    files = listed if listed is not None else _walk(root)
    files = [f for f in files if not path_excluded(f, exclude_globs) and (root / f).is_file()]
    det = Detection(root=root, files=files, from_git=listed is not None)
    for rel in files:
        p = PurePosixPath(rel)
        name = p.name.lower()
        low = rel.lower()
        if low.endswith(PY_EXT) or name in PY_MANIFESTS or is_requirements(name):
            det.ecosystems.add("python")
        if low.endswith(JS_EXT) or name in JS_MANIFESTS:
            det.ecosystems.add("js")
        if low.endswith(PHP_EXT) or name in ("composer.json", "composer.lock"):
            det.ecosystems.add("php")
        if low.endswith(GO_EXT) or name in ("go.mod", "go.sum"):
            det.ecosystems.add("go")
        if low.endswith(SHELL_EXT):
            det.ecosystems.add("shell")
        if is_dockerfile(name):
            det.ecosystems.add("docker")
        if is_compose(name):
            det.ecosystems.add("compose")
        if is_iac(rel):
            det.ecosystems.add("iac")
        if is_workflow(rel):
            det.ecosystems.add("actions")
        if p.suffix in (".yml", ".yaml"):
            det.ecosystems.add("yaml")
        if is_dependency_file(rel):
            det.ecosystems.add("deps")
    return det
