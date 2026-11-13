"""Release discovery: latest stable release older than the cooldown, checksums, advisories."""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

from codesift.lockfile import PlatformAsset, ToolLock
from codesift.net import NetworkError, fetch, fetch_json
from codesift.tools import TOOL_SPECS, ToolSpec, parse_checksums

API = "https://api.github.com"


class ReleaseError(Exception):
    pass


# ---------------------------------------------------------------- versions


def version_key(version: str) -> tuple[tuple[int, ...], int]:
    """Comparable key: numeric parts, then 1 for final releases / 0 for pre-releases."""
    v = version.strip().lstrip("vV=")
    m = re.match(r"^(\d+(?:\.\d+)*)(.*)$", v)
    if not m:
        return ((0,), 0)
    nums = tuple(int(x) for x in m.group(1).split("."))
    nums = nums + (0,) * (4 - len(nums)) if len(nums) < 4 else nums
    return (nums, 0 if m.group(2) else 1)


def in_range(version: str, spec: str) -> bool:
    """Evaluate a GitHub advisory range like '>= 1.5.0, < 1.30.2' or '= 0.69.4'."""
    key = version_key(version)
    comparators = re.findall(r"(<=|>=|==|<|>|=)\s*v?([0-9][^\s,]*)", spec or "")
    if not comparators:
        return False
    for op, ver in comparators:
        other = version_key(ver)
        ok = {
            "<": key < other,
            "<=": key <= other,
            ">": key > other,
            ">=": key >= other,
            "=": key == other,
            "==": key == other,
        }[op]
        if not ok:
            return False
    return True


def _date(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


# ---------------------------------------------------------------- GitHub releases


@dataclass
class Release:
    repo: str
    tag: str
    published: datetime
    assets: dict[str, dict[str, Any]]  # name -> {url, size, digest}
    html_url: str

    @property
    def version(self) -> str:
        return self.tag.lstrip("v")


def list_releases(repo: str, per_page: int = 20) -> list[Release]:
    data = fetch_json(f"{API}/repos/{repo}/releases?per_page={per_page}")
    if not isinstance(data, list):
        raise ReleaseError(f"{repo}: unexpected releases response")
    out = []
    for r in data:
        if r.get("draft") or r.get("prerelease") or not r.get("published_at"):
            continue
        assets = {
            a["name"]: {
                "url": a["browser_download_url"],
                "size": int(a.get("size", 0)),
                "digest": a.get("digest") or "",
            }
            for a in r.get("assets", [])
        }
        out.append(Release(repo, r["tag_name"], _date(r["published_at"]), assets, r.get("html_url", "")))
    return out


def pick_release(
    releases: list[Release], cooldown_days: int, now: datetime | None = None
) -> tuple[Release | None, Release | None]:
    """Return (eligible, newest). `eligible` is the newest stable release older than the cooldown."""
    now = now or datetime.now(UTC)
    ordered = sorted(releases, key=lambda r: version_key(r.tag), reverse=True)
    newest = ordered[0] if ordered else None
    cutoff = now - timedelta(days=cooldown_days)
    eligible = next((r for r in ordered if r.published <= cutoff), None)
    return eligible, newest


def build_tool_lock(spec: ToolSpec, release: Release) -> ToolLock:
    """Lock entry with sha256 from the official checksums file, cross-checked against GitHub's
    server-side asset digest when present. Any disagreement aborts."""
    version = release.version
    official: dict[str, str] = {}
    source = "github-asset-digest"
    if spec.checksums:
        source = spec.checksums.format(version=version)
        meta = release.assets.get(source)
        if meta is None:
            raise ReleaseError(f"{spec.name} {release.tag}: checksums file {source} missing from release")
        official = parse_checksums(fetch(meta["url"], max_bytes=200_000).decode("utf-8", "replace"))
    entry = ToolLock(
        repo=spec.repo,
        tag=release.tag,
        version=version,
        published=release.published.strftime("%Y-%m-%d"),
        checksum_source=source,
    )
    for plat, template in spec.assets.items():
        name = template.format(version=version)
        meta = release.assets.get(name)
        if meta is None:
            raise ReleaseError(f"{spec.name} {release.tag}: asset {name} missing")
        digest = str(meta["digest"])
        gh_sha = digest.split(":", 1)[1].lower() if digest.startswith("sha256:") else ""
        if spec.checksums:
            sha = official.get(name, "")
            if not sha:
                raise ReleaseError(f"{spec.name} {release.tag}: {name} not listed in {source}")
            if gh_sha and gh_sha != sha:
                raise ReleaseError(
                    f"{spec.name} {release.tag}: {name} checksum file and GitHub digest disagree"
                )
        else:
            if not gh_sha:
                raise ReleaseError(f"{spec.name} {release.tag}: no GitHub digest for {name}")
            sha = gh_sha
        entry.platforms[plat] = PlatformAsset(asset=name, url=meta["url"], sha256=sha, size=int(meta["size"]))
    return entry


# ---------------------------------------------------------------- advisories


@dataclass
class Advisory:
    ghsa: str
    severity: str
    summary: str
    range: str


def repo_advisories(repo: str) -> list[dict[str, Any]]:
    data = fetch_json(f"{API}/repos/{repo}/security-advisories?state=published&per_page=50")
    return data if isinstance(data, list) else []


def global_advisories(ecosystem: str, package: str, version: str) -> list[dict[str, Any]]:
    affects = quote(f"{package}@{version}", safe="")
    data = fetch_json(f"{API}/advisories?ecosystem={ecosystem}&affects={affects}&per_page=50")
    return data if isinstance(data, list) else []


def affecting(
    advisories: list[dict[str, Any]], version: str, package_hint: str | None = None
) -> list[Advisory]:
    found: dict[str, Advisory] = {}
    for adv in advisories:
        if adv.get("withdrawn_at"):
            continue
        for vuln in adv.get("vulnerabilities") or []:
            pkg = ((vuln.get("package") or {}).get("name") or "").lower()
            if package_hint and pkg and package_hint.lower() not in pkg and pkg not in package_hint.lower():
                continue
            rng = str(vuln.get("vulnerable_version_range") or "")
            if in_range(version, rng):
                ghsa = str(adv.get("ghsa_id"))
                found[ghsa] = Advisory(ghsa, str(adv.get("severity")), str(adv.get("summary", ""))[:100], rng)
    return list(found.values())


def tool_advisories(name: str, version: str) -> list[Advisory]:
    spec = TOOL_SPECS[name]
    result = affecting(repo_advisories(spec.repo), version, package_hint=spec.repo.split("/")[1])
    if spec.go_module:
        with contextlib.suppress(NetworkError):
            result += affecting(global_advisories("go", spec.go_module, version), version)
    seen: dict[str, Advisory] = {a.ghsa: a for a in result}
    return list(seen.values())


# ---------------------------------------------------------------- rules repository


def latest_commit(repo: str) -> tuple[str, datetime, bool]:
    info = fetch_json(f"{API}/repos/{repo}")
    if not isinstance(info, dict):
        raise ReleaseError(f"{repo}: unexpected response")
    branch = info.get("default_branch", "main")
    commit = fetch_json(f"{API}/repos/{repo}/commits/{quote(branch)}")
    if not isinstance(commit, dict):
        raise ReleaseError(f"{repo}: unexpected commit response")
    return commit["sha"], _date(commit["commit"]["committer"]["date"]), bool(info.get("archived"))
