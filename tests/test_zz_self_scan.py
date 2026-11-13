"""sift scans itself (runs last: file name sorts last). Offline so the test is deterministic;
the online dependency check is part of the release checklist."""

from __future__ import annotations

from pathlib import Path

import pytest

from codesift.paths import Paths, get_paths
from codesift.scan import ScanOptions, scan
from test_integration import _installed

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(not _installed(), reason="CodeSift tools not installed")
def test_codesift_scans_itself_clean(tmp_path: Path) -> None:
    base = get_paths()
    paths = Paths(data=base.data, config=tmp_path, runs=tmp_path / "runs", bin=base.bin, skill=tmp_path)
    outcome = scan(ScanOptions(path=str(ROOT), no_llm=True, offline=True), paths)
    errors = {r.name: r.reason for r in outcome.results if r.status == "error"}
    assert errors == {}
    above = [f"{f.id} {f.severity.label} {f.location} {f.rules}" for f in outcome.findings if f.severity >= 2]
    assert above == [], "CodeSift must scan itself clean at medium (fix it or baseline with a reason)"
    assert outcome.exit_code == 0
