"""Live sandbox VM test. Skipped unless CODESIFT_LIVE_VM=1 (it contacts the VM configured with
`sift setup --vm` in the user's normal config dir). Never runs in CI or by default."""

from __future__ import annotations

import os

import pytest

pytestmark = [
    pytest.mark.live_vm,
    pytest.mark.skipif(os.environ.get("CODESIFT_LIVE_VM") != "1", reason="set CODESIFT_LIVE_VM=1 to run"),
]


@pytest.fixture(autouse=True)
def _allow_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """The live test needs the real network (SSH to the VM): undo the conftest socket block, which
    shares this test's monkeypatch instance and ran first."""
    monkeypatch.undo()


def test_live_selftest_passes() -> None:
    from codesift.paths import get_paths
    from codesift.vm.commands import doctor_lines

    lines = doctor_lines(get_paths())
    assert lines[-1] == "self-test PASSED", "\n".join(lines)
