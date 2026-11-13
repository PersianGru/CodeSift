"""The bake-off corpus stays consistent: every label points at an existing file/line, the corpus
carries no hint comments, and file names do not reveal the answer."""

from __future__ import annotations

import json
import re
from pathlib import Path

BAKEOFF = Path(__file__).parent / "bakeoff"


def test_labels_point_at_existing_lines() -> None:
    labels = json.loads((BAKEOFF / "labels.json").read_text(encoding="utf-8"))
    assert labels["cases"]
    for key, value in labels["cases"].items():
        rel, line = key.rsplit(":", 1)
        lines = (BAKEOFF / "corpus" / rel).read_text(encoding="utf-8").splitlines()
        assert 1 <= int(line) <= len(lines), key
        assert value["label"] in ("real", "fp") and value["why"]


def test_corpus_has_no_hints() -> None:
    hint = re.compile(r"\b(REAL|FALSE POSITIVE|vulnerable|insecure|safe|fixture|CodeSift)\b", re.IGNORECASE)
    for path in (BAKEOFF / "corpus").rglob("*"):
        if path.is_file():
            assert not hint.search(path.read_text(encoding="utf-8")), path
            assert not re.search(r"(real|fp|safe|vuln)", path.name, re.IGNORECASE), path
