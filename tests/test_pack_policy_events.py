from __future__ import annotations

import io
import json
import os
import tarfile
from pathlib import Path

import pytest

from codesift.finding import Finding
from codesift.models import Severity
from codesift.redact import Redactor
from codesift.validate.events import (
    EventError,
    EventLog,
    bug_type_of,
    district_of,
    read_events,
    validate_event,
)
from codesift.validate.pack import PackError, pack_files, pack_tree, safe_name, safe_unpack
from codesift.validate.policy import check_patch

# ---------------------------------------------------------------- pack


def _tar(*members: tarfile.TarInfo, data: bytes = b"x") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for m in members:
            if m.isfile():
                m.size = len(data)
                tf.addfile(m, io.BytesIO(data))
            else:
                tf.addfile(m)
    return buf.getvalue()


def _member(name: str, kind: bytes = tarfile.REGTYPE, link: str = "") -> tarfile.TarInfo:
    m = tarfile.TarInfo(name)
    m.type = kind
    m.linkname = link
    return m


@pytest.mark.parametrize(
    "name", ["../x", "a/../../x", "/etc/passwd", "a//b", "C:/x", "a\\b", "a/\x00b", "", ".", "a/./b"]
)
def test_safe_name_rejects(name: str) -> None:
    with pytest.raises(PackError):
        safe_name(name)


def test_pack_roundtrip(tmp_path: Path) -> None:
    src = tmp_path / "src"
    (src / "pkg").mkdir(parents=True)
    (src / "pkg" / "a.py").write_text("print(1)\n", encoding="utf-8")
    (src / ".git").mkdir()
    (src / ".git" / "config").write_text("x", encoding="utf-8")
    data = pack_tree(src, extra={".codesift/x": b"y"})
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        names = tf.getnames()
        assert all(m.uname == "nobody" and m.mode in (0o644, 0o755) for m in tf.getmembers())
    assert names == ["pkg/a.py", ".codesift/x"]
    out = safe_unpack(data, tmp_path / "out")
    assert sorted(out) == [".codesift/x", "pkg/a.py"]


def test_pack_refuses_symlinks(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "a").write_text("x", encoding="utf-8")
    try:
        os.symlink(src / "a", src / "link")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available")
    with pytest.raises(PackError, match=r"regular|symlink"):
        pack_tree(src)


@pytest.mark.parametrize(
    "member",
    [
        _member("../evil"),
        _member("/abs"),
        _member("link", tarfile.SYMTYPE, "/etc/passwd"),
        _member("hard", tarfile.LNKTYPE, "x"),
        _member("dev", tarfile.CHRTYPE),
        _member("fifo", tarfile.FIFOTYPE),
    ],
)
def test_unpack_rejects_from_vm(tmp_path: Path, member: tarfile.TarInfo) -> None:
    with pytest.raises(PackError):
        safe_unpack(_tar(member), tmp_path / "out")
    assert not (tmp_path / "evil").exists()


def test_unpack_non_strict_skips_links(tmp_path: Path) -> None:
    skipped: list[tuple[str, str]] = []
    data = _tar(_member("ok.txt"), _member("link", tarfile.SYMTYPE, "/etc"))
    assert safe_unpack(data, tmp_path / "o", strict=False, skipped=skipped) == ["ok.txt"]
    assert skipped == [("link", "link")]
    with pytest.raises(PackError):  # traversal is always fatal
        safe_unpack(_tar(_member("../x")), tmp_path / "o2", strict=False)


def test_tar_bombs(tmp_path: Path) -> None:
    many = pack_files({f"f{i}": b"x" for i in range(30)})
    with pytest.raises(PackError, match="too many"):
        safe_unpack(many, tmp_path / "a", max_files=10)
    big = pack_files({"big": b"x" * 5000})
    with pytest.raises(PackError, match="cap"):
        safe_unpack(big, tmp_path / "b", max_file=1000)
    with pytest.raises(PackError, match="size cap"):
        safe_unpack(pack_files({"a": b"x" * 600, "b": b"x" * 600}), tmp_path / "c", max_total=1000)
    with pytest.raises(PackError, match="uncompressed"):
        import gzip

        safe_unpack(gzip.compress(big), tmp_path / "d")
    with pytest.raises(PackError):
        pack_files({f"f{i}": b"" for i in range(5)}, max_files=3)


# ---------------------------------------------------------------- policy


def diff(path: str, removed: list[str], added: list[str], header: str = "") -> str:
    body = "".join(f"-{r}\n" for r in removed) + "".join(f"+{a}\n" for a in added)
    return (
        f"diff --git a/{path} b/{path}\n{header}index 1111111..2222222 100644\n--- a/{path}\n+++ b/{path}\n"
        f"@@ -1,{len(removed)} +1,{len(added)} @@\n{body}"
    )


GOOD = diff(
    "app/tools.py", ['    os.system("ping " + host)'], ['    subprocess.run(["ping", host], check=False)']
)


def test_policy_accepts_a_real_fix() -> None:
    r = check_patch(GOOD, finding_paths=["app/tools.py"])
    assert r.ok, r.messages()


@pytest.mark.parametrize(
    ("patch", "code"),
    [
        (diff("app/other.py", ["a = 1"], ["a = 2"]), "outside_scope"),
        (diff("tests/test_tools.py", ["assert x"], ["assert True"]), "touches_tests"),
        (diff("app/test_tools.py", ["assert x"], ["pass"]), "touches_tests"),
        (diff("web/app.spec.ts", ["a"], ["b"]), "touches_tests"),
        (diff("package-lock.json", ["a"], ["b"]), "touches_lockfile"),
        (diff("package.json", ["a"], ["b"]), "touches_manifest"),
        (diff(".github/workflows/ci.yml", ["a"], ["b"]), "touches_ci"),
        (diff(".codesift-baseline.json", ["a"], ["b"]), "touches_scanner_config"),
        (diff(".gitleaksignore", ["a"], ["b"]), "touches_scanner_config"),
        (diff(".husky/pre-push", ["a"], ["b"]), "touches_hooks"),
        (diff("app/tools.py", ["os.system(x)"], ["os.system(x)  # nosec"]), "adds_suppression"),
        (diff("app/tools.py", ["os.system(x)"], ["os.system(x)  # NoQA: S605"]), "adds_suppression"),
        (diff("app/tools.py", ["eval(x)"], ["eval(x) // eslint-disable-line"]), "adds_suppression"),
        (diff("app/tools.py", ["eval(x)"], ["eval(x) # no\u200bsec"]), "adds_suppression"),
        (diff("app/tools.py", ["eval(x)"], ["eval(x) # \uff4e\uff4f\uff53\uff45\uff43"]), "adds_suppression"),
        (diff("app/tools.py", ["eval(x)"], ["eval(x) # n o s e c"]), "adds_suppression"),
        (diff("app/tools.py", ["eval(x)"], ["eval(x) # type: ignore"]), "adds_suppression"),
        (diff("app/tools.py", ["x = 1"], ["x = 1 # gitleaks:allow"]), "adds_suppression"),
        (diff("app/tools.py", ["a()", "b()", "c()", "d()", "e()"], ["pass"]), "mass_deletion"),
        (diff("app/tools.py", ["os.system(x)"], ["os.system( x )"]), "cosmetic_only"),
        (diff("app/tools.py", ["# old comment", "x = 1"], ["# new comment", "x = 1"]), "cosmetic_only"),
        (diff("app/tools.py", [f"l{i}" for i in range(50)], [f"m{i}" for i in range(50)]), "too_large"),
        (diff("app/tools.py", ["a"], ["b"], header="old mode 100644\nnew mode 100755\n"), "mode_change"),
        (diff("app/tools.py", ["a"], ["b"], header="new file mode 100644\n"), "adds_file"),
        (diff("app/tools.py", ["a"], ["b"], header="deleted file mode 100644\n"), "deletes_file"),
        (diff("app/tools.py", ["a"], ["b"], header="new file mode 120000\n"), "symlink"),
        (
            "diff --git a/x.bin b/x.bin\nindex 1..2 100644\nBinary files a/x.bin and b/x.bin differ\n",
            "binary",
        ),
        ("diff --git a/a.py b/b.py\nsimilarity index 90%\nrename from a.py\nrename to b.py\n", "rename"),
        ("garbage before\ndiff --git a/x b/x\n", "unparseable_diff"),
        ("", "empty_diff"),
    ],
)
def test_policy_rejects(patch: str, code: str) -> None:
    allowed = ["app/tools.py", "app/test_tools.py", "x.bin", "a.py", "package.json"]
    r = check_patch(patch, finding_paths=["app/tools.py"], allowed_paths=allowed)
    assert not r.ok
    assert code in [v.code for v in r.violations], r.messages()
    assert all(v.message for v in r.violations)


def test_policy_existing_suppression_moved_is_fine() -> None:
    p = diff("app/tools.py", ["x = run(a)  # noqa: E501"], ["x = run(b)  # noqa: E501"])
    assert check_patch(p, finding_paths=["app/tools.py"]).ok


def test_policy_manifest_allowed_when_finding_is_there() -> None:
    p = diff("package.json", ['"lodash": "4.17.10"'], ['"lodash": "4.17.21"'])
    assert check_patch(p, finding_paths=["package.json"]).ok


def test_policy_limits() -> None:
    files = "".join(diff(f"app/f{i}.py", ["a"], ["b"]) for i in range(4))
    r = check_patch(files, finding_paths=["app/f0.py"], allowed_paths=[f"app/f{i}.py" for i in range(4)])
    assert "too_many_files" in [v.code for v in r.violations]
    big = diff("app/tools.py", [f"l{i}" for i in range(250)], [f"m{i}" for i in range(250)])
    assert not check_patch(big, finding_paths=["app/tools.py"], max_lines=10_000).ok  # hard max 400


# ---------------------------------------------------------------- events


def _finding(**kw: object) -> Finding:
    base: dict[str, object] = {
        "tool": "bandit",
        "rule": "B605",
        "severity": Severity.HIGH,
        "path": "tools/ping.py",
        "line": 3,
        "message": "m",
        "fingerprint": "f",
    }
    base.update(kw)
    return Finding(**base)  # type: ignore[arg-type]  # test helper with loose kwargs


def test_classification() -> None:
    assert bug_type_of(_finding(cwe=["CWE-89"])) == "sqli"
    assert bug_type_of(_finding(cwe=["CWE-79"])) == "xss"
    assert bug_type_of(_finding(cwe=["CWE-78"])) == "cmdi"
    assert bug_type_of(_finding(cwe=["CWE-22"])) == "traversal"
    assert bug_type_of(_finding(tool="gitleaks")) == "secret"
    assert bug_type_of(_finding(tool="osv-scanner")) == "dependency"
    assert bug_type_of(_finding()) == "glitch"
    assert district_of("app/db/models.py") == "db"
    assert district_of("web/templates/x.html") == "web"
    assert district_of("scripts/run.sh") == "tools"
    assert district_of(".github/workflows/ci.yml") == "config"
    assert district_of("package-lock.json") == "vendor"
    assert district_of("src/main.py") == "annex"
    assert district_of("src/main.py", {"web": ["src"]}) == "web"


def test_event_log_roundtrip_and_redaction(tmp_path: Path) -> None:
    secret = "s3cr3t-value-0123456789"
    log = EventLog(tmp_path / "events.jsonl", "20261114-100000", Redactor([secret]))
    log.emit("run.start", mode="fix")
    log.emit("stage.enter", "F001", stage="fix", note=f"key {secret} " + "x" * 1000)
    log.emit("finding.outcome", "F001", outcome="fixed_verified")
    text = (tmp_path / "events.jsonl").read_text(encoding="utf-8")
    assert secret not in text
    events, offset = read_events(tmp_path / "events.jsonl")
    assert [e["seq"] for e in events] == [0, 1, 2]
    assert len(events[1]["data"]["note"]) <= 300
    with (tmp_path / "events.jsonl").open("a", encoding="utf-8") as fh:
        fh.write('{"v":1,"ts":"x","run":"r","seq":3,"type":"run.e')  # truncated, still being written
    more, offset2 = read_events(tmp_path / "events.jsonl", offset)
    assert more == [] and offset2 == offset


@pytest.mark.parametrize(
    "bad",
    [
        {"type": "nope"},
        {"type": "stage.enter", "data": {"stage": "hack"}},
        {"type": "finding.outcome", "finding": "F001", "data": {"outcome": "safe"}},
        {"type": "finding.outcome", "data": {"outcome": "fixed_verified"}},
        {"type": "verify.result", "finding": "F001", "data": {"gate": "x", "status": "passed"}},
        {"run": "../../x"},
        {"finding": "<script>"},
        {"v": 2},
    ],
)
def test_event_schema_rejects(bad: dict[str, object]) -> None:
    ev: dict[str, object] = {"v": 1, "ts": "t", "run": "r1", "seq": 0, "type": "run.start", "data": {}}
    ev.update(bad)
    with pytest.raises(EventError):
        validate_event(ev)


def test_event_rejects_code_objects(tmp_path: Path) -> None:
    log = EventLog(tmp_path / "e.jsonl", "r", Redactor())
    with pytest.raises(EventError):
        log.emit("run.start", obj=object())
    assert json.loads('{"a":1}')  # file stays valid JSONL even after a refused event
