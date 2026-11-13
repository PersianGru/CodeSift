"""Model bake-off for LLM triage. Re-run after model or prompt changes.

    python scripts/bakeoff.py --out docs/bakeoff-results.json [--configs primary:think,primary:nothink,...]

1. Copies tests/bakeoff/corpus to a temp dir and scans it (no LLM, offline).
2. Keeps the medium+ findings labelled in tests/bakeoff/labels.json.
3. For each config (model x thinking on/off), one model at a time, sequentially, asks the exact
   triage prompt CodeSift uses and validates the answer the same way (incl. quoted_line).
4. Writes per-case results (no code, no secrets) and prints a summary table.

Bifrost credentials come from the usual CodeSift config / BIFROST_* environment variables.
"""

from __future__ import annotations

import argparse
import json
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from codesift.config import load_credentials, load_user_config, model_overrides  # noqa: E402
from codesift.llm import BifrostClient, ClientSettings, LLMError  # noqa: E402
from codesift.paths import Paths, get_paths  # noqa: E402
from codesift.redact import Redactor  # noqa: E402
from codesift.scan import ScanOptions, scan  # noqa: E402
from codesift.triage import InvalidAnswer, build_excerpt, build_messages, validate  # noqa: E402

CORPUS = ROOT / "tests" / "bakeoff" / "corpus"
LABELS = ROOT / "tests" / "bakeoff" / "labels.json"


def collect_cases(tmp: Path) -> tuple[Path, list[Any], dict[str, Any]]:
    project = tmp / "project"
    shutil.copytree(CORPUS, project)
    base = get_paths()
    paths = Paths(data=base.data, config=tmp / "cfg", runs=tmp / "runs", bin=base.bin, skill=tmp / "skill")
    outcome = scan(ScanOptions(path=str(project), no_llm=True, offline=True), paths)
    labels = json.loads(LABELS.read_text(encoding="utf-8"))
    cases = []
    for f in outcome.findings:
        key = f"{f.path}:{f.line}"
        if f.severity < 2:
            continue
        if key in labels["cases"]:
            cases.append((key, labels["cases"][key]["label"], f))
        elif not any(rule.endswith(x) for rule in f.rules for x in labels["excluded"]):
            print(f"warning: unlabelled medium+ finding {key} {f.rules[0]}", file=sys.stderr)
    missing = set(labels["cases"]) - {c[0] for c in cases}
    if missing:
        print(f"warning: labelled cases not reported by the scanners: {sorted(missing)}", file=sys.stderr)
    return project, cases, {"ecosystems": ["actions", "go", "js", "php", "python"]}


def run_config(
    client: BifrostClient, model: str, think: bool, project: Path, cases: list[Any], ecos: list[str]
) -> list[dict[str, Any]]:
    redactor = Redactor()
    rows = []
    for key, label, f in cases:
        excerpt = build_excerpt(project, f, redactor, 30, set())
        if excerpt is None:
            continue
        messages = build_messages(f, excerpt, ecos)
        row: dict[str, Any] = {"case": key, "label": label, "rule": f.rules[0]}
        attempts = []
        verdict = None
        for _attempt in range(2):
            start = time.monotonic()
            try:
                answer = client.chat(model, messages, max_tokens=2048, timeout=180, think=think)
            except LLMError as exc:
                attempts.append(
                    {"error": "llm", "detail": str(exc)[:120], "s": round(time.monotonic() - start, 1)}
                )
                break
            elapsed = round(time.monotonic() - start, 1)
            try:
                verdict = validate(answer.content, excerpt)
                attempts.append({"ok": True, "s": elapsed, "tokens": answer.usage.get("completion_tokens")})
                break
            except InvalidAnswer as exc:
                kind = (
                    "hallucinated_quote"
                    if "does not appear" in str(exc)
                    else ("invalid_json" if "JSON" in str(exc) else "schema")
                )
                attempts.append({"error": kind, "detail": str(exc)[:80], "s": elapsed})
                messages = [
                    *messages,
                    {"role": "assistant", "content": answer.content[:2000]},
                    {
                        "role": "user",
                        "content": f"That answer was rejected: {exc}. Reply again with ONLY the JSON "
                        "object; quoted_line must be copied exactly from the excerpt.",
                    },
                ]
        row["attempts"] = attempts
        row["verdict"] = verdict["verdict"] if verdict else "failed"
        row["severity_suggestion"] = verdict["severity_suggestion"] if verdict else ""
        row["reason"] = verdict["reason"][:200] if verdict else ""
        expected = "likely_real" if label == "real" else "likely_false_positive"
        row["correct"] = row["verdict"] == expected
        rows.append(row)
        print(f"  {key:<34} {label:<4} -> {row['verdict']:<22} {attempts[-1].get('s')}s", flush=True)
    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(rows)
    first = [r["attempts"][0] for r in rows if r["attempts"]]
    lat = [a["s"] for r in rows for a in r["attempts"] if "s" in a]
    real = [r for r in rows if r["label"] == "real"]
    fps = [r for r in rows if r["label"] == "fp"]
    p95 = sorted(lat)[max(0, round(0.95 * len(lat)) - 1)] if lat else 0
    return {
        "cases": n,
        "accuracy": round(sum(r["correct"] for r in rows) / n, 3),
        "real_recall": round(sum(r["correct"] for r in real) / max(1, len(real)), 3),
        "fp_detected": round(sum(r["correct"] for r in fps) / max(1, len(fps)), 3),
        "real_called_fp": sum(r["verdict"] == "likely_false_positive" for r in real),
        "unsure": sum(r["verdict"] == "unsure" for r in rows),
        "failed": sum(r["verdict"] == "failed" for r in rows),
        "invalid_json_first_try": sum(a.get("error") == "invalid_json" for a in first),
        "hallucinated_first_try": sum(a.get("error") == "hallucinated_quote" for a in first),
        "schema_first_try": sum(a.get("error") == "schema" for a in first),
        "median_s": round(statistics.median(lat), 1) if lat else 0,
        "p95_s": p95,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "docs" / "bakeoff-results.json"))
    ap.add_argument("--configs", default="primary:think,primary:nothink,fallback:think,fallback:nothink")
    args = ap.parse_args()

    paths = get_paths()
    creds = load_credentials(paths)
    if creds is None:
        print("no Bifrost credentials (config or BIFROST_* env vars)", file=sys.stderr)
        return 2
    llm = load_user_config(paths).llm
    for k, v in model_overrides(paths).items():
        setattr(llm, k, v)
    models = {"primary": llm.model, "fallback": llm.fallback_model}
    client = BifrostClient(creds, ClientSettings(timeout_s=180, retries=1, backoff_s=(10,)))

    with tempfile.TemporaryDirectory(prefix="codesift-bakeoff-") as tmp:
        project, cases, meta = collect_cases(Path(tmp))
        print(
            f"{len(cases)} labelled cases "
            f"({sum(c[1] == 'real' for c in cases)} real, {sum(c[1] == 'fp' for c in cases)} fp)"
        )
        results: dict[str, Any] = {"date": time.strftime("%Y-%m-%d"), "models": models, "configs": {}}
        current_model = None
        for spec in args.configs.split(","):
            which, mode = spec.split(":")
            model = models[which]
            think = mode == "think"
            if model != current_model:
                start = time.monotonic()
                try:
                    client.chat(
                        model,
                        [{"role": "user", "content": 'Reply with JSON only: {"ok": true}'}],
                        max_tokens=256,
                        timeout=240,
                        think=False,
                    )
                except LLMError as exc:
                    print(f"warm-up of {model} failed: {exc}", file=sys.stderr)
                    results["configs"][spec] = {"error": str(exc)[:200]}
                    continue
                results.setdefault("warmup_s", {})[model] = round(time.monotonic() - start, 1)
                current_model = model
            print(f"== {spec} ({model})", flush=True)
            rows = run_config(client, model, think, project, cases, meta["ecosystems"])
            results["configs"][spec] = {
                "model": model,
                "think": think,
                "summary": summarize(rows),
                "rows": rows,
            }
            print("   ", json.dumps(results["configs"][spec]["summary"]), flush=True)
    Path(args.out).write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
