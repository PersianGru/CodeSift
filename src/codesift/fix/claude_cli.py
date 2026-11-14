"""Fixer backend: the Claude CLI (`claude -p`) - opt-in with consent.

Argument list only (no shell), the prompt on stdin, `cwd` = the workspace (secret files already
removed), tools limited to read/search/edit, edits accepted without prompts, a turn cap, a timeout
and a minimal environment (only what the CLI needs to find its own login). No secret is ever on its
command line. The resulting diff goes through the same patch policy as every other backend."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field

from codesift.fix.base import FixRequest, FixResult, Usage
from codesift.fix.prompts import cli_prompt
from codesift.redact import Redactor

ALLOWED_TOOLS = "Read,Grep,Glob,Edit"
DENIED_TOOLS = "Bash,WebFetch,WebSearch,Write,NotebookEdit,Task"
ENV_KEEP = (
    "PATH",
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "XDG_CONFIG_HOME",
    "CLAUDE_CONFIG_DIR",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "LANG",
)
MAX_OUTPUT = 1_000_000


def find_claude(configured: str = "") -> str | None:
    if configured:
        return configured if os.path.isfile(configured) else None
    return shutil.which("claude")


def minimal_env(base: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ if base is None else base)
    return {k: v for k, v in env.items() if k.upper() in ENV_KEEP}


@dataclass
class ClaudeCliFixer:
    path: str
    model: str = ""
    max_turns: int = 8
    timeout_s: int = 600
    redactor: Redactor = field(default_factory=Redactor)
    name: str = "claude-cli"

    def argv(self) -> list[str]:
        cmd = [
            self.path,
            "-p",
            "--output-format",
            "json",
            "--max-turns",
            str(int(self.max_turns)),
            "--permission-mode",
            "acceptEdits",
            "--allowedTools",
            ALLOWED_TOOLS,
            "--disallowedTools",
            DENIED_TOOLS,
        ]
        if self.model:
            cmd += ["--model", self.model]
        return cmd

    def fix(self, req: FixRequest) -> FixResult:
        prompt = self.redactor.scrub(cli_prompt(req))
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, prompt on stdin, cwd = workspace copy
                self.argv(),
                input=prompt.encode("utf-8"),
                cwd=str(req.workspace),
                env=minimal_env(),
                capture_output=True,
                timeout=self.timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return FixResult(
                False, error=f"the Claude CLI timed out after {self.timeout_s}s", model=self.model
            )
        except OSError as exc:
            return FixResult(False, error=f"cannot start the Claude CLI: {exc.strerror}", model=self.model)
        out = proc.stdout[:MAX_OUTPUT].decode("utf-8", "replace")
        try:
            data = json.loads(out)
        except ValueError:
            data = {}
        usage_raw = data.get("usage") if isinstance(data, dict) else None
        usage = Usage()
        if isinstance(usage_raw, dict):
            usage = Usage(int(usage_raw.get("input_tokens") or 0), int(usage_raw.get("output_tokens") or 0))
        if proc.returncode != 0 or not isinstance(data, dict) or data.get("is_error"):
            err = proc.stderr[:2000].decode("utf-8", "replace") or str(data.get("result", ""))[:300]
            return FixResult(
                False,
                error=self.redactor.scrub(
                    f"Claude CLI exit {proc.returncode}: {' '.join(err.split())[:300]}"
                ),
                model=self.model,
                usage=usage,
            )
        explanation = self.redactor.scrub(" ".join(str(data.get("result", "")).split()))[:500]
        return FixResult(True, explanation, model=self.model or "claude-cli", usage=usage)
