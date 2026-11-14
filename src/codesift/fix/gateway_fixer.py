"""Fixer backend: a model behind the user's OpenAI-compatible LLM gateway (one request at a time)."""

from __future__ import annotations

from dataclasses import dataclass, field

from codesift.fix.base import EditError, FixRequest, FixResult, Usage, apply_edits, parse_edits
from codesift.fix.prompts import SYSTEM_PROMPT, user_message
from codesift.gateway import GatewayClient, LLMError
from codesift.redact import Redactor


def usage_of(raw: dict[str, object]) -> Usage:
    def num(key: str) -> int:
        v = raw.get(key)
        return int(v) if isinstance(v, int | float) and not isinstance(v, bool) else 0

    return Usage(
        num("prompt_tokens") or num("input_tokens"), num("completion_tokens") or num("output_tokens")
    )


@dataclass
class GatewayFixer:
    client: GatewayClient
    model: str
    redactor: Redactor = field(default_factory=Redactor)
    max_tokens: int = 4096
    timeout_s: float = 300
    name: str = "gateway"

    def fix(self, request: FixRequest) -> FixResult:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": self.redactor.scrub(user_message(request))},
        ]
        usage = Usage()
        for round_ in range(2):  # one retry with the parse error as feedback
            try:
                result = self.client.chat(
                    self.model, messages, max_tokens=self.max_tokens, timeout=self.timeout_s, json_mode=True
                )
            except LLMError as exc:
                return FixResult(False, error=self.redactor.scrub(str(exc)), model=self.model, usage=usage)
            usage.add(usage_of(result.usage))
            try:
                edits, explanation = parse_edits(result.content)
                applied = apply_edits(request.workspace, edits, request.allowed_paths)
                return FixResult(True, explanation, model=result.model, usage=usage, applied=applied)
            except (EditError, UnicodeDecodeError) as exc:
                if round_ == 1:
                    return FixResult(False, error=f"invalid edits: {exc}", model=result.model, usage=usage)
                messages += [
                    {"role": "assistant", "content": result.content[:4000]},
                    {
                        "role": "user",
                        "content": f"That answer was rejected: {exc}. Answer with the JSON object only.",
                    },
                ]
        return FixResult(False, error="no answer", model=self.model, usage=usage)
