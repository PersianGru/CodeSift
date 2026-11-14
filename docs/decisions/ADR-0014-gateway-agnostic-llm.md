# ADR-0014: Gateway-agnostic LLM configuration

- Status: accepted
- Date: 2026-11-14
- Amends: [ADR-0001](ADR-0001-scope-and-fixed-decisions.md) (the "Local LLM" row: the endpoint is any
  OpenAI-compatible gateway), [ADR-0007](ADR-0007-llm-triage.md) item 10 (transport)

## Context

0.1.0 was written against one specific gateway product and used its name in variable names, help
text and docs. Users run many different OpenAI-compatible endpoints: self-hosted model servers, local
model runners with a `/v1` API, hosted routers, corporate proxies.

## Decision

1. The LLM endpoint is "the LLM gateway": any OpenAI-compatible base URL. User-facing text never
   names a specific product.
2. Configuration: `<config>/gateway.env` with `CODESIFT_LLM_BASE_URL`, `CODESIFT_LLM_API_KEY` (may be
   empty), `CODESIFT_LLM_MODEL`, `CODESIFT_LLM_FALLBACK_MODEL`, and `CODESIFT_LLM_ALLOW_HTTP`
   (the user's recorded "trusted network" choice). Environment variables override the file. Written
   with owner-only permissions by `sift setup --llm`.
3. URL rules: `https`, or `http` only for loopback or a private LAN address after an explicit
   "trusted network" confirmation; no embedded credentials, query or fragment; trailing slash
   stripped.
4. Backward compatibility: the 0.1.0 variable names and credentials file are still read silently as
   a fallback and migrated into `gateway.env` by the next `sift setup`; the legacy names are never
   shown to the user. The client class is `GatewayClient`; the old class name remains as an alias.
5. An empty API key is allowed (some local gateways need none); then no `Authorization` header is
   sent.

## Consequences

- Doctor and the wizard show host, model count and latency only; key values are never shown.
- The model ids are free text; CodeSift does not assume names.
