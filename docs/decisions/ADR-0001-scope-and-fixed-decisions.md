# ADR-0001: Scope and decisions fixed by the owner

- Status: accepted
- Date: 2026-11-12

## Context

CodeSift exists to make security reviews cheap: free scanners plus a free local LLM do the bulk work,
and a paid reviewer only reads a short summary.

## Decision

The owner fixed these points up front; they are not re-opened without the owner:

| Topic | Decision |
|---|---|
| Repository | GitHub repo `PersianGru/CodeSift` (public, MIT licence) |
| Install | one installer → `sift` command + user-level Claude Code skill `/sift`; Windows and Linux |
| Languages | Python, JavaScript/TypeScript, Docker/config/CI files, PHP, Go, generic coverage for the rest |
| Tool updates | pinned versions + `sift update`; every run warns when tools are outdated |
| Automation | git pre-push hook only (fast, scanners only, no LLM); no CI services, no third-party SaaS |
| Binaries | gitleaks, osv-scanner, trivy, opengrep from official GitHub releases, checksum-verified, in CodeSift's own folder |
| Local LLM | `ollama/qwen3.8:27b-mtp-q4_K_M` via Bifrost, fallback `ollama/qwen3-coder:30b` (confirmed by the bake-off) |
| semgrep | not used; opengrep instead (see ADR-0003) |

## Consequences

The hard limits of [RULES.md](../../RULES.md) follow from these decisions: static analysis only,
a closed list of outbound hosts, no secret values anywhere.
