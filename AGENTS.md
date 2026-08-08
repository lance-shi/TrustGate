# TrustGate contributor guide

## Purpose

TrustGate is a Python sensitive-data boundary that lets LLM-powered applications work with sensitive data without disclosing raw values to an LLM. It governs data exposure, not action authorization. Keep the core protocol- and framework-independent.

## Project conventions

- Use Python 3.11+ and the `src/` package layout.
- Keep public models and APIs typed.
- Prefer small explicit functions and standard-library features over abstraction layers.
- Keep framework integrations (MCP, LangChain, agent SDKs) outside the core package.
- Add or update tests with every behavioral change.

## Security invariants

These are release-blocking requirements:

1. Never return raw sensitive values to an LLM after sanitization.
2. Rehydrate a tool argument only after an explicit `ALLOW` data-release decision for its destination.
3. Missing or malformed policy is deny by default.
4. Token mappings are scoped to a session and cannot resolve across sessions.
5. Sanitize every tool result before it becomes LLM-visible.
6. Audit events, exceptions, and debug logs must never include raw sensitive values.
7. The LLM must never receive direct access to the token vault.

## Implementation guardrails

- Read and write-style tool calls use the same rehydration pipeline. Do not add validation that rejects a call merely because it is a write.
- TrustGate determines whether data may be released to a destination; it never determines whether a user or agent may execute that action.
- Make session lifecycle explicit through `TrustSession`; raw mappings stay process-local, in-memory, session-scoped, and ephemeral.
- Never persist raw token mappings to a database, cache, filesystem, audit store, log, or remote service.
- Treat unknown, malformed, and cross-session tokens in tool arguments as errors; do not pass them through.
- Do not silently broaden policy permissions.
- Do not mutate caller-owned tool result structures while sanitizing them.
- Process text replacements from right to left or use an equivalently index-safe approach.
- Prefer an in-memory audit sink in tests; assert its serialized events contain no sensitive values.

## Testing

Run the focused test file while developing, then run the full suite:

```bash
pytest
```

Security-sensitive changes must include tests for both the desired behavior and leakage prevention.

## Scope discipline

Do not add persistent storage, encryption/key management, authentication, IAM/RBAC/ABAC, user/tool/business authorization, approval flows, transaction handling, retry/idempotency logic, web UI, cloud deployment, distributed sessions, or agent framework coupling to v0.1 unless explicitly requested.
