# TrustGate

**Let AI agents use sensitive data without exposing that data to the LLM.**

TrustGate is a small, framework-independent Python library that creates a policy-controlled sensitive-data boundary between enterprise data, LLMs, and tools. It governs data exposure, not action authorization.

```text
User: Check account 12345678 for John Smith.
                         |
                         v
LLM sees: Check account [ACCOUNT_NUMBER_1] for [PERSON_1].
                         |
                         v
LLM requests: get_account("[ACCOUNT_NUMBER_1]")
                         |
                         v
TrustGate data policy: allow ACCOUNT_NUMBER to be released to get_account
                         |
                         v
Tool receives: get_account("12345678")
                         |
                         v
LLM receives: {"account": "[ACCOUNT_NUMBER_1]", "owner": "[PERSON_1]"}
```

The LLM sees tokens. Tools receive real values only when data-release policy allows rehydration. The surrounding system—not TrustGate—decides whether a tool call is authorized or should execute.

## Status

TrustGate is in early design and implementation (v0.1). The first release focuses on session-scoped in-memory vaults, YAML data-release policies, and deterministic tokenization.

## v0.1 goals

- Detect sensitive text with Presidio and custom recognizers.
- Replace sensitive values with stable, session-scoped tokens.
- Rehydrate tool arguments only after an explicit destination-aware data-release decision.
- Sanitize every tool result before it returns to the LLM.
- Emit audit events that never contain raw sensitive values.
- Remain independent of agent frameworks and LLM providers.

## Non-goals

v0.1 intentionally excludes authentication, IAM, user/tool/business authorization, human approval, persistent/distributed vaults, UI, database storage, MCP proxying, transaction handling, and agent-framework integrations. Both read and write-style tool calls may pass through the same data-rehydration pipeline; TrustGate does not decide whether either action is permitted.

## Session lifecycle

Sensitive token mappings are process-local, in-memory, and scoped to an explicit `TrustSession`.

```python
with gate.session(principal="user-123") as session:
    safe_input = session.sanitize(user_input)
    # Send only safe_input to the LLM.

    safe_tool_result = session.process_tool_call(tool_call)
    # Send only safe_tool_result to the LLM.

    user_response = session.rehydrate_for_user(llm_response)
```

When a session closes, its token mappings become unavailable. TrustGate never intentionally persists raw mappings to storage, logs, or remote services. If a process ends, rehydration fails closed; Python does not guarantee physical memory zeroization.

## Planned layout

```text
src/trustgate/     Core package
tests/             Unit, security, and end-to-end tests
examples/          Runnable, framework-independent examples
docs/              Design and policy documentation
```

## Development

Python 3.11 or later is required. Once implementation begins:

```bash
python -m pip install -e ".[dev]"
pytest
```

## License

Apache-2.0. See [LICENSE](LICENSE) once added.
