# TrustGate

**Let AI agents use sensitive data without exposing that data to the LLM.**

TrustGate is a small, framework-independent Python library that creates a policy-controlled privacy boundary between enterprise data and an LLM.

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
TrustGate policy: allow this read-only tool to receive ACCOUNT_NUMBER
                         |
                         v
Tool receives: get_account("12345678")
                         |
                         v
LLM receives: {"account": "[ACCOUNT_NUMBER_1]", "owner": "[PERSON_1]"}
```

The LLM sees tokens. Trusted tools see real values. Policy controls the boundary.

## Status

TrustGate is in early design and implementation (v0.1). The first release focuses on read-only tool calls, in-memory session vaults, YAML policies, and deterministic tokenization.

## v0.1 goals

- Detect sensitive text with Presidio and custom recognizers.
- Replace sensitive values with stable, session-scoped tokens.
- Rehydrate tool arguments only after an explicit allow policy decision.
- Sanitize every tool result before it returns to the LLM.
- Emit audit events that never contain raw sensitive values.
- Remain independent of agent frameworks and LLM providers.

## Non-goals

v0.1 intentionally excludes write tools, human approval, persistent/distributed vaults, IAM, UI, database storage, MCP proxying, and agent-framework integrations.

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
