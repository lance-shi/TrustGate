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

## Language support

TrustGate v0.1 supports **English (`en`) text detection only**. Its sensitive
data detection uses Presidio with a local English spaCy model. Session-scoped
tokenization, policy decisions, vault isolation, and rehydration are language
independent, but v0.1 makes no detection-quality promise for other languages.

Some pattern-based entities, such as email addresses or account numbers, may
still be detected in non-English text; this does not constitute multi-language
support. Additional languages require explicit model configuration and a
language-specific test suite before they can be supported.

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

## Policies and secure defaults

TrustGate uses destination-aware YAML data-release policies. See
[`examples/sample-policy.yaml`](examples/sample-policy.yaml) for a complete v0.1 example.

```yaml
data_policies:
  ACCOUNT_NUMBER:
    external_llm: tokenize
    destinations:
      get_account: allow
```

Sanitization and release are deliberately separate operations:

- **Sanitize by default.** Every detected sensitive value is tokenized before
  it can become LLM-visible, including values in tool results. v0.1 does not
  provide a policy option to send a detected raw value to an LLM.
- **Deny rehydration by default.** A token is restored for a tool only when its
  sensitive-data type and destination have an explicit `allow` decision.
- A missing policy, an unlisted data type, an unlisted destination, a malformed
  policy, an unknown token, a cross-session token, or a closed session all fail
  closed: no original value is released.

The policy controls data release only. It does not authorize a user, agent, or
tool to perform an action.

## Intended library usage

TrustGate is a Python library, not an LLM client or an agent framework. The
host application owns its LLM provider, API key, tool runtime, authentication,
and business authorization. It calls TrustGate at each data boundary:

```python
from trustgate import TrustGate

gate = TrustGate.from_yaml("examples/sample-policy.yaml")

with gate.session(principal="user-123") as session:
    llm_input = session.sanitize("Check account 12345678 for Jane Smith.")
    # Host application sends only llm_input to its chosen LLM provider.

    tool_call = {"name": "get_account", "arguments": {"account": "[ACCOUNT_NUMBER_1]"}}
    tool_arguments = session.rehydrate_for_tool(tool_call)
    # The host application's existing tool runtime receives tool_arguments.

    raw_tool_result = {"owner": "Jane Smith", "account": "12345678"}
    llm_visible_result = session.sanitize_tool_result(raw_tool_result)
    # Host application sends only llm_visible_result back to the LLM.
```

The names above describe the planned v0.1 public API; they will be implemented
with the core models and tests. Keeping this boundary as a library lets the
same protection layer work with DeepSeek, another hosted provider, a local
model, or no LLM in tests, without giving TrustGate access to provider keys or
tool authorization decisions.

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
