# TrustGate

**Let AI agents use sensitive data without exposing raw values to the LLM.**

TrustGate is a small, framework-independent Python library for building a
sensitive-data boundary between enterprise data, LLMs, and tools. It governs
data exposure, not action authorization.

## Status

TrustGate is pre-alpha. The current implementation provides:

- Local English sensitive-text detection and deterministic, session-scoped
  tokenization.
- YAML policy loading with strict validation and default-deny decisions.
- Policy-controlled recursive tool-argument rehydration.
- Recursive tool-result sanitization before values become LLM-visible.
- Process-local, in-memory audit events containing only safe metadata.
- Session cleanup and cross-session token isolation.
- Conservative session-local person resolution for normalized full names and
  uniquely matching first names or title-plus-surname mentions.

`rehydrate_for_user()` is intentionally not implemented. TrustGate also remains
framework-independent and has no persistent audit or vault storage.

## Usage: LLM and tool boundaries

```python
from trustgate import ToolCall, TrustGate

gate = TrustGate.from_yaml("examples/sample-policy.yaml")

with gate.session() as session:
    safe_input = session.sanitize("Check account 12345678 for Jane Smith.")
    # Send only safe_input to the LLM.

    # The LLM returns tokenized arguments it has seen, never raw values.
    tool_call = ToolCall(
        name="get_account",
        arguments={"account": "[ACCOUNT_NUMBER_1]"},
    )
    tool_arguments = session.rehydrate_for_tool(tool_call)
    # Send tool_arguments only to the trusted tool runtime, never to the LLM.

    tool_result = {"account": tool_arguments["account"], "owner": "Jane Smith"}
    safe_tool_result = session.sanitize_tool_result(tool_result)
    # Send only safe_tool_result to the LLM.
```

The LLM-visible result contains tokens such as `[ACCOUNT_NUMBER_1]` and
`[PERSON_1]`, rather than the detected raw values. Token mappings are
process-local, in-memory, scoped to one `TrustSession`, and discarded when that
session closes. A token from another active session fails closed.

`rehydrate_for_tool()` traverses nested JSON-like arguments without mutating the
`ToolCall`. Every token must belong to the current session and have an explicit
`allow` decision for the tool destination. Unknown, malformed, cross-session,
or denied tokens fail closed. Read and write-style destinations use the same
data-release decision path.

## Person-name resolution

Person resolution uses local, deterministic English name rules. After a
confirmed `John Smith`, `John` or `Mr Smith` can reuse that person's token only
when there is exactly one compatible confirmed candidate. If `Larry Smith` is
also known, `Mr Smith` receives an independent token with an ambiguous state.

Identical unresolved or ambiguous mentions keep their own token and original
state, even after later input supplies a matching full name. Unconfirmed
mentions never become candidate identities. Each occurrence retains private
state and reason metadata without retaining its raw text in mention history.
Tokens always rehydrate to their original canonical value, subject to the
destination's explicit release policy. Alias resolution is not implemented yet.

## Language support and local model setup

Day 2 supports English (`en`) detection using Presidio and an explicitly loaded
local `en_core_web_sm` spaCy model. TrustGate never downloads a model while
sanitizing: if the model is unavailable, detection fails closed.

```bash
python -m pip install -e ".[dev]"
python -m spacy download en_core_web_sm
```

Some pattern-based entities, such as account numbers and email addresses, may
be detectable in other languages. This does not constitute multi-language
support.

## Data-release policy

Policies are loaded using `TrustGate.from_yaml()`. The schema is strict: the
only supported version is `1`, LLM exposure must be `tokenize`, and release
decisions are `allow` or `deny`.

```yaml
version: 1
data_policies:
  ACCOUNT_NUMBER:
    external_llm: tokenize
    destinations:
      get_account: allow
      update_account: allow
      send_email: deny
```

Missing, unreadable, malformed, or structurally invalid policy documents fail
closed. Missing entity types and destinations also deny by default. See
[`examples/sample-policy.yaml`](examples/sample-policy.yaml) for the complete
example.

## Tool-result sanitization and auditing

`sanitize_tool_result()` recursively copies and sanitizes JSON-like values,
including nested dictionaries, lists, and dictionary keys. Unsupported values
and sanitized-key collisions fail closed rather than returning a potentially
unsafe value.

Each `TrustGate` uses an in-memory `InMemoryAuditSink` by default; an
application can provide an `AuditSink` to `TrustGate(...)`. Events record only
safe metadata: session ID, event type, release decision, and opaque audit
identifiers for entity types, tokens, and destination. They never include vault
mappings or raw sensitive values.

## Workflow

```text
User input -> sanitize -> LLM sees tokens
LLM tool call -> explicit policy ALLOW -> tool receives approved raw values
Tool result -> sanitize -> LLM sees tokens
```

## Non-goals

v0.1 excludes authentication, IAM, user/tool/business authorization, human
approval, persistent or distributed vaults, UI, database storage, MCP proxying,
transaction handling, retry/idempotency, and agent-framework integrations.

## Development

Python 3.11 or later is required.

```bash
python -m pytest
python -m ruff check .
```
