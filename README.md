# TrustGate

**Let AI agents use sensitive data without exposing raw values to the LLM.**

TrustGate is a small, framework-independent Python library for building a
sensitive-data boundary between enterprise data, LLMs, and tools. It governs
data exposure, not action authorization.

## Status

TrustGate is pre-alpha. The current Day 2 implementation provides local English
sensitive-text detection, deterministic session-scoped tokenization, an
in-memory vault, session cleanup, and cross-session token isolation.

YAML policy loading, tool argument rehydration, recursive tool-result
sanitization, and auditing are planned but **not implemented**. Do not use this
version as a complete tool-data boundary or release it as the complete v0.1
workflow.

## Current usage: sanitize text before an LLM boundary

```python
from trustgate import TrustGate

with TrustGate().session() as session:
    safe_input = session.sanitize("Check account 12345678 for Jane Smith.")
    # Send only safe_input to the LLM.
```

The LLM-visible result contains tokens such as `[ACCOUNT_NUMBER_1]` and
`[PERSON_1]`, rather than the detected raw values. Token mappings are
process-local, in-memory, scoped to one `TrustSession`, and discarded when that
session closes. A token from another active session fails closed.

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

## Planned v0.1 workflow

The following is design intent, not a currently runnable API:

```text
User input -> sanitize -> LLM sees tokens
LLM tool call -> explicit policy ALLOW -> tool receives approved raw values
Tool result -> sanitize -> LLM sees tokens
```

The planned policy schema is documented in
[`examples/sample-policy.yaml`](examples/sample-policy.yaml). It cannot yet be
loaded by `TrustGate.from_yaml()`.

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
