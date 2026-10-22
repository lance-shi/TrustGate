# Data-release policy reference

TrustGate decides whether a sensitive token's value may be released to a named
destination. The host application decides whether to execute that action.
Read and write-style destinations use exactly the same data-release rules.

## Loading and schema

Load a UTF-8 YAML policy with `TrustGate.from_yaml(path)`. The complete schema is:

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

| Field | Supported value |
| --- | --- |
| `version` | The integer `1` |
| `data_policies` | A mapping from entity type to its handling rules |
| Entity type | Uppercase names matching `[A-Z][A-Z0-9_]*` |
| `external_llm` | `tokenize` only |
| `destinations` | A mapping from exact destination names to `allow` or `deny` |
| Destination name | A nonempty string of at most 256 characters |

The version must be the integer `1`; booleans and floating-point values are
rejected even when they compare equal to `1`. Unknown fields, unsupported
versions/decisions, duplicate YAML keys, and YAML merge keys are rejected.
Missing, unreadable, malformed, excessively nested, or invalid documents
raise a fixed `PolicyValidationError`; the document and its path are not included
in the public exception. Loading failure does not produce a permissive gate.

The validated policy is immutable. A gate created without a policy still
sanitizes data, but token release is denied. An unlisted entity type or destination
also denies release. Destination matching is exact and case-sensitive; there are
no wildcards, groups, inheritance, or permissions inferred from tool names.

## What the sample permits

The repository's [sample policy](../examples/sample-policy.yaml) has these rules:

| Type | `get_account` | `update_account` | `send_email` |
| --- | --- | --- | --- |
| `ACCOUNT_NUMBER` | allow | allow | deny |
| `PERSON` | allow | allow | deny |
| `EMAIL_ADDRESS` | deny (unlisted) | deny (unlisted) | allow |
| `PHONE_NUMBER` | deny (unlisted) | deny (unlisted) | deny (unlisted) |

Every other destination/type combination denies release. An explicit `deny`
documents an intentional restriction; an omitted rule has the same denial effect.
Allowing an email address to reach `send_email` does not allow person or account
tokens in that same call, and does not authorize sending a message.

## Tool-bound behavior

Use `session.rehydrate_for_tool(ToolCall(...))` for arguments proposed by the
LLM. It copies nested JSON-like argument keys and values and resolves token
references only within that session. Each referenced token requires an explicit `allow`
for its entity type and the call's destination before a raw value is substituted.
Denied, malformed, unknown, cross-session, and closed-session references fail
closed. Top-level and nested dictionary keys use the same token parser and
release policy as values. Literal square brackets are subject to token syntax
validation in both positions. If distinct keys become equal after rehydration,
the call raises a fixed `TokenResolutionError` rather than overwriting an
argument. A failed call never returns a partially rehydrated argument tree.

The argument tree is checked again during rehydration because nested model
containers can be mutated after validation. Cycles, excessive recursion,
unsupported objects, non-string keys, custom scalar subclasses, and unexpected
iterator failures raise a fixed `ToolArgumentRehydrationError` and record a
denied-release event with `unsafe_argument_structure`. Ordinary shared containers
remain supported. This does not detect new sensitive data in untokenized strings.

Strings containing several tokens require allowance for every token. Tokens
always release their immutable canonical value; an ambiguous person token can
release only its original detected surface, not a guessed identity. Resolution
state does not silently expand or override policy.

This method does not execute a tool or detect new sensitive strings in its
arguments. Untokenized values are copied unchanged, and calls without token
references do not require a token-release decision. Sanitize sensitive data at
ingress, give only those sanitized values to the LLM, and send rehydrated values
only to the trusted tool runtime. Independently of the release decision, sanitize
every tool result with `sanitize_tool_result()` before returning it to the LLM.

`session.decide_data_release(DataReleaseRequest(...))` can inspect a decision
without resolving vault values. It neither executes an action nor releases data.
The optional `principal` parameter on `gate.session()` is currently ignored;
it is not an identity, permission, or authorization check.

## Detection and diagnostics

Policy configures release, not detection. Adding an entity-type entry does not
add a detector or extend the local model vocabulary. Built-in English detection
currently supports `PERSON`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, and eight-digit
`ACCOUNT_NUMBER` patterns; detection coverage still depends on the input.
Undetected text remains unchanged. Alias additions also do not expand detection.

Audit events contain safe metadata and opaque identifiers, never rehydrated
arguments or policy contents. The optional transcript is disabled by default and
records only completed sanitization outputs; it never records the raw arguments
returned by rehydration. Its content inherits the detector's coverage limits.

If recording an event fails, a fixed `AuditRecordingError` replaces the original
sink/serialization exception. No operation result or transcript entry is returned
for that failed operation. An already accepted safe event is not rolled back.
Close clears private state before attempting its audit event; other failures
still require explicit session cleanup.

See the [README](../README.md), [scope](v0.1-scope.md), and
[runnable mock example](../examples/boundary_demo.py) for the complete lifecycle.
