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
- Typed per-occurrence resolution reasons and a default-off sanitized transcript.
- A runnable local mock LLM/tool example using the real detector.
- Session cleanup and cross-session token isolation.
- Conservative session-local person resolution for normalized full names and
  uniquely matching first names, title-plus-surname mentions, and built-in
  given-name aliases plus caller-provided session-local additions.

`rehydrate_for_user()` is intentionally not implemented. TrustGate also remains
framework-independent and has no persistent audit or vault storage.

Day 6 implementation and acceptance are recorded in the
[acceptance report](docs/day6-acceptance.md). Independent adversarial review and
release validation remain Day 7 work; the package is still pre-alpha.

## Usage: LLM and tool boundaries

```python
import re

from trustgate import ToolCall, TrustGate

gate = TrustGate.from_yaml("examples/sample-policy.yaml")

with gate.session() as session:
    safe_input = session.sanitize("Check account 12345678 for Jane Smith.")
    # Send only safe_input to the LLM.

    # The LLM returns tokenized arguments it has seen, never raw values.
    account_token = re.search(r"\[ACCOUNT_NUMBER_[1-9][0-9]*\]", safe_input)
    if account_token is None:
        raise RuntimeError("The expected account token was not detected.")
    tool_call = ToolCall(
        name="get_account",
        arguments={"account": account_token.group()},
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
Token sequence numbers are process-wide; use tokens from sanitized output
rather than assuming that a new session starts at `_1`.

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
destination's explicit release policy.

The small built-in alias table supports `Jo` -> `Joanna`, `Joseph`, or `Joanne`,
and `Joe` -> `Joseph`. Alias relations generate candidates, never automatic
merges. For example, `Jo Taylor` can reuse a known `Joanna Taylor` token, but
remains ambiguous if `Joseph Taylor` is also known. Any supplied middle names
and surname must match exactly. Titled surname-only mentions do not use aliases.
Relations are directional and direct: sharing an alias does not make two full
names equivalent, and reverse/transitive relations are not inferred. Exact,
partial, and alias candidates are considered together; conflicting identities
remain ambiguous even when one candidate is an exact match.

Add custom given-name relations when creating a session:

```python
with gate.session(aliases={"Liz": ["Elizabeth", "Eliza"], "Beth": ["Elizabeth"]}) as session:
    safe_input = session.sanitize("Ask Elizabeth Taylor, then Liz Taylor.")
    # Only send safe_input to the LLM.
```

`TrustSession(aliases=...)` accepts the same optional argument. Aliases are a
mapping from one given-name component to a nonempty sequence of given-name
components (for example, lists or tuples). Components use Unicode and case
normalization; letters, combining marks, hyphens, and apostrophes are accepted.
Empty names, titles, full names, and malformed structures raise
`AliasValidationError` with a fixed, non-sensitive message before a session is
opened. Normalized duplicate keys combine their targets.

Custom relations add to the built-in table and use the same uniqueness,
component-matching, and release-policy rules. The session copies the input;
later edits to the caller's mapping or target lists have no effect. Custom
relations remain process-local and in memory, are discarded on close, and are
never stored on the gate, shared with other sessions, persisted, audited,
logged, or sent to the LLM. `None` or an empty mapping keeps the built-in table.

Resolution applies only to spans detected as `PERSON`. The detector preserves
an immediately preceding supported title (`Mr`, `Mrs`, `Ms`, or `Dr`, optionally
with a period), so a detected surname can reach the resolver as `Mr Smith`.
Alias configuration does not register new detector patterns or guarantee that
spaCy recognizes every spelling or mention. Undetected text remains unchanged;
applications must verify detection coverage for their data. A custom local
`EntityDetector` can be passed to `TrustSession(detector=...)` for known formats.

Ambiguous tokens retain the original detected surface as their canonical value,
not an arbitrarily chosen full name. If policy allows release, that original
surface can still reach the trusted tool. Resolution is not identity verification
or action authorization. See [the scope document](docs/v0.1-scope.md).

## Language support and local model setup

TrustGate supports English (`en`) detection using Presidio and an explicitly loaded
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
example. The [policy reference](docs/data-release-policy.md) documents schema
validation, the sample's decision matrix, and token-free argument behavior.

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

Sanitization events also include a `resolutions` tuple with one entry per
detected person occurrence, in processing order. Each entry contains only an
opaque token audit identifier, a fixed `EntityResolutionState`, and a fixed
`EntityResolutionReason`. States are `exact`, `unique_partial`, `unique_alias`,
`unresolved`, and `ambiguous`; reasons distinguish full-name matches, first- or
last-name matches, alias matches, and absent or conflicting candidates. An
`exact` state also describes a newly registered full name, not verified identity.
Multiple occurrences may reference the same token with different reasons.

These entries never contain names, normalized names, aliases, candidate lists,
or canonical tool values. Non-person, lifecycle, and tool-release events have
no resolution entries. A failed tool-result event may include safe evidence
from occurrences processed before failure; it does not indicate a successful
result or data release. Audit snapshots remain readable after session close.
The typed `AuditResolution` model rejects unknown fields, invalid identifiers,
and inconsistent state/reason combinations with a non-sensitive exception.

Local resolver failures raise a fixed `EntityResolutionError`, without the
original exception message, cause, or context. Failed tool-result events identify
this as `entity_resolution_unavailable`. Invalid detector output (including
`None` instead of a tuple of `SensitiveEntity` spans) raises
`DetectionUnavailableError`. Cyclic results and unexpected container iteration
errors raise `ToolResultSanitizationError` with `unsafe_result_structure` audit
metadata. Reusing a container in different branches is supported and produces
independent sanitized copies.

Failed sanitization returns no partial result and adds no transcript entry.
Session state created before failure remains private until the session closes;
failure does not automatically close an explicitly managed session or undo
earlier state. Use a context manager, or close the session in `finally`, to
discard vault mappings, entity/mention state, aliases, and token ownership
metadata even when an operation fails. Audit and transcript snapshots remain
readable after closure.

## Optional sanitized transcript

Transcript collection is disabled by default. Enable it for an individual
session with `gate.session(transcript=True)` or `TrustSession(transcript=True)`:

```python
gate = TrustGate.from_yaml("examples/sample-policy.yaml")
with gate.session(transcript=True) as session:
    safe_input = session.sanitize("Check account 12345678 for Jane Smith.")
    safe_result = session.sanitize_tool_result({"owner": "Jane Smith"})

# Independent typed snapshots remain readable after the session closes.
entries = session.transcript
for entry in entries:
    print(entry.model_dump_json())
```

`session.transcript` returns a tuple of `TranscriptEntry` snapshots, each with
`kind` (`input_sanitized` or `tool_result_sanitized`) and `content`. Entries are
appended only after the entire corresponding operation and its audit recording
succeed. Failed operations add no entry, including when some nested items were
already processed. Disabled sessions allocate no transcript collector and return
an empty tuple. Only a boolean is accepted for the creation-time switch.

Collection is automatic at those two boundaries. There is no public append
method, file output, logging handler, or external transcript sink. Tool calls
are not collected: neither caller-supplied call names/arguments nor the raw
arguments returned by `rehydrate_for_tool()` enter this history. LLM responses
are not automatically collected either; this is a history of completed
sanitization outputs, not a complete conversation recorder.

The collector never reads aliases, normalized names, or vault mappings. It owns
copies of sanitized outputs, and each read returns another independent deep
copy, so editing a result or a snapshot cannot modify the stored history.
Histories belong to one session and remain in memory while that session object
is retained. Closing the session clears raw mappings and resolution state while
preserving the transcript; previously obtained snapshots remain caller-owned.

Transcript safety depends on detection coverage, just like the sanitization
return values: undetected sensitive text remains unchanged and can therefore
appear in this opt-in history. `TranscriptEntry` validates structure, not
sensitivity; constructing one directly does not sanitize its content. Verify
the local detector's coverage for your data before enabling content collection.

## Runnable local example

After the package and local model are installed using the setup commands above,
run this from the repository root:

```bash
python examples/boundary_demo.py
```

On Windows, if `python` selects an inaccessible WindowsApps alias, use the
installed launcher:

```powershell
& "$env:LOCALAPPDATA\Python\bin\python.exe" examples/boundary_demo.py
```

The example uses the real local detector, synthetic data, a mock LLM, and mock
read/write tools. No API key or network connection is needed. The mock LLM
receives only sanitized text and constructs calls using observed tokens. After
explicit policy allowance, the trusted mock tool receives raw arguments; its
nested result is sanitized before becoming LLM-visible. Both read and write
destinations use the same release path; the write is only an in-memory simulation.

The JSON report shows tokenized input/calls/results, mock replies, a stable
follow-up token, an ambiguous alias with its own token, a denied release, cross-session replay
rejection, and rejection after session close. It also includes the optional
sanitized transcript and a compact audit summary. Tokens come from actual
sanitized output; their numbers may differ between runs.

The script loads its policy relative to its own file, so an absolute script
path also works from another working directory. It checks these known demo
fixtures before printing anything. Missing detection, policy, or tool failures
produce a fixed stderr message and a nonzero exit status without printing raw
values or exception details. Those fixture checks do not replace a general
detector or establish coverage for other data. The model must already be local;
the example never downloads one at runtime.

Run the example regressions with:

```bash
python -m pytest tests/test_boundary_demo.py
```

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

The Day 5 whole-flow regressions run with the installed local spaCy model:

```bash
python -m pytest tests/test_person_boundary_flow.py tests/test_detection.py
```

They exercise sanitized input -> mock LLM -> policy-controlled read/write tool
arguments -> copied, sanitized nested results -> follow-up -> session closure,
including custom aliases, ambiguous identities, denied destinations, and
cross-session replay. Candidate and session tests use controlled detector spans
to verify resolution rules independently of NER accuracy. Optional sanitized
transcript collection and the runnable example above are implemented.

The Day 6 acceptance commands and environment notes are recorded in the
[acceptance report](docs/day6-acceptance.md). The
[baseline and coverage checklist](docs/day6-baseline.md) preserves the
pre-change baseline and the evidence for each implementation step.
