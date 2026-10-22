# Day 7 Step 4: output and diagnostic adversarial tests

Date: 2026-10-22 (Australia/Sydney).
Starting revision: `5c4a8534f89f0cc79528d7b8e8b35e7d7d251c09`, with completed
Steps 1-3 changes still in the working tree.
Status: complete for baseline targets D1-D4. Release checks remain open.

## Findings and fixes

### Audit failures could propagate unsafe exceptions

A custom audit sink could raise a raw message and chained exception during
session opening, sanitization, release, failure reporting, or closure. The
exception propagated directly. Failed opening could also leave aliases on a
retained partially constructed instance. Close already cleared state before
recording, but a failed close audit could chain the caller's unsafe context-body
exception.

Audit metadata construction, encoding, and callback failures now raise exported
`AuditRecordingError`, with a fixed message and no original cause/context.
The new exception's context is explicitly cleared before a bare re-raise so
context-manager unwinding cannot attach the unsafe body exception again.
Opening failure clears private state; closing still clears it before auditing.
An ordinary operation whose audit fails returns no result and adds no transcript
entry, while retaining private state until explicit close/context exit.

There is no retry, secondary audit write, or event rollback. A custom sink may
have accepted an already-safe event before raising. Its independent logging and
side effects remain trusted host behavior, not a Python sandbox guarantee.

### Mutable argument trees could escape JSON validation

Frozen `ToolCall` fields do not freeze their nested dictionaries/lists. After
construction, a caller could inject cycles, unsupported objects, invalid keys,
custom scalar objects, or failing iterators. Traversal previously recursed to
`RecursionError`, propagated iterator errors, or returned unsupported values
unchanged after processing an approved token.

Rehydration now tracks active container paths, permits shared containers in
independent branches, validates scalar/key types during traversal, and wraps
unexpected failures in exported `ToolArgumentRehydrationError`. The denied audit
event carries fixed `unsafe_argument_structure` metadata. No partial argument
tree is returned and caller-owned structures are not changed.

Known denied/token errors keep their public error types with freshly constructed
static exceptions. A caller iterator cannot smuggle raw exception arguments or
an unsafe custom exception subclass through the known-error handler. Both read
and write destinations still require the same explicit per-token ALLOW.

### Custom scalar objects could become LLM-visible outputs

Result sanitization accepted subclasses of `str`, `int`, and `float`. With no
detected span, a string subclass could survive unchanged; numeric subclasses
were returned directly. Such objects can contain extra state or an unsafe
representation despite having an ordinary scalar value.

Sanitization and rehydration now accept ordinary built-in scalar types only.
Custom scalar subclasses in tool results raise `ToolResultSanitizationError`;
direct `sanitize()` rejects non-built-in strings with `ModelValidationError`.
This preserves the existing text-detection scope and does not add numeric-data
detection. List/dictionary traversal still returns independent ordinary
containers and safely handles iterator failures.

### Model copying could leak before validation

`model_copy()` first serialized fields using `model_dump()`. Mutated contents
could therefore enter Pydantic serializer warnings through their raw `repr`
before validation rejected them. A caller-supplied update mapping could also
raise an unwrapped exception.

Copies now read declared fields and validate the fields plus updates directly,
without that serialization pass. Copy failures return the model's fixed
`ModelValidationError` or `PolicyValidationError`. Valid nested argument copies
remain independent for either `deep` flag. This does not make arbitrary caller
models or explicit serialization of unsanitized content safe.

## Additional confirmed boundaries

- Invalid lone-surrogate destinations are already rejected by policy, tool-call,
  and request model validation before audit encoding. Regression tests preserve
  this safe rejection; no encoding bypass was reproduced through those APIs.
- Explicit export/session-surface checks exclude direct vault, registry, raw
  mapping, resolver, and transcript-append capabilities. Existing demo tests
  now recursively assert that LLM inputs/results and the report contain only
  plain JSON-like data, with no session, vault object, or callable.
- Open-session `rehydrate_for_user()` still raises a safe
  `FeatureUnavailableError`; this step does not implement it.

These are API/integration checks. Trusted Python code can inspect private
attributes, and the host must still route every result through sanitization
and avoid giving the LLM a session object or raw-resolution tool.

## Regression inventory

| File | Added cases / changes |
| --- | --- |
| `tests/test_adversarial_diagnostics.py` | 72 new cases: all audited lifecycle/operation failures with transcript on/off; failed construction through both APIs; unsafe context-body error during close; mutated/cyclic/deep argument trees; custom scalars; safe Unicode metadata rejection; shared-container compatibility; safe unavailable user rehydration; spoofed token exceptions; sink serializer fault injection |
| `tests/test_adversarial_model_copy.py` | 6 new cases: raising update mappings for three public model types; raw serializer-warning prevention; independent valid nested copies for both deep flags |
| `tests/test_public_api.py` | 2 new cases: public vault-capability exclusion and static exported failure types |
| `tests/test_boundary_demo.py` | Strengthened existing tests with recursive plain-data assertions at both mock LLM boundaries and in the report |

There are **80 new cases**, growing the full suite from 698 to 778. Tests check
fixed exception arguments/cause/context, ordinary formatted tracebacks,
serialized audit events, transcript snapshots, warnings, logs, stdout/stderr,
caller ownership, no partial returns, cleanup, and token ownership revocation.
Fault injection uses synthetic values, in-memory sinks, and a deterministic
fixture detector. Existing real local detection/demo regressions also pass.

## Final validation

| Check | Result |
| --- | --- |
| Focused diagnostic, model, audit, transcript, API, result, rehydration and demo tests | **243 passed in 6.30 seconds** |
| Full suite | **778 passed in 10.20 seconds** |
| Ruff and formatting | Passed |

The final pytest runs reported no skips or warnings. Focused cases are included
in the full count. Tests used approved execution outside the sandbox to avoid
the documented Windows console-handle issue. No checks or dependencies were
bypassed, and sample policy permissions remain unchanged.

Reproduce from the repository root in PowerShell:

```powershell
$trustgatePython = 'C:\Users\Lance\AppData\Local\Python\bin\python.exe'
$trustgateFocusedTemp = Join-Path $env:TEMP ('trustgate-day7-step4-focused-' + [guid]::NewGuid().ToString('N'))
& $trustgatePython -m pytest tests/test_adversarial_diagnostics.py tests/test_adversarial_model_copy.py tests/test_public_api.py tests/test_boundary_demo.py tests/test_audit.py tests/test_audit_resolution.py tests/test_transcript.py tests/test_boundary_failures.py tests/test_models.py tests/test_rehydration.py tests/test_tool_result_sanitization.py tests/test_security_constraints.py -q --tb=short -p no:cacheprovider --basetemp=$trustgateFocusedTemp
$trustgateFullTemp = Join-Path $env:TEMP ('trustgate-day7-step4-full-' + [guid]::NewGuid().ToString('N'))
& $trustgatePython -m pytest -q --tb=short -p no:cacheprovider --basetemp=$trustgateFullTemp
& $trustgatePython -m ruff check .
```

Use fresh dedicated temporary directories; pytest manages their contents.
See [the baseline](day7-baseline.md), [Step 2](day7-step2.md), and
[Step 3](day7-step3.md) for preceding evidence.

## Remaining release work

Steps 5-6 still own coverage assessment, package builds, clean installation,
compatibility evidence, release notes/version consistency, and final acceptance.
This step adds no storage, external service, authorization, transaction rollback,
framework coupling, or user-response rehydration. The package remains pre-alpha.
