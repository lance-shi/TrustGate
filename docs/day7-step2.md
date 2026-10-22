# Day 7 Step 2: policy and token adversarial tests

Date: 2026-10-22 (Australia/Sydney).
Starting revision: `5c4a8534f89f0cc79528d7b8e8b35e7d7d251c09`.
Status: complete for baseline targets P1-P3. Steps 3-6 remain open.

## Findings and fixes

1. **Token references in dictionary keys bypassed validation.** Top-level and
   nested argument dictionaries copied keys unchanged, so denied, unknown,
   malformed, and foreign-session tokens could pass through in keys. Approved
   tokens in keys also stayed tokenized instead of reaching the trusted tool
   as their canonical value. Both levels now share `_rehydrate_mapping()`,
   which applies the existing parser and per-token destination policy to keys
   and values. Distinct keys that collide after rehydration raise the existing
   fixed `TokenResolutionError`. No partial tree is returned and no caller
   arguments are mutated. Invalid references and collisions emit denial events.
   The original behavior was token pass-through, not a demonstrated raw-value
   release without permission.
2. **Policy version accepted equal but incorrectly typed values.** Pydantic's
   `Literal[1]` accepted `True` and `1.0`, contrary to the documented integer
   schema. A before-validator now requires an actual integer; `Literal[1]`
   still enforces its value. YAML, direct initialization, validation, JSON,
   trusted construction, and copy updates obey the same schema. This closes a
   malformed-policy acceptance gap without adding release permissions.
3. **Excessive YAML nesting escaped the safe policy error boundary.** Parsing
   could raise `RecursionError` directly. `from_yaml()` now converts it to the
   fixed `PolicyValidationError`, outside the original handler so the public
   exception retains neither the original cause nor context. No gate is
   returned on failure. This is safe error handling, not a general resource
   exhaustion limit or a promise to process arbitrarily large policy files.

The first focused run reproduced the defects: **43 failed, 59 passed** in the
initial 102 cases. Collision rejection was added alongside the key-resolution
contract. After the fixes, 12 additional mixed-token-string cases were added;
all 114 new cases pass in the final full run.

## Regression evidence

| File | Added cases | Behavior and leakage checks |
| --- | --- | --- |
| `tests/test_adversarial_tokens.py` | 78 | Approved read/write release in top-level keys, nested keys, and values; invalid references after an approved value; denied/unknown/active-foreign/closed-owner tokens; malformed/nested/unmatched brackets, Unicode digits, long unknown sequences; mixed-token strings in both orders; exact destination matching; key collisions in both insertion orders; index-safe adjacent replacement; missing-policy denial |
| `tests/test_adversarial_policy.py` | 36 | Duplicate keys at each policy level; multiple documents; recursive aliases; sequence/mapping/numeric keys; invalid decision types/values; merge keys; unsafe Python YAML tags; excessive nesting; invalid UTF-8; version typing and invalid release rules across construction paths; valid nonrecursive alias compatibility; copied caller policy isolation |

Token tests use a deterministic fixture detector and public sanitization to
issue tokens, with process-local mappings and explicit session cleanup.
Existing whole-flow tests continue to exercise real local detection.
Failure tests inspect exception arguments/chains, serialized in-memory audits,
transcript snapshots, and captured logs/stdout/stderr for synthetic sensitive
values. Approved release tests verify that only the trusted return contains
the expected raw value. Rehydration never appends transcript entries.

The key-collision regression deliberately includes a synthetic literal raw key
to exercise collision with a resolved token in either insertion order. This
does not change the ingress requirement: normal LLM arguments should already
contain sanitized content.

## Final validation

| Check | Result |
| --- | --- |
| Focused policy/token tests, including existing regressions | **148 passed in 2.59 seconds** |
| Full suite | **612 passed in 10.11 seconds** |
| Ruff | **All checks passed** |
| Direct `examples/boundary_demo.py` | **Exit 0**, safe JSON lifecycle report |

No skips or warnings were reported by either final pytest run. The full suite
contains the 148 focused cases; these counts must not be added together.
Tests used approved execution outside the sandbox to avoid the documented
Windows console issue. No dependencies or test assertions were bypassed.

Reproduce from the repository root with the launcher/environment described in
[the baseline](day7-baseline.md):

```powershell
$trustgatePython = 'C:\Users\Lance\AppData\Local\Python\bin\python.exe'
$trustgateFocusedTemp = Join-Path $env:TEMP ('trustgate-day7-step2-focused-' + [guid]::NewGuid().ToString('N'))
& $trustgatePython -m pytest tests/test_adversarial_tokens.py tests/test_adversarial_policy.py tests/test_rehydration.py tests/test_policy_loading.py tests/test_policy_models.py tests/test_policy_decisions.py tests/test_session_policy.py -q --tb=short -p no:cacheprovider --basetemp=$trustgateFocusedTemp
$trustgateFullTemp = Join-Path $env:TEMP ('trustgate-day7-step2-full-' + [guid]::NewGuid().ToString('N'))
& $trustgatePython -m pytest -q --tb=short -p no:cacheprovider --basetemp=$trustgateFullTemp
& $trustgatePython -m ruff check .
& $trustgatePython examples/boundary_demo.py
```

Use fresh dedicated temporary paths; pytest manages their contents.

## Scope and next work

The [policy reference](data-release-policy.md) and README now document key/value
rehydration and collision rejection. The sample policy permissions are unchanged.
Reads and writes continue to use the same explicit release decision, and TrustGate
does not execute or authorize an action. Literal square brackets in argument keys
now receive the same syntax validation as brackets in argument values.

Step 3 identity combinations and Step 4 raising audit sinks, mutated argument
containers, metadata edge cases, and public vault exclusion remain open. A
method failure still does not promise rollback or automatic session closure.
Coverage measurement, supported-version compatibility evidence, package builds,
clean installation, and final release acceptance are deferred to Steps 5-6.
