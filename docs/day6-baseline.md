# Day 6 test baseline and coverage checklist

Recorded on 2026-10-19 before implementing Day 6 behavior changes.
Starting commit: `ef87d21` (`Finalise steps and update readme`).
The tracked working tree was clean at the start of this check.

This is a test inventory, not a line-coverage measurement or a release audit.
Items marked pending are planned work, not currently passing guarantees.

## Verified baseline

| Check | Result |
| --- | --- |
| Focused audit, leakage, sanitization, and whole-flow tests | 29 passed |
| Full test suite | 339 passed in 4.31 seconds; no warnings or skips reported |
| Ruff | All checks passed |

The focused tests are also included in the full-suite count.

Environment used:

- Windows, Python 3.14.6.
- Installed interpreter: `C:\Users\Lance\AppData\Local\Python\pythoncore-3.14-64\python.exe`.
- Working launcher: `C:\Users\Lance\AppData\Local\Python\bin\python.exe`.
- Editable package `trustgate` 0.1.0 resolves to this repository's `src/trustgate`.
- pytest 9.1.1; Ruff 0.16.2; Presidio Analyzer 2.2.364; spaCy 3.8.13;
  Pydantic 2.13.4; PyYAML 6.0.3.
- Local `en_core_web_sm` is installed; real detector tests passed.
- This run does not establish compatibility across all supported Python versions.

Reproduction in PowerShell from the repository root:

```powershell
$trustgatePython = 'C:\Users\Lance\AppData\Local\Python\bin\python.exe'
& $trustgatePython -m pytest tests/test_audit.py tests/test_security_constraints.py tests/test_sanitization.py tests/test_tool_result_sanitization.py tests/test_person_boundary_flow.py -q -p no:cacheprovider
$trustgateTestTemp = Join-Path $env:TEMP ('trustgate-day6-' + [guid]::NewGuid().ToString('N'))
& $trustgatePython -m pytest -q -p no:cacheprovider --basetemp=$trustgateTestTemp
& $trustgatePython -m ruff check .
```

Use a fresh, dedicated `--basetemp` for each run: pytest manages and may remove
that directory. Never point it at an existing directory containing other work.

Local execution issues and resolution:

- Bare `python` selects an inaccessible WindowsApps alias; use the explicit launcher.
- The sandboxed test process encountered a Colorama console-handle error while
  importing spaCy. Tests succeeded when run with approved execution outside the sandbox.
- The first focused run passed with a pytest cache-write warning.
- Full-suite attempts using the existing default temp location and then the
  repository's `.pytest_cache` location each had 330 passes and 9 fixture setup
  errors due to directory permissions. These were not assertion failures.
- Disabling cache writes and selecting a fresh independent temp directory produced
  the final 339-pass result. No application or test code was changed to obtain it.

## Existing coverage to reuse

Paths in the following table are relative to `tests/`.

| Area | Existing evidence | Remaining Day 6 work |
| --- | --- | --- |
| In-memory auditing | `test_audit.py`: allowed release metadata, opaque destination, no release event for token-free calls, custom falsy sink | Add resolution state/reason metadata and test the resulting serialized events |
| Audit serialization and leakage assertions | `test_security_constraints.py`: event serialization, nested disclosure detection, exception-context inspection; `security_assertions.py` serializes Pydantic models | Exercise new diagnostic fields and collected events, including normalized names and custom aliases |
| Tool-result audit failures | `test_tool_result_sanitization.py`: detector failure, unsupported structure, sanitized-key collision | Review new resolver and diagnostic failure paths as they are introduced |
| Nested results and caller ownership | `test_tool_result_sanitization.py`, `test_partial_name_resolution.py`, `test_alias_resolution.py`: nested values and sensitive dictionary keys, repeated names, original result unchanged | Extend only where new diagnostics or failure paths add risk |
| Empty content | `test_person_boundary_flow.py::test_real_detector_input_tool_result_followup_and_session_close` includes nested empty string, dictionary, list, and null | Add focused cases for top-level empty content and diagnostics if not already covered by the new tests |
| Span conflicts and replacement offsets | `test_sanitization.py`: overlapping types, adjacent spans, different lengths, out-of-bounds detection | Add deterministic conflict cases such as equal-score ties, containment, and chained overlaps |
| Duplicate values and canonical identity | `test_sanitization.py`, `test_vault.py`, `test_entity_resolution.py`: token reuse, independent identities, immutable canonical values | Verify audit/transcript additions preserve those behaviors |
| Detector failure cleanup | `test_person_boundary_flow.py::test_detector_failure_closes_session_and_cannot_expose_exception_context`: input/result failure, context-manager closure, vault and alias cleanup | Add separate resolver-failure injection; detector failure is not resolver coverage |
| Session and vault lifecycle | `test_session_vault.py`, `test_vault.py`, `test_partial_name_resolution.py`, `test_alias_resolution.py`, `test_session_aliases.py`: cross-session rejection, close, entity/alias cleanup | Exercise failure after some entities or nested items have already been processed |
| Tool argument release | `test_rehydration.py`: explicit allow, denied/invalid/cross-session tokens, nested copies, no partially returned release, allowed writes | Ensure no rehydrated arguments enter new diagnostic outputs |
| Name ambiguity and safe diagnostics | `test_partial_name_resolution.py`, `test_alias_resolution.py`, `test_session_aliases.py`: unique/ambiguous names, no retroactive merge, safe mention metadata/audits/logs | Publish only fixed safe state/reason metadata through audit |
| Full lifecycle with local detection | `test_person_boundary_flow.py`: mock LLM, read/write tools, nested sanitized results, follow-up, denial, replay, closure | Turn the intended flow into a runnable example with stdout/stderr checks |
| Optional transcript | Whole-flow tests build local lists of sanitized values; there is no transcript feature | Implement default-off collection and dedicated safety tests |
| Example and documentation | `examples/sample-policy.yaml`, README, `docs/v0.1-scope.md` | Add runnable demo, diagnostic usage, commands, and limits |

## Implementation checklist

### Step 1: baseline and inventory

- [x] Locate the actual interpreter and local detector dependencies.
- [x] Run focused tests, then the complete suite and Ruff.
- [x] Record reproducible commands and distinguish environment errors from failures.
- [x] Map existing tests to Day 6 requirements and record missing coverage.

### Step 2: safe audit metadata — complete on 2026-10-19

- [x] Define fixed safe resolution states/reasons without raw names or free-form errors.
- [x] Cover exact, unique partial, unique alias, unresolved, and ambiguous outcomes.
- [x] Verify emitted event JSON excludes raw/normalized names, runtime alias entries,
      vault mappings, and rehydrated arguments.
- [x] Preserve release-policy decisions and canonical token behavior.

Implementation adds typed `AuditResolution` entries to existing sanitization
events, including safe processed evidence on supported tool-result failure paths.
Each entry holds only the opaque token audit identifier and validated state/reason
enums. No additional event types or release decisions are introduced. Non-person,
lifecycle, and release events keep an empty resolution tuple.

`tests/test_audit_resolution.py` adds 40 cases covering per-occurrence ordering,
nested keys/values, all five states, safe JSON round trips, failure events,
independent sessions, stable uncertain evidence, canonical read/write release,
default deny, and invalid metadata through construction/validation/copy paths.
The existing alias leakage test uses `Beth` in place of `Liz` because the fixed
reason `exact_normalized_full_name` contains the substring `liz`; the same raw
and normalized alias leakage assertions remain in place.

Step 2 verification: initial focused set 53 passed; final full suite 379 passed
in 4.33 seconds, including the subsequently added same-text occurrence test;
Ruff passed. The original 339-test baseline above remains the pre-change record.

### Step 3: optional sanitized transcript

- [ ] Define an in-memory, explicitly enabled, default-off interface.
- [ ] Collect only content after the relevant sanitization boundary succeeds.
- [ ] Exclude raw inputs/results, rehydrated tool arguments, aliases, and vault state.
- [ ] Test default-off behavior, safe serialization, snapshot isolation, session
      isolation, and failure without a partially recorded unsafe entry.
- [ ] Document detection coverage limits; copying a value into a transcript does
      not establish that the value was sanitized.

### Step 4: failure and boundary regressions

- [ ] Inject resolver failures during input and nested result sanitization,
      including failure after prior items created session state.
- [ ] Assert safe exception arguments/chains and no raw audit/log/transcript output.
- [ ] Assert no partially processed result is returned and caller data is unchanged.
- [ ] Verify context-manager exit clears vault, entity, mention, and alias state.
      Do not assume that a failed method automatically closes an explicitly managed session.
- [ ] Add missing empty-content and deterministic span-conflict cases.
- [ ] Preserve duplicate token reuse, identity separation, policy enforcement,
      cross-session rejection, and closed-session rejection with diagnostics enabled.

### Step 5: runnable example

- [ ] Use public APIs, mock LLM/tools, and the local detector without framework coupling.
- [ ] Demonstrate stable tokens, a deliberately ambiguous name, allowed release,
      denied release, result sanitization, and explicit session closure.
- [ ] Add a smoke test that captures stdout/stderr and rejects sensitive values.
- [ ] Avoid fixed token sequence numbers and runtime model downloads.

### Step 6: documentation and final checks

- [ ] Update README and policy guidance for implemented diagnostics and the demo.
- [ ] Keep detection limits, conservative resolution, and data-release boundaries explicit.
- [ ] Run focused tests, the full suite, Ruff, and the runnable demo.

No runtime behavior or public API changes are part of Step 1. User-response
rehydration, persistent storage, framework integrations, and Day 7 release checks
remain outside this step.
