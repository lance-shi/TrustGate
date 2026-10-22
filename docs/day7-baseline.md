# Day 7 baseline and security review inventory

Date: 2026-10-22 (Australia/Sydney).
Starting revision: `5c4a8534f89f0cc79528d7b8e8b35e7d7d251c09`.
The tracked working tree was clean before this step.

Status: Step 1 complete. Existing tests, Ruff, and the direct example pass.
This is a baseline and review inventory, not completed adversarial testing or
release acceptance. No runtime behavior, public API, test, or policy changes
are part of this step.

## Verified environment and results

| Item | Observed value |
| --- | --- |
| Platform | Windows 11, build 26200, AMD64 |
| Python | 3.14.6 |
| Launcher | `C:\Users\Lance\AppData\Local\Python\bin\python.exe` |
| Interpreter | `C:\Users\Lance\AppData\Local\Python\pythoncore-3.14-64\python.exe` |
| Package | `trustgate` 0.1.0; import resolves to this repository's `src/trustgate/__init__.py` |
| Test tools | pytest 9.1.1; pytest-cov 7.1.0; Ruff 0.16.2 |
| Detection dependencies | presidio-analyzer 2.2.364; spaCy 3.8.13; local `en_core_web_sm` found |
| Model/policy dependencies | Pydantic 2.13.4; PyYAML 6.0.3 |
| Full test suite | **498 passed in 8.95 seconds**; no skips or warnings reported |
| Ruff | **All checks passed** |
| Direct example | **Exit 0**; JSON report shows tokenized LLM input/results and successful lifecycle checks |

The full test run includes the existing example tests for safe stdout/stderr,
offline operation, standalone execution, and failure handling. The direct run
also reported stable person tokens, an ambiguous identity, denied release,
cross-session rejection, closure, and rejection after close.

### Reproduction and environment failures

Run from the repository root in PowerShell:

```powershell
$trustgatePython = 'C:\Users\Lance\AppData\Local\Python\bin\python.exe'
$trustgateTestTemp = Join-Path $env:TEMP ('trustgate-day7-baseline-' + [guid]::NewGuid().ToString('N'))
& $trustgatePython -m pytest -q -p no:cacheprovider --basetemp=$trustgateTestTemp
& $trustgatePython -m ruff check .
& $trustgatePython examples/boundary_demo.py
```

Use a fresh dedicated `--basetemp`: pytest manages its contents. Do not point
it at an existing directory containing other work.

- The first launcher lookup using `$env:LOCALAPPDATA` failed because the sandbox
  redirects that variable to a sandbox package directory. No Python check ran
  in those attempts. The explicit installed launcher above works.
- The sandboxed full-suite attempt then stopped with 26 collection errors:
  spaCy/Wasabi/Colorama encountered the Windows console-handle error
  `0xc0000008`. These were import/collection errors, not test assertion failures.
- Repeating the full suite with approved execution outside the sandbox and a
  fresh temporary directory produced the 498-pass result above. No code,
  dependency, or test changes were needed. Ruff and the direct example passed
  in the sandbox using the explicit launcher.

The same console issue was documented in the
[Day 6 acceptance report](day6-acceptance.md).

## Public surface and failure-path inventory

Paths in the evidence column are relative to `tests/`. These are existing tests
inspected for this inventory; a passing file is not proof of exhaustive coverage.

| Surface | Contract and failure paths to review | Existing evidence |
| --- | --- | --- |
| `TrustGate(...)`, `policy`, `audit_sink` | Preserve configured policy/sink; absent policy denies release; gate retains no session mappings | `test_public_api.py`, `test_session_policy.py`, `test_audit.py` |
| `TrustGate.from_yaml()` | Unreadable, malformed, ambiguous, or invalid policy fails closed; no path/content in exceptions | `test_policy_loading.py`, `test_policy_models.py`, `test_failure_safety.py` |
| `TrustGate.session(...)`, `TrustSession(...)` | Distinct vaults and aliases; copied runtime aliases; strict default-off transcript; `principal` does not authorize actions | `test_public_api.py`, `test_session_vault.py`, `test_session_aliases.py`, `test_transcript.py` |
| `TrustSession.session_id`, `is_closed`, `__enter__`, `__exit__`, `close()` | Opaque identity; explicit cleanup on normal/exceptional exit; idempotent close; reject operations after close | `test_session_vault.py`, `test_failure_safety.py`, `test_boundary_failures.py`, `test_person_boundary_flow.py` |
| `TrustSession.sanitize()` | Validate detector output; cover overlapping spans; preserve canonical identities; fixed safe detector/resolver failures | `test_sanitization.py`, `test_detection.py`, `test_entity_resolution.py`, `test_boundary_spans.py`, `test_boundary_failures.py` |
| `decide_data_release()`, `TrustSession.decide_data_release()` | Exact destination/type decision; no vault-value return; missing rules deny; closed session rejects | `test_policy_decisions.py`, `test_session_policy.py` |
| `TrustSession.rehydrate_for_tool()` | Only explicit ALLOW releases a current-session value; malformed/unknown/foreign tokens fail; no partial return or caller mutation; same rules for reads/writes | `test_rehydration.py`, `test_partial_name_resolution.py`, `test_alias_resolution.py`, `test_person_boundary_flow.py` |
| `TrustSession.sanitize_tool_result()` | Sanitize nested keys/values without caller mutation; reject collisions, unsupported structures, cycles, detector/resolver failures; no partial return | `test_tool_result_sanitization.py`, `test_boundary_failures.py`, `test_boundary_spans.py`, `test_person_boundary_flow.py` |
| `TrustSession.transcript` | Default-off, completed outputs only, independent snapshots; exclude tool arguments and failed outputs; safe history survives close | `test_transcript.py` |
| `TrustSession.rehydrate_for_user()` | Remains unavailable; closed-session check takes precedence | Source inspection of `session.py`; closed-session rejection in `test_failure_safety.py`; open-session unavailable case needs an explicit test |
| Public typed models and enums | Validate construction and supported alternate Pydantic entry points; immutable policy mappings; fixed safe validation errors | `test_models.py`, `test_policy_models.py`, `test_audit_resolution.py`, `test_security_constraints.py` |
| `AuditSink.record()`, `InMemoryAuditSink.record()`, `events` | Generated events contain only safe metadata; fixed resolution state/reason; snapshot contains no mappings | `test_audit.py`, `test_audit_resolution.py`, `test_security_constraints.py` |
| Exported exceptions | Static messages; no sensitive arguments, cause, or context on wrapped boundary failures | `test_failure_safety.py`, `test_detection.py`, `test_boundary_failures.py`, `test_session_aliases.py` |

The export inventory is rooted in `src/trustgate/__init__.py`. Internal vault,
registry, resolver, and transcript collector are implementation dependencies,
not LLM tools. Public policy/request/model objects accept caller-provided data;
constructing one is not sanitization. Likewise, `AuditSink` accepts already-safe
events and does not itself detect arbitrary content supplied by a caller.

## Seven release-blocking invariants

| # | Required invariant | Current evidence | Remaining adversarial review |
| --- | --- | --- | --- |
| 1 | No detected raw sensitive values in LLM-visible sanitized returns | `test_sanitization.py`, `test_boundary_spans.py`, `test_person_boundary_flow.py`, `test_boundary_demo.py` | Expand hostile span/text/container cases and distinguish detection limits from transformation defects |
| 2 | Rehydrate only after explicit destination ALLOW | `test_policy_decisions.py`, `test_rehydration.py`, `test_session_policy.py` | Try destination variations, mixed token states, argument keys, and post-validation argument mutations |
| 3 | Missing/malformed policy denies by default | `test_policy_loading.py`, `test_policy_models.py`, `test_failure_safety.py` | Extend YAML structures/encodings and alternate policy construction paths |
| 4 | Token mappings cannot resolve across sessions | `test_session_vault.py`, `test_rehydration.py`, `test_session_aliases.py`, `test_person_boundary_flow.py` | Combine replay, closure, new sessions, and nested/mixed argument positions |
| 5 | Every tool result is sanitized before LLM exposure | `test_tool_result_sanitization.py`, `test_person_boundary_flow.py`, `test_boundary_demo.py` | Exercise traversal failures and less usual supported values; host must still route every result through the API |
| 6 | Audit, exceptions, and logs disclose no raw sensitive values | `test_security_constraints.py`, `test_audit_resolution.py`, `test_boundary_failures.py`, `test_transcript.py` | Inject audit sink failures and exceptional metadata/serialization inputs; assert exception chains and captured diagnostics |
| 7 | LLM has no direct vault access | Export/source inspection; `test_public_api.py`, `test_session_vault.py`; demo uses public boundary methods | Explicitly assert no vault/resolve capability in public exports, safe return objects, or demo LLM inputs |

Invariant 7 is an integration/API boundary, not a Python object sandbox. Trusted
host code can inspect private attributes; the host must never give the LLM a
session object, private vault, or a tool exposing raw resolution.

### Conservative identity contract

Existing `test_entity_candidates.py`, `test_partial_name_candidates.py`,
`test_alias_candidates.py`, `test_partial_name_resolution.py`,
`test_alias_resolution.py`, and `test_session_aliases.py` cover unique candidates,
ambiguity, producer-order conflicts, no retroactive merge, immutable canonical
values, runtime alias copying, and isolation. Day 7 should challenge combinations
of these conditions rather than repeat the existing happy paths. A confirmed
identity must never be inferred from an earlier uncertain mention.

## Prioritized follow-up tests

These are review targets, not confirmed vulnerabilities. Steps 2-4 must establish
expected behavior and reproduce any suspected defect before changing runtime code.

| ID | Step | Target and testable outcome |
| --- | --- | --- |
| P1 | 2 | Argument dictionary keys: inspect token references in top-level and nested keys. Current rehydration traverses values and copies keys. Determine the safe supported contract and test malformed/unknown/foreign references in those positions. Do not silently broaden release permissions. |
| P2 | 2 | Token parser combinations: unmatched/nested brackets, adjacent tokens, zero/leading-zero/very long sequences, and mixed allowed/denied/foreign tokens. Assert rejection without a partial return, caller mutation, or diagnostic leakage. |
| P3 | 2 | Policy ambiguity: nested duplicate keys, multiple documents, non-string/unhashable keys, recursive aliases, invalid UTF-8, exact destination variations, and alternate model construction. Require safe rejection/default deny without raw paths/content/chains. Existing duplicate/merge-key tests remain useful. |
| I1 | 3 | Combine exact/partial/alias conflicts with observation-order changes and nested tool results. Require uniqueness across all producers, stable uncertain identities, and immutable canonical rehydration. Existing permutation/no-retroactive tests are the baseline. |
| I2 | 3 | Combine caller alias mutation, session closure, and a fresh session. No alias or entity state may cross sessions or promote uncertain mentions. |
| D1 | 4 | Raising custom audit sink at session creation, sanitization, release, failure reporting, and close. Check exception chains, no partial returned output/transcript, and cleanup order. Existing sink tests cover a falsy sink, not a raising sink. |
| D2 | 4 | Public models containing mutable dictionaries/lists: mutate a validated `ToolCall.arguments` tree before rehydration; test cycles, unsupported objects, and iterator errors. Verify safe failure and document the supported boundary without adding transaction rollback. |
| D3 | 4 | Metadata/serialization edge cases, including unusual Unicode in destinations and caller model validation inputs. Capture logs, stdout/stderr, audit JSON, transcript, exception args/cause/context. Arbitrary caller objects are not automatically LLM-safe. |
| D4 | 4 | Assert no raw-resolution capability is exported or present in LLM-facing demo values; extend public API checks beyond the current expected-export subset. Explicitly test that open-session `rehydrate_for_user()` raises a safe `FeatureUnavailableError`. |

For each confirmed security defect, add both a behavior regression and a
leakage-prevention assertion using synthetic fixtures and the in-memory sink.
Run the focused file first, then the full suite and Ruff after fixes.

## Coverage and release limits

- `pytest-cov` is installed and listed in development dependencies. No coverage
  options or threshold are configured in `pyproject.toml`; this step did not
  measure statement/branch coverage. The tables are an evidence inventory,
  not a percentage or a complete security review.
- Only the existing local Python 3.14.6 environment was exercised. This does
  not establish the declared Python 3.11+ compatibility matrix.
- Wheel/sdist build, clean installation outside the repository, release notes,
  and final version/documentation consistency are still Steps 5-6 work.
- Local English detection has documented limits. Undetected text can remain
  unchanged and enter an enabled transcript. Host routing remains essential.
- Method failures do not promise rollback or automatic session closure; use
  explicit close or a context manager. Raw mappings remain ephemeral and
  process-local. No persistent storage, framework integration, authorization,
  approval flow, or user-response rehydration is added.

## Step 1 completion checklist

- [x] Record starting revision, clean tracked state, interpreter, and dependencies.
- [x] Run the full suite, Ruff, and the direct example.
- [x] Record environment errors separately from assertion failures.
- [x] Map public surfaces and seven invariants to existing evidence.
- [x] Identify concrete follow-up attack cases without claiming them as defects.
- [x] Keep adversarial review, fixes, and release acceptance open.

## Subsequent progress

Step 2 (P1-P3) completed on 2026-10-22. See
[the Step 2 report](day7-step2.md) for reproduced findings, fixes, and validation:
114 new cases, 148 focused passes, 612 full-suite passes, Ruff passed, and the
direct demo exited 0. The baseline counts and inventory above preserve the
pre-Step 2 state.

Step 3 (I1-I2) completed on 2026-10-22. See
[the Step 3 report](day7-step3.md): 86 new identity adversarial cases, 308 focused
passes, 698 full-suite passes, and Ruff passed. No runtime fix was needed for
the tested combinations.

Step 4 (D1-D4) completed on 2026-10-22. See
[the Step 4 report](day7-step4.md): 80 new diagnostic/API cases, 243 focused
passes, 778 full-suite passes, and Ruff passed. Audit errors, unsafe argument
trees, custom scalar outputs, and model-copy warning/exception paths were
hardened. Package and final release acceptance remain open.

Step 5 completed on 2026-10-22. See [the package-validation report](day7-step5.md):
782 tests pass locally and in both clean Windows installs (Python 3.11 source
distribution and Python 3.14 wheel). Statement coverage is 99.43%, branch
coverage 97.25%; builds, package-content checks, offline smoke flows, dependency
checks, and Ruff pass. Final release acceptance remains open.

Step 6 completed on 2026-10-22. The [final acceptance report](day7-acceptance.md)
and [0.1.0 release notes](../CHANGELOG.md) close the documented v0.1 local plan.
Runtime evidence remains 782 passes in all three tested environments, statement
coverage 99.43% and branch coverage 97.25%. Final documentation and rebuilt
candidate artifacts are consistent; package status remains pre-alpha.
