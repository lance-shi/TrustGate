# Day 6 acceptance report

Date: 2026-10-19 (Australia/Sydney).
Starting revision for this documentation pass: `695841a`.

Status: passed. All six Day 6 implementation slices are complete.

## Accepted scope

| Deliverable | Implementation and evidence |
| --- | --- |
| Baseline and coverage inventory | [Baseline/checklist](day6-baseline.md); 339 tests before Day 6 changes |
| Safe resolution auditing | `AuditResolution`, fixed state/reason enums, opaque token IDs; `tests/test_audit_resolution.py` |
| Optional transcript | Default-off collection of completed sanitized outputs, independent deep-copy snapshots; `tests/test_transcript.py` |
| Safe failures and cleanup | Static resolver errors without raw exception chains, detector-output validation, cycle rejection; `tests/test_boundary_failures.py` |
| Boundary regressions | Span conflicts, duplicates, empties, shared containers, read/write release and isolation; `tests/test_boundary_spans.py` |
| Runnable example | [Mock lifecycle](../examples/boundary_demo.py), local detection, safe stdout/stderr, offline and standalone tests; `tests/test_boundary_demo.py` |
| Documentation | [README](../README.md), [policy reference](data-release-policy.md), [scope](v0.1-scope.md), and sample-policy comments |

The baseline report preserves individual step results. It is a historical
inventory, not a line-coverage percentage. The final checks below apply to the
current complete implementation.

## Reproduction

The verified local environment uses Windows, Python 3.14.6, and the installed
`en_core_web_sm` model. See the baseline report for dependency versions.
The WindowsApps `python` alias is inaccessible in this environment, so the
explicit launcher is used. Importing spaCy required approved execution outside
the sandbox. Existing pytest cache/default temp directories had permission
issues; fresh dedicated temporary directories avoid them without changing tests.

From the repository root in PowerShell:

```powershell
$trustgatePython = Join-Path $env:LOCALAPPDATA 'Python\bin\python.exe'
$trustgateFocusedTemp = Join-Path $env:TEMP ('trustgate-day6-focused-' + [guid]::NewGuid().ToString('N'))
& $trustgatePython -m pytest tests/test_audit.py tests/test_audit_resolution.py tests/test_transcript.py tests/test_boundary_failures.py tests/test_boundary_spans.py tests/test_boundary_demo.py tests/test_person_boundary_flow.py -q -p no:cacheprovider --basetemp=$trustgateFocusedTemp
$trustgateFullTemp = Join-Path $env:TEMP ('trustgate-day6-final-' + [guid]::NewGuid().ToString('N'))
& $trustgatePython -m pytest -q -p no:cacheprovider --basetemp=$trustgateFullTemp
& $trustgatePython -m ruff check .
& $trustgatePython examples/boundary_demo.py
```

Use only a fresh dedicated path for `--basetemp`; pytest manages its contents.
On other systems with a working Python command, use `python` and normal pytest
temporary-directory defaults as shown in the README.

## Final results

| Check | Result |
| --- | --- |
| Focused Day 6 tests | 169 passed in 7.54 seconds |
| Full suite | 498 passed in 9.56 seconds |
| Ruff | All checks passed |
| Direct demo invocation | Exit 0; valid JSON; fixed lifecycle confirmations true |
| Demo output | Known sensitive fixtures absent; stderr empty |
| README Python snippets | All 3 executed successfully; captured output checked for fixture leakage |
| YAML documentation snippets | All 3 validated against `TrustPolicy` |
| Local Markdown file links | All checked targets exist |
| Sample-policy permissions | Exact existing destination/type permissions verified unchanged |
| Diff whitespace check | Passed |

The focused set is included in the full-suite count; it is not an additional
169 unique tests. Neither test run reported skipped cases or warnings. This
pass changes documentation and stale docstrings only, with no runtime behavior
or policy-permission change.

The policy reference adds the sample decision matrix, exact destination matching,
token-free argument behavior, detection limits, and the distinction between data
release and execution. The scope's standalone YAML example now includes the
required `version: 1`. README status, example commands, diagnostics, and lifecycle
descriptions match the implemented API. The baseline checklist and local
implementation plan are marked complete for Day 6.

## Acceptance limits and next work

- Detection is local English detection with documented coverage limits;
  unknown/undetected text can remain unchanged and enter an opted-in transcript.
- Audit metadata contains no raw mapping; transcript content is completed
  sanitization output, not an independent sensitivity guarantee.
- Failures return no partial result or transcript entry. Session state is
  discarded on explicit close/context exit, not rolled back per failed method.
- Read and write-style calls share release rules; the host owns execution,
  IAM, business validation, and authorization. The demo uses only mock tools.
- Safe history and caller snapshots may survive close; raw mappings are not
  persisted. Physical memory zeroization is not claimed.
- `rehydrate_for_user()` remains unavailable. No persistence, approval flow,
  distributed session, or framework integration is introduced.
- This checks the local environment, not a multi-version/platform matrix.
  Independent adversarial review, coverage assessment if configured, package
  build, clean-install smoke testing, and release consistency remain Day 7 work.
  Day 6 acceptance does not make the pre-alpha package a production release.
