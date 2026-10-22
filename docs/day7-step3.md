# Day 7 Step 3: identity adversarial tests

Date: 2026-10-22 (Australia/Sydney).
Starting revision: `5c4a8534f89f0cc79528d7b8e8b35e7d7d251c09`, with the
completed Steps 1-2 changes still in the working tree.
Status: complete for baseline targets I1-I2. Steps 4-6 remain open.

## Outcome

Added **86 adversarial cases** in `tests/test_adversarial_identity.py`.
The first 74-case run passed; the expanded cases and strengthened leakage
assertions also pass. No incorrect merge, retroactive promotion, canonical-value
drift, or cross-session identity transfer was reproduced by these cases.
No runtime code, public API, detector behavior, or release permissions were
changed in this step. Existing Step 2 fixes remain in the working tree.

This is evidence for the tested combinations, not proof of real-world identity
or exhaustive detection/resolution correctness.

## Attack matrix and expected behavior

| Attack group | Cases | Verified behavior |
| --- | --- | --- |
| Candidate union across observation orders and channels | 24 | All six registrations of `Jo Smith`, `Joanna Taylor`, and `Joseph Taylor`, via batched input or nested results, with transcript on/off. Exact, partial, and alias candidates coexist; ambiguous bare/alias/surname mentions remain independent. Unique partials and exact normalized full names still resolve. A reversed detector return order does not reverse textual observation order. |
| Early uncertainty followed by complete conflicting candidate sets | 12 | Both an untitled first-name mention and a titled surname remain unresolved with their original token across all six later registration orders and repeated nested results. Earlier mention metadata and serialized audit evidence remain unchanged. |
| Confirmed alias followed by two later competitors | 12 | Earlier confirmed canonical token and audit evidence stay stable; subsequent ambiguous occurrences share a distinct stable token. Read/write releases, key/value argument positions, explicit deny, and missing policy preserve the same boundary. |
| Duplicate/self-alias evidence plus conflicting identity | 12 | Duplicate normalized aliases do not create false ambiguity for one identity, nor outweigh a second identity. All six producer orders reject exact-plus-alias and partial-plus-alias ties without arbitrary selection. |
| Remaining component and near-match attacks | 10 | Middle names, surname suffixes, apostrophes, hyphens versus spaces, and a Cyrillic confusable surname are not silently equated. Both registration orders retain unique complete-component alias matches while bare aliases remain ambiguous. |
| Alias mutation, close, and fresh sessions | 2 | Mutating the caller's alias mapping/list changes only later sessions. Simultaneous sessions may resolve the same surface differently without rebinding old tokens. Closing one clears its private state and retained alias producer, leaves another usable, revokes ownership, and preserves safe history. A fresh default session inherits no custom relation. |
| Unicode/title normalization and canonical stability | 2 | Full-width names/titles and composed/decomposed accents reuse tokens without replacing the first raw canonical tool value. Nested result ownership and read/write releases are preserved. |
| Alias chains and cycles | 4 | A successfully resolved alias mention does not become a candidate source for another alias. Direct cyclic relations may later create genuine ambiguity, but never retroactively replace earlier canonical identity or its tool value. Transcript on/off has no effect on the decision. |
| Normalized custom alias union plus built-in competitors | 4 | Caller additions supplement built-ins, normalized duplicate keys union their candidates, and duplicate targets do not hide competitors. A narrower direct alias still resolves uniquely; titled singletons remain surname mentions. |
| Ambiguous full alias excluded from future candidates | 4 | Ambiguous multi-component mentions remain separate and never enter the confirmed candidate set, whether first seen in input or a nested result. Later direct aliases cannot infer identity through that uncertain surface. |

Token identifiers are taken from actual sanitized output; tests do not assume
sequence numbers. Canonical values and expected ambiguity are asserted explicitly,
without using the resolver under test to calculate expected candidates.

## Leakage and boundary assertions

- Check sanitized returns, serialized in-memory audit events, transcript
  snapshots, per-occurrence mention metadata, captured logs, and stdout/stderr
  for synthetic raw and NFKC/case-folded names. Custom alias component fixtures
  are included so an alias table cannot silently enter diagnostics.
- Approved rehydration returns only the correct first canonical value or the
  uncertain mention's own surface; neither ambiguity nor confirmed identity
  grants additional release permissions. Denials retain no exception cause or
  context and do not append transcript entries.
- Nested tool-result structures and tool-call arguments are compared with
  pre-operation copies. Previously recorded mention objects and audit JSON
  remain unchanged when later data changes the current candidate set.
- Sessions use context managers. The lifecycle test also inspects cleared
  private maps and a retained alias-producer reference, while exercising other
  sessions through public APIs. Producer-order permutations deliberately reorder
  private producers to challenge the decision path; they do not add new runtime
  extension points.

Tests use a local deterministic PERSON fixture detector to isolate resolution
from model vocabulary/NER behavior. The focused and full suites also include the
existing real Presidio/spaCy person-boundary tests. No claim of detecting every
name, proving actual identity, or treating Python private attributes as a sandbox
is introduced.

## Final validation

| Check | Result |
| --- | --- |
| Focused identity tests, including existing regressions | **308 passed in 3.10 seconds** |
| Full suite with final leakage assertions | **698 passed in 9.99 seconds** |
| Ruff | **All checks passed** |

Both final pytest runs reported no skips or warnings. The focused set is included
in the full-suite count. The suite grew from Step 2's 612 cases to 698 cases.
Approved execution outside the sandbox avoided the already documented Windows
console-handle issue; no dependency, test assertion, or runtime code was changed
to obtain these results.

Reproduce from the repository root in PowerShell:

```powershell
$trustgatePython = 'C:\Users\Lance\AppData\Local\Python\bin\python.exe'
$trustgateFocusedTemp = Join-Path $env:TEMP ('trustgate-day7-step3-focused-' + [guid]::NewGuid().ToString('N'))
& $trustgatePython -m pytest tests/test_adversarial_identity.py tests/test_entity_models.py tests/test_entity_candidates.py tests/test_entity_resolution.py tests/test_partial_name_candidates.py tests/test_partial_name_resolution.py tests/test_alias_candidates.py tests/test_alias_resolution.py tests/test_session_aliases.py tests/test_person_boundary_flow.py -q --tb=short -p no:cacheprovider --basetemp=$trustgateFocusedTemp
$trustgateFullTemp = Join-Path $env:TEMP ('trustgate-day7-step3-full-' + [guid]::NewGuid().ToString('N'))
& $trustgatePython -m pytest -q --tb=short -p no:cacheprovider --basetemp=$trustgateFullTemp
& $trustgatePython -m ruff check .
```

Use fresh dedicated temporary paths: pytest manages their contents.
See [the baseline](day7-baseline.md) for the verified environment and
[Step 2](day7-step2.md) for policy/token hardening evidence.

## Remaining work

Step 4 still owns raising audit sinks, mutated argument containers, serialization
edge cases, and explicit public vault-exclusion checks. Steps 5-6 still own
coverage assessment, package build, clean-install smoke testing, compatibility
evidence, and final release acceptance. The package remains pre-alpha.
