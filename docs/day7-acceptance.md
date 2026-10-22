# TrustGate v0.1 final local acceptance

Date: 2026-10-22 (Australia/Sydney).
Package: `trustgate` **0.1.0**, development status **pre-alpha**.
Baseline revision: `5c4a8534f89f0cc79528d7b8e8b35e7d7d251c09`.

**Status: passed for the documented local v0.1 scope.** All six Day 7 steps
are complete. Acceptance applies to the reviewed working-tree contents and
locally built artifacts; it does not identify a newly created commit or tag.

## Accepted implementation

TrustGate provides a framework-independent, local English sensitive-text
boundary with ephemeral session mappings, explicit destination-aware ALLOW/DENY
decisions, conservative person resolution, safe diagnostic metadata, and
default-off sanitized transcript snapshots. Read and write-style tools share
the same data-release pipeline. The host owns execution and authorization.

| Day 7 step | Evidence |
| --- | --- |
| 1. Baseline and API/invariant inventory | [Baseline](day7-baseline.md); initial full suite 498 passed |
| 2. Policy/token adversarial tests and fixes | [Step 2](day7-step2.md); 114 added cases; full suite 612 passed |
| 3. Entity mismerge adversarial tests | [Step 3](day7-step3.md); 86 added cases; full suite 698 passed; no runtime defect reproduced in those combinations |
| 4. Output/diagnostic adversarial tests and fixes | [Step 4](day7-step4.md); 80 added cases; full suite 778 passed |
| 5. Coverage, builds, clean installation | [Step 5](day7-step5.md); 4 added cases; full suite 782 passed in developer and two clean installed environments |
| 6. Documentation/release consistency and final artifact verification | This report, [release notes](../CHANGELOG.md), final documentation checks, and final artifact manifests |

Step 6 changes documentation only. Runtime checks from Step 5 remain applicable:
the final candidate's library source and typing marker are byte-identical to
the tested Step 5 artifacts. Documentation/metadata are rebuilt and reinstalled;
offline smoke and dependency checks are repeated on those exact final artifacts.

## Security-invariant acceptance evidence

| Requirement | Representative passing evidence |
| --- | --- |
| Detected raw values do not reach LLM-visible sanitized returns | `test_sanitization.py`, `test_tool_result_sanitization.py`, `test_person_boundary_flow.py`, `test_boundary_demo.py`, scalar-object attacks in `test_adversarial_diagnostics.py` |
| Tool rehydration requires explicit destination ALLOW | `test_policy_decisions.py`, `test_rehydration.py`, `test_adversarial_tokens.py`; read/write and key/value cases |
| Missing/malformed policy denies by default | `test_policy_loading.py`, `test_policy_models.py`, `test_adversarial_policy.py`; malformed YAML, duplicate/merge keys, strict version type, construction paths |
| Token mappings cannot resolve across sessions | `test_session_vault.py`, `test_adversarial_tokens.py`, `test_adversarial_identity.py`; replay, close, simultaneous/fresh sessions |
| Tool results cross the sanitization boundary before mock LLM exposure | `test_boundary_demo.py`, `test_person_boundary_flow.py`; nested keys/values, copied results, plain-data payload assertions |
| Generated diagnostics and wrapped boundary exceptions omit raw values | `test_audit_resolution.py`, `test_boundary_failures.py`, `test_adversarial_diagnostics.py`, `test_adversarial_model_copy.py`; JSON, warnings, logs, stdout/stderr, exception args/chains and ordinary tracebacks |
| No direct vault capability is given to the LLM | `test_public_api.py` export/session-surface checks and `test_boundary_demo.py` plain-data checks at both LLM boundaries |

Conservative identity tests separately cover complete candidate unions,
observation/producer order, exact/partial/alias conflicts, stable uncertain
tokens, immutable canonical values, direct-only aliases, caller mutation,
and no retroactive promotion. These tests do not prove real-world identity.

## Verified results

| Check | Result and provenance |
| --- | --- |
| Developer full suite with coverage | **782 passed**, Step 5 |
| Clean Python 3.14.6 wheel full suite | **782 passed**, packaged tests outside checkout, Step 5 |
| Clean Python 3.11.17 source full suite | **782 passed**, packaged tests outside checkout, Step 5 |
| Statement / branch coverage | **99.43% / 97.25%**, Step 5; five remaining lines/branches assessed there |
| README Python examples | All three executed in document order with local detection; safe output and closed-session checks |
| YAML documentation examples | README, scope, and policy-reference examples validated with the actual policy loader |
| Sample policy | Same validated permissions as baseline HEAD; exact decision matrix checked |
| Documentation links, fences, whitespace | Checked across repository Markdown and local implementation plan |
| Version and status | `pyproject.toml`, release notes, README, scope, artifact metadata agree on 0.1.0/pre-alpha |
| Ruff and formatting | Passed for changed Python files; no runtime edits in Step 6 |
| Final isolated sdist/wheel build | Passed; wheel built from the source archive |
| Final content/metadata/source comparison | Passed; package bytes match checkout, Step 5 runtime, both archives, and installed copies |
| Final installed offline smoke and `pip check` | Passed for both clean environments |

The same 782 tests run in each environment; counts are not additive. This
documentation-only step reuses passing runtime evidence and does not rerun
the full suite simply to change Markdown. Final archive and metadata changes
are checked through rebuilding, reinstalling, byte comparison, and real-detector
smoke execution.

## Final candidate and reproducibility

Final deliverables are local ignored build artifacts:

- `dist/release/trustgate-0.1.0-py3-none-any.whl`
- `dist/release/trustgate-0.1.0.tar.gz`
- `dist/release/manifest.json`: final SHA-256 hashes, content/metadata checks,
  runtime comparison, and installed-environment results
- `dist/release/documentation-check.json`: documentation verification summary
- `dist/release/smoke-wheel.json` and `smoke-sdist.json`: final safe smoke reports

Step 5's artifacts and evidence remain separately under `dist/day7` so their
historical hashes are not overwritten by final documentation changes.
Both source archives contain the tests/examples/docs and release smoke script;
wheels contain only library files, `py.typed`, and metadata. Local notes,
environment/build output, coverage data, pet artifacts, and `.git`/`.env` files
are excluded. No token mappings are written into release evidence.

Rebuild from the repository root with the already provisioned build environment:

```powershell
& '.\dist\day7\build-env\Scripts\python.exe' -m build --outdir dist/release
```

See [Step 5](day7-step5.md) for full-suite/coverage, fresh-environment setup,
normal artifact installation, explicit local-model configuration, and the
`python -I scripts/release_smoke.py --model-path ...` verification procedure.
The verifier accepts absolute paths when invoked from outside the checkout.

## Acceptance boundaries

- **Pre-alpha, local acceptance:** no claim of a third-party audit, universal
  disclosure prevention, or production readiness. No registry upload or Git
  release/tag is performed by this acceptance step.
- **Compatibility:** Windows AMD64, Python 3.11.17 and 3.14.6. Installed-package
  evidence uses Presidio 2.2.364, spaCy 3.8.16, Pydantic 2.14.1, PyYAML 6.0.3,
  and local `en_core_web_sm` 3.8.0. Other platforms/versions and dependency-minimum
  combinations are unverified. Model assets are provisioned separately.
- **Detection:** undetected text remains unchanged and may enter an opted-in
  transcript. Resolution operates only on detected PERSON spans and never
  proves a person's actual identity.
- **Host responsibility:** every LLM-facing result must pass sanitization;
  vault/session/raw-resolution capabilities must not be exposed. Policy does
  not authorize execution, and arbitrary trusted Python callbacks/introspection
  are not sandboxed.
- **Lifecycle:** failures return no partial output but do not generally roll
  back private state or close an explicitly managed session. Failed opening
  clears state, and close clears before audit. Accepted safe audit events are
  not rolled back. Physical memory zeroization is not guaranteed.
- **v0.1 exclusions:** user-response rehydration, persistent/distributed state,
  authentication/IAM, business/action authorization, approval flows, retries,
  transactions, UI, cloud deployment, and framework coupling remain outside
  the accepted scope.

No reproduced security defect remains unresolved within the accepted test scope.
The seven-day v0.1 implementation plan is complete at this local acceptance
boundary; broader compatibility, external integration, and publication are
separate future work.
