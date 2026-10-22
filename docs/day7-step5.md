# Day 7 Step 5: coverage, packaging, and clean installation

Date: 2026-10-22 (Australia/Sydney).
Starting revision: `5c4a8534f89f0cc79528d7b8e8b35e7d7d251c09`, with Steps 1-4
changes still in the working tree.
Status: complete. Final documentation/release acceptance remains Step 6 work.

## Changes in this step

- Added four meaningful regressions after coverage inspection: malformed JSON
  validation, non-mapping string-validation input, and two non-string result-key
  cases after an earlier item has been sanitized. Tests assert fixed exceptions,
  no raw diagnostic values, caller ownership, and session cleanup.
- Added `src/trustgate/py.typed`. The first wheel omitted this marker, so type
  checkers could not reliably recognize the installed package's inline typing.
  Final wheel and sdist content checks require it.
- Added [the installed-package smoke verifier](../scripts/release_smoke.py).
  It checks actual installed-package origin and typing metadata, then exercises
  the real local detector and full data boundary offline. It prints only a
  fixed-field safe JSON report and a fixed failure message on failure.
- No core runtime behavior, release permissions, or dependency bounds changed.
  No coverage exclusions or arbitrary percentage gate were added.

## Final checks

| Check | Result |
| --- | --- |
| Focused validation/result failure regressions | **20 passed in 1.67 seconds** |
| Full local suite with branch coverage | **782 passed in 10.95 seconds** |
| Statement coverage | **874 / 879 = 99.43%** |
| Branch coverage | **177 / 182 = 97.25%** |
| Combined line/branch coverage | **99.06%** (terminal rounded display: 99%) |
| Ruff and changed-file formatting | Passed |
| Isolated sdist build and wheel built from that sdist | Passed, `trustgate` 0.1.0 |
| Clean Python 3.14.6 wheel installation | Passed; **782 packaged tests passed in 11.51 seconds** |
| Clean Python 3.11.17 source installation | Passed; **782 packaged tests passed in 10.88 seconds** |
| Offline installed-package smoke, both environments | Passed; zero observed socket connection attempts |
| `pip check`, both environments | No broken requirements |
| Final archive contents, metadata, and installed runtime source comparison | Passed |

All final pytest runs reported no skips or warnings. These are separate runs of
the same 782 cases, not additional unique cases. The suite grew from 778 by four.
The terminal's single `Cover` percentage combines statements and branches; it
must not be reported as the statement-only percentage.

### Coverage assessment

The initial 778-case measurement was 869/879 statements and 176/182 branches.
The four added regressions cover previously untested public model-parser error
handlers and the tool-result non-string-key rejection path.

Five statement lines and their five branches remain unexecuted:

| Location at validation time | Assessment |
| --- | --- |
| `entity.py:398` | Internal person-resolution consistency guard |
| `entity.py:440` | Internal person-mention span/input consistency guard |
| `entity.py:502` | Existing-identity return in the internal exact-only helper; the session's exact resolution/canonical stability path is tested separately |
| `gate.py:26` | YAML mapping-constructor guard for a non-mapping node; the loader registers it for mapping nodes |
| `session.py:190` | Defensive root-argument type check; normally validated `ToolCall.arguments` is always a dictionary |

These were reviewed without adding synthetic implementation-mirroring tests
solely to reach 100%. Coverage still does not prove security. Three existing
excluded lines are the candidate-producer Protocol stub in `entity.py`; this
step adds no `no cover` pragmas or coverage configuration exclusions.

Raw measurement: `dist/day7/coverage.json` (local ignored artifact).

## Build and archive validation

Build tooling lives in `dist/day7/build-env`, with build 1.6.1 and isolated
hatchling 1.32.4. Global Python packages were not changed. The build frontend
first produces the source archive and then builds the wheel from that archive.

Final artifacts:

- `dist/day7/artifacts/trustgate-0.1.0-py3-none-any.whl`
- `dist/day7/artifacts/trustgate-0.1.0.tar.gz`
- `dist/day7/artifact-manifest.json` records SHA-256 hashes and content checks.

The wheel contains only the library, `py.typed`, and distribution metadata.
Its name, version, and Python requirement agree with `pyproject.toml`. Library
source bytes agree across the checkout, wheel, sdist, and both installed
environments. The source archive includes tests, examples, the smoke script,
and documentation, including the Day 7 reports.

Neither archive includes local implementation notes, pet-generation artifacts,
virtual environments, build output, coverage files, `.git`, or `.env` files.
Only package artifacts and verification metadata are written; raw token mappings
remain process-local and are never serialized into these outputs.

## Clean installation and compatibility evidence

Both environments are outside the repository, under the dedicated temporary
directory recorded in `dist/day7/release-paths.json`. They were created without
system site packages. Runtime imports resolve to each virtual environment's
`site-packages`, not the checkout or an editable installation.

| Environment | Package route | Resolved runtime dependencies |
| --- | --- | --- |
| Windows AMD64, Python 3.14.6 | Built wheel, normal dependency resolution | Presidio Analyzer/Anonymizer 2.2.364; spaCy 3.8.16; Pydantic 2.14.1; PyYAML 6.0.3 |
| Windows AMD64, Python 3.11.17 | Built sdist, isolated PEP 517 wheel build, normal dependency resolution | Same versions above |

This differs from the developer environment's spaCy 3.8.13 and Pydantic 2.13.4,
so the installed-package runs also exercise newly resolved permitted dependency
versions. No upper/lower bound was tightened merely to reuse developer packages.

Python 3.11.17 was downloaded using uv 0.13.5 into the temporary verification
directory with `--no-bin --no-registry`. It did not change PATH, the Windows
registry, default Python, or global installed packages.

The first smoke runs used the explicitly supplied local `en_core_web_sm` 3.8.0
model directory while the clean environments had no installed model package.
This verifies explicit asset configuration without sharing Python site packages.
The fixed model wheel and pytest were then explicitly installed during setup
to run all tests from the extracted source distribution in each environment.
Those tests import the installed library. Final smoke checks also work with
each environment's own installed model assets.

Network/package downloads are setup operations. During the smoke flow, socket
connection entry points are disabled, the model is already local, and a
deliberately missing model fails closed before downloading. The verifier checks:

- sanitized input and nested results reaching the mock LLM boundary;
- explicitly allowed read/write rehydration and unchanged caller arguments;
- stable person tokens and a deliberately ambiguous alias;
- default deny, an unlisted destination, and cross-session rejection;
- safe audit/transcript content, closure, and rejection after close.

The verifier uses synthetic fixtures; its leak checks are not a general detector.
Safe JSON smoke reports are stored in `dist/day7/smoke-wheel.json` and
`dist/day7/smoke-sdist.json`. Environment package-version inventories are kept
alongside them. These local artifacts contain no token vault or raw mappings.

### Reproduction

From the repository root, using the verified developer launcher:

```powershell
$trustgatePython = 'C:\Users\Lance\AppData\Local\Python\bin\python.exe'
$trustgateTestTemp = Join-Path $env:TEMP ('trustgate-day7-coverage-' + [guid]::NewGuid().ToString('N'))
& $trustgatePython -m pytest -q --tb=short -p no:cacheprovider --basetemp=$trustgateTestTemp --cov=trustgate --cov-branch --cov-report=term-missing --cov-report=json:dist/day7/coverage.json
& $trustgatePython -m ruff check .
& $trustgatePython -m venv dist/day7/build-env
& '.\dist\day7\build-env\Scripts\python.exe' -m pip install build
& '.\dist\day7\build-env\Scripts\python.exe' -m build --outdir dist/day7/artifacts
```

For a new verification environment, install the artifact normally, with its
dependencies, rather than using an editable install or system site packages.
Run from a directory outside this repository:

```powershell
& $trustgateCleanPython -m pip install $trustgateArtifact
& $trustgateCleanPython -m pip check
& $trustgateCleanPython -I $trustgateSmokeScript --model-path $trustgateLocalModelDirectory
```

The four variables in the last example must be absolute paths to the clean
virtual-environment interpreter, wheel/sdist, `scripts/release_smoke.py`, and
local spaCy model data directory respectively. Use fresh dedicated test temp
paths: pytest manages their contents. To reproduce the installed-package full
suite, explicitly install pytest and the fixed model package during setup,
extract the sdist into another temporary directory, change to that directory,
and run that environment's interpreter with `-I -m pytest`.

## Limits and next step

This establishes Windows AMD64 evidence for Python 3.11.17 and 3.14.6. It does
not establish every Python patch/minor version or Linux/macOS compatibility,
and it is not a dependency-minimum-version test matrix. Installation needs the
declared dependencies and an explicitly provisioned local English model for
real detection. The model is not bundled into TrustGate's wheel.

The package remains 0.1.0/pre-alpha. Final README/scope/version/release-note
consistency and release acceptance are Step 6 work. No registry upload, release
tag, persistent mapping store, or framework integration is part of this step.
