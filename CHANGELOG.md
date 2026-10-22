# TrustGate release notes

## 0.1.0 candidate — security review fixes, 2026-10-22

- Reject cross-type overlapping detector spans instead of selecting one type
  and losing other types' destination restrictions. Same-type overlap remains
  supported. Both input and tool-result paths fail with a safe
  `DetectionUnavailableError` without partial LLM output.
- Suppress Presidio diagnostic records within detector initialization and
  analysis, including DEBUG logs containing normalized context. Suppression is
  context-local; host levels/handlers and unrelated threads are preserved.
- Add a random 32-hex namespace per vault to tokens, preventing cross-process
  lifecycle reuse. The format is now `[TYPE_<namespace>_<sequence>]`.
  Legacy unnamespaced tokens are malformed; copy opaque tokens from current
  sanitized output rather than constructing them.
- Update examples, parsing assertions, installed smoke checks, and security
  regressions. Current validation is recorded in the
  [security review follow-up](docs/security-review-fixes.md).

## 0.1.0 — initial local acceptance, 2026-10-22

Status: pre-alpha. This records the initial documented v0.1 implementation and
completed local verification. Distribution artifacts are built locally; this
entry does not announce a registry publication or a Git release/tag.

TrustGate governs sensitive-data representation and destination-aware release.
The host application owns LLM calls, tool execution, and action authorization.

### Included behavior

- Local English sensitive-text detection using Presidio and an explicitly
  provisioned spaCy model. Missing models fail closed without runtime downloads.
- Process-local, ephemeral, session-scoped token mappings with explicit cleanup,
  stable tokens, and rejection of foreign/unknown/malformed token references.
- Strict YAML policy validation and default-deny release decisions. Each token
  needs an explicit ALLOW for its entity type and exact tool destination.
  Read and write-style destinations use the same pipeline.
- Canonical person identities with deterministic normalized-name matching,
  conservative partial/direct-alias resolution, complete candidate-set
  uniqueness, stable uncertain identities, and no retroactive merges.
- Recursive, copied tool-argument rehydration and tool-result sanitization,
  including dictionary keys, with safe collision/structure failures.
- Safe in-memory audit metadata and optional, default-off sanitized transcript
  snapshots. Raw mappings and rehydrated arguments are not recorded.
- Framework-independent mock LLM/tool demo, typed public APIs, a packaged
  `py.typed` marker, and an offline installed-distribution smoke verifier.

### Security and failure semantics finalized during acceptance

- Argument dictionary keys now receive the same token parsing, session checks,
  and release decisions as values. Rehydrated key collisions raise fixed
  `TokenResolutionError`. Literal brackets in keys also undergo token parsing.
- Policy version is strictly integer `1`; boolean/float equivalents are invalid.
  Excessive YAML recursion becomes fixed `PolicyValidationError`.
- Mutated/cyclic/unsupported argument structures raise new
  `ToolArgumentRehydrationError` and safe `unsafe_argument_structure` metadata.
  Malformed, unknown, foreign, and denied token errors keep their public types.
- Audit metadata/callback failures raise new `AuditRecordingError` without raw
  messages or retained cause/context. Failed opening clears private state;
  close clears it before its audit attempt. Other operation failures still
  require explicit close/context exit. Accepted safe events are not rolled back.
- Boundary scalars must be ordinary built-in types. Custom string/numeric
  subclasses are rejected so custom state/representations cannot escape in
  sanitized returns. Direct `sanitize()` requires a built-in `str`.
- Public `model_copy()` validates fields/updates without serializing damaged
  contents first, preventing raw serializer warnings and update-iterator errors.
- Failed boundary operations return no partial result or new transcript entry.
  No transaction rollback, automatic retry, or execution authorization is added.

Applications catching `TrustGateError` also catch the two new failure classes.
Custom sinks remain trusted host code; their independent side effects/logging
are outside the callback error wrapper's control.

### Validation and compatibility

- Full suite: **782 passed** locally, against a clean Python 3.11.17 source
  install, and against a clean Python 3.14.6 wheel install on Windows AMD64.
- Statement coverage: **99.43%**; branch coverage: **97.25%**. The five remaining
  lines/branches and the limits of this measurement are recorded in
  [the package-validation report](docs/day7-step5.md).
- Installed-package runs use Presidio 2.2.364, spaCy 3.8.16, Pydantic 2.14.1,
  PyYAML 6.0.3, and explicitly installed local `en_core_web_sm` 3.8.0 assets.
- Ruff, isolated sdist/wheel builds, archive/metadata checks, dependency checks,
  and offline real-detector read/write smoke flows pass.

The metadata requires Python 3.11+. Only the two Windows environments above
were verified; this is not an all-platform, all-version, or minimum-dependency
matrix. See [final acceptance](docs/day7-acceptance.md) for the complete evidence.

### Known limits and exclusions

Detection is English/local-model based and may miss sensitive mentions. Undetected
content remains unchanged, including in an enabled transcript. Resolution is
not real-world identity verification; uncertain tokens release only their own
original surface after ALLOW, never a guessed identity.

Raw mappings are in-memory only and lost on close/process loss. Physical memory
zeroization and arbitrary Python object/callback isolation are not claimed.
The host must sanitize every tool result and never expose a vault/session or
raw-resolution tool to the LLM.

User-response rehydration remains unavailable. Persistent/distributed state,
authentication/IAM, business or action authorization, approval workflows,
transactions/retries, UI, cloud deployment, and framework integrations are
outside v0.1. This local pre-alpha acceptance is not a third-party security
audit or a production-readiness certification.
