# Security review follow-up

Date: 2026-10-22. Package: TrustGate 0.1.0 candidate, pre-alpha.

This report supersedes the initial [Day 7 acceptance](day7-acceptance.md).
All three reported vulnerabilities were reproduced before changing runtime
code; the first seven regression cases failed against the previous candidate.

## Fixes and compatibility

1. Cross-type intersecting spans fail closed with a fixed
   `DetectionUnavailableError`. The complete cluster is checked before any
   text tokenization, so score, length, ordering, or an allowed email policy
   cannot discard an overlapping account-number restriction. Same-type spans
   still merge; adjacent spans remain separate. Tool-result failures return
   no partial output and add no transcript entry. The existing safe
   `detection_unavailable` audit failure category is retained.
2. Presidio's `presidio-analyzer` and `decision_process` emitting loggers have
   a context-local filter during detector construction and analysis. Records
   are dropped before their own or root handlers receive them, including
   normalized DEBUG context. A `ContextVar` is reset in `finally`; logger
   levels, handlers, and unrelated threads' records are preserved. These are
   the concrete logging channels used by the supported local Presidio path;
   arbitrary host callbacks and custom detector logging remain trusted code.
3. Every vault generates an independent random UUID4 namespace, including
   when an ownership identifier is reused. Tokens now have the shared model
   and vault grammar `[TYPE_<32 lowercase hex namespace>_<positive sequence>]`.
   Old unnamespaced tokens are malformed. Tokens are opaque, copied from
   current sanitized output, and never reconstructed by the caller. An old
   process's token cannot bind to a restarted process's new mapping. No
   persistent or distributed registry or raw-value storage was added.

## Verification

- Full developer suite: **802 passed**, including real overlapping email and
  account detection, DEBUG logging before model construction, both input and
  result boundaries, dependency-owned handlers, exception cleanup, concurrent
  unrelated logging, same-type overlap, malformed namespaces, and independent
  subprocess replay for both read and write destinations.
- Statement coverage: **900/905 (99.45%)**. Branch coverage:
  **181/186 (97.31%)**. New logging, token-format, and vault code is fully
  covered; the five remaining lines/branches are in existing identity/session
  and gate paths. Coverage is test evidence, not proof of absence of defects.
- Ruff and changed-file formatting pass.
- Rebuilt sdist and wheel; full packaged suites outside the checkout and
  offline real-detector smoke checks pass in the existing isolated Windows
  AMD64 environments: Python **3.11.17** (sdist) and **3.14.6** (wheel), each
  **802 passed**. Both dependency checks pass. Dependencies and local model
  assets are unchanged from the initial acceptance environment.

Current local artifacts are `dist/release/trustgate-0.1.0.tar.gz` and
`dist/release/trustgate-0.1.0-py3-none-any.whl`. Their replacement
`dist/release/manifest.json` records hashes and verification results for this
candidate. Coverage is stored at `dist/review-security/coverage.json`.
Initial Day 7 evidence under `dist/day7` remains historical. No registry
publication, commit, or Git tag is created by this follow-up.

Detection still depends on the local English model and can miss mentions.
Mappings remain ephemeral and must be cleared through explicit session close
or context exit. All previous v0.1 scope exclusions continue to apply.
