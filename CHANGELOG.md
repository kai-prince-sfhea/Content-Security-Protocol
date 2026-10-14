# Changelog

## Unreleased documentation review — 14 October 2026

- Distinguish native CLI version presentation from the exact installed manifest
  version and audit runtime identity. Runtime, metadata and stored contracts are
  unchanged; no new supported-release or accessibility claim is made.

## 0.0.4 — experimental source update, 13 October 2026

- Reject publication paths with empty components; preserve the HTML limit when
  an internal caller overrides only some inventory limits.
- Bound Deno native inspection by time and stdout/stderr bytes, with redacted
  failures and owned-child cleanup.
- Bind CLI output selection to the current receipt; refuse irrelevant reset flags.
- Refuse oversized report JSON before committing an unreadable generation.
- Reuse shared-asset digests within each audit, discard file bodies on digest-only
  scans and skip text decoding when no publication markers are configured.
  Preserve both full content-hashing scans and per-reference SRI decisions.
- Add regression challenges and a retained synthetic baseline/candidate benchmark;
  native rendering, browser checks and accessibility retain separate evidence.

## 0.0.3 — local experimental audit and assurance core

- Add pending/failed/disabled state and immutable report generations, with atomic
  current receipt and exact source/configuration/runtime/output freshness checks.
- Preserve pre-render requested inputs when native post-render lists are absent;
  report changed unrendered/removed sources without promising recomputation.
- Add installed-only audit/status/headers/accessibility/compare/findings/exceptions/
  crypto/clear-current commands, a structural options schema and private output
  path/marker findings. Standalone explicit audit works with network denied.
- Prepare bounded Netlify header candidates without deployment. Enforcement
  refuses known violations and requires exact-snapshot uncertainty review.
- Add pinned native axe orchestration on a private copy; preserve its violation-
  only uncertainty gap as needs review rather than a conformance pass.
- Correct base-URL authorization, SRI ASCII whitespace/options/strongest hashes,
  stronger declared CSP digests and unsupported IP source handling.
- Add native format/preview, actual localhost CSP/SRI and browser-parser evidence;
  retain human accessibility, actual hosting and later crypto/runtime gates.

## 0.0.2 — local experimental SEC-0 development

- Replace the active prototype rewrite pipeline with an opt-in metadata
  post-render audit; preserve project type and existing hooks.
- Inventory final file bytes and structured HTML, separate declared policy from
  candidate inline hashes/SRI and unknown dynamic capabilities.
- Store deterministic JSON/Markdown outside published output; reject unsupported
  configuration and linked/outside paths without echoing rejected values.
- No enforcement, nonce generation, HTML rewriting, security scoring or automatic
  origin approval. Old prototype features require deliberate migration.

## 0.0.1 — original prototype

Historical partial pipeline at db847ea99b1ed55bec63fe825700e331365a7058.
Its generated artifacts and README feature claims were not acceptance evidence.
