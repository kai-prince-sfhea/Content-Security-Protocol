# Content Security Protocol

Experimental **0.0.4**. Publication assurance for Quarto:
a read-only audit, explicit host-header preparation and optional accessibility
checking. It inventories final files, proposes static inline hashes
and local SRI values, and compares discovered resource origins with an explicit
declared Content Security **Policy**. The repository retains its original name.

Ordinary auditing installs no CSP, changes no HTML/assets, fetches no remote
resources and assigns no security score. Optional accessibility checking executes
trusted page code on a private copy. No tool establishes that a website is secure.

## Install and enable

Use Quarto **1.11.5 prerelease** for the tested workflow. From an existing Quarto
website, install the extension from GitHub:

```sh
quarto add kai-prince-sfhea/Content-Security-Protocol --no-prompt
```

Add to the project's `_quarto.yml`:

```yaml
content-security-protocol:
  enabled: true
```

Then use normal `quarto render`. The installed metadata extension supplies its
pre/post-render hooks automatically; keep your existing project type, theme, filters
and hooks. Do not register the old Lua stages or copy hook paths into your YAML.
Installing the extension without explicit activation performs no audit/report
write, although its hook inspects the effective project configuration.

To try the shipped synthetic example, open a terminal in this repository's
checkout and run `quarto render`. Its [_quarto.yml](_quarto.yml) renders only
[example.qmd](example.qmd); no separate template setup is required. Installing
into an existing website copies the runtime under `_extensions`, not these
root-level example files. This follows Quarto's
[extension distribution layout](https://quarto.org/docs/extensions/distributing.html).

### Installation namespaces

The repository name selects the download; the lowercase installed extension ID
selects the command path and removal target. Confirm the installed version and
namespace using `quarto list extensions` before following any update instructions.

| Installation | Installed extension ID | CLI path |
| --- | --- | --- |
| GitHub | `kai-prince-sfhea/content-security-protocol` | `_extensions/kai-prince-sfhea/content-security-protocol/cli.ts` |
| Local directory | `content-security-protocol` | `_extensions/content-security-protocol/cli.ts` |

Every CLI example below uses the **GitHub** path. To install a local checkout
instead, run `quarto add "C:/path/to/content-security-protocol" --no-prompt`
and omit the owner directory from subsequent CLI paths. The
`content-security-protocol` metadata namespace stays the same. Install one copy
only: duplicate installed copies are refused. See Quarto's official
[managing extensions guide](https://quarto.org/docs/extensions/managing.html)
for installation, listing, update and removal conventions.

Reports are **private build material**. Use the installed command interface:

```sh
quarto run _extensions/kai-prince-sfhea/content-security-protocol/cli.ts status
quarto run _extensions/kai-prince-sfhea/content-security-protocol/cli.ts audit
```

`audit` is useful after all output-changing hooks. `status` checks exact output,
declared source/configuration and runtime identities. Installation supplies
pre/post hooks automatically; ordinary renders invalidate old status before work
and publish a new generation only after the audit completes.

- `.quarto/content-security-protocol/status.json`: pending, complete, failed,
  disabled or cleared state.
- `.quarto/content-security-protocol/current.json`: authoritative receipt binding
  an immutable generation's JSON/Markdown hashes and its source/runtime snapshot.
- `.quarto/content-security-protocol/generations/<id>/report.json` and `report.md`:
  machine findings and human summary. Historical generations remain available.


They contain output paths, origins and hashes. They omit raw inline bodies and
URL credentials/query/fragment. Review before sharing; these omissions do not
make a report public-safe or a personal-data scan. Keep `.quarto` out of published
resources. A disabled, failed or interrupted build leaves history available but
does not claim a current result. Changes made after this hook are detected by
`status`; run `audit` after those changes. Invalid native configuration can fail
before hooks run, so explicit status verification remains necessary.

## Options and policy authority

Configuration is project-level only. Page/directory/format metadata does not
select a separate security policy, including document `--metadata-file` values.
Quarto resolves project/profile configuration before this extension reads it.
In the tested 1.11.5 version, repeated policy source lists are appended across
project/profile layers: a profile list cannot remove a permission already in the
shared project list. Keep varying policy lists out of the shared `_quarto.yml`,
and put them in each selected profile. Inspect the result with `quarto inspect`
before auditing. A profile's `enabled: false` disables the project audit; page
metadata cannot activate a disabled project. Use the same profile for subsequent
status/derived commands, for example by selecting `QUARTO_PROFILE`. See
[Quarto profiles](https://quarto.org/docs/projects/profiles.html).

| Option | Default | Meaning |
| --- | --- | --- |
| `enabled` | absent/inactive | Explicit `true` activates; `false` bypasses other options. |
| `mode` | `audit` | Only audit is implemented. Enforcement/report-only delivery is refused. |
| `policy` | documented restrictive baseline | Replace specified directive lists. Discovery never adds permissions. |
| `fail-on` | `none` | `known` fails on known static violations; `any` fails on any finding. Neither means complete security coverage. |
| `publication.forbidden-markers` | `[]` | Up to 64 private text markers; reports identify marker indices, never the marker itself. |
| `publication.forbidden-paths` | `[]` | Exact relative files or trailing-slash prefixes to flag in output; no empty components, wildcards or traversal. |

Copied source notebooks/QMD, private/state/Git/extension paths and `.env` files
are flagged by default. Marker scanning covers raw final file text; compressed
archives, image/audio/OCR content and unknown private facts require other review.
See the installed `config-v1.schema.json` for structural editor validation;
runtime additionally checks canonical origins, digest lengths and path semantics.

The baseline is `default-src 'none'`, `base-uri 'none'`, `object-src 'none'`,
`frame-ancestors 'none'`, `form-action 'none'`, `connect-src 'none'`,
`frame-src 'none'`, `worker-src 'none'`; scripts, styles, images, fonts, media
and manifests permit `'self'`. **This is an undelivered comparison baseline, not
a promise that native interactive features would work under enforcement.**

For example, separately approve one required HTTPS origin:

```yaml
content-security-protocol:
  enabled: true
  mode: audit
  policy:
    script-src: ["'self'", "https://approved.example"]
```

Use a sequence for each directive. Supported sources are `'self'`, `'none'`,
canonical HTTPS DNS origins and valid SHA-256/384/512 digest tokens for `script-src`
and `style-src`. `data:`/`blob:`
are admitted only for the documented non-script resource directives. Wildcards,
unsafe execution keywords, nonce delivery, arbitrary paths/credentials and
unimplemented directives are refused. `none` must be the sole source.

Supported directives: `default-src`, `base-uri`, `object-src`, `frame-ancestors`,
`form-action`, `script-src`, `style-src`, `img-src`, `font-src`, `media-src`,
`connect-src`, `frame-src`, `worker-src`, `manifest-src`. This bounded subset
is not a complete CSP language validator or a browser policy evaluator. HTTPS IP
source expressions are outside this subset. External-resource authorization is
an origin-only comparison; external CSP hash/SRI authorization is not modeled.

Inline hashes are computed from UTF-8 browser-parsed script/style text, including
HTML newline normalization. Whole-file digests and SRI use raw file bytes.
JSON/JSON-LD script data receives no executable approval hash. Import maps,
speculation rules, dynamic JavaScript/CSS dependencies, frames, forms, base URLs,
responsive sources and foreign content remain explicit unassessed findings.
Existing SRI is compared with local bytes using its strongest recognized digest;
no integrity attributes are injected and external bytes are never fetched.

## Coverage and limitations

Every audit re-enumerates the retained output tree, so changed assets and actual
file removals are reflected without an incremental cache. Retained stale pages
are still inventory entries: a partial render does not prove a complete rebuild
of current sources. Pre-render requested inputs are preserved when native
post-render input lists are unavailable; they are request evidence, not proof of
recomputation. Changed unrendered or removed declared sources are observations.
Transitive/generated dependencies remain unassessed. Empty HTML inventory is
incomplete, not a pass. Shared-asset digests are reused only within one audit's
in-memory snapshot. Both full output scans still read and hash every file; there
is no persistent cache or reliance on file timestamps. Digest-only freshness
scans discard file bodies, and text decoding for publication markers runs only
when markers are configured. A generation's pair is immutable and one atomic receipt
selects it; the status command also checks freshness after later hooks run.

The output directory must be a separate directory within the project. Root,
outside, `.quarto`, `.git`, `_extensions`, linked files/directories and linked
report destinations are refused. Limits: 5,000 files, 128 MiB total, 32 MiB per
file, 8 MiB per HTML page, 5,000 directories and depth 64. Generated report JSON
must also fit the 8 MiB state-reader limit; excessive findings stop publication
without truncating findings or marking an unreadable generation complete.
Native configuration inspection has a 30-second deadline and a 16 MiB limit on
each captured output stream. UTF-8 HTML is required. This assumes a trusted local
build tree and no concurrent writers; it is not an OS filesystem sandbox.

Tested target: Windows, Quarto **1.11.5 prerelease**, HTML website/book/manuscript
projects and installed-only operation. Native DOCX projects receive asset
inventory only and an incomplete HTML assessment. Unconfigured standalone HTML
remains a no-op. Explicit standalone audit uses a contained output directory and
JSON options; it also runs with Deno network denial. Native QMD preview/watch is
tested separately. Arbitrary Unicode paths, Reveal/dashboard behavior and other
platforms remain unverified.
A manifest constraint is not evidence for all accepted later versions.

## Hosting and accessibility

Prepare a private Netlify candidate without installing or deploying it:

```sh
quarto run _extensions/kai-prince-sfhea/content-security-protocol/cli.ts headers
```

The default is report-only. The artifact is
`.quarto/content-security-protocol/headers-netlify.txt`. Existing `_headers`,
`_redirects` or `netlify.toml` configurations are conflicts requiring manual
reconciliation. Only bounded ASCII static routes/index aliases are supported;
functions, proxies, rewrites, custom 404 fallback and actual Netlify delivery are
outside this adapter's verification. Header-only controls remain header-only.

`headers --mode enforce` refuses known violations and unapproved hashes/resources.
Named uncertainty acknowledgements require `--review review.json` containing
`{"inventoryDigest":"<current digest>","codes":["script-behavior-unassessed"]}`.
Acknowledgements are explicit permission for those uncertainties on that exact
snapshot, not proof or permission to waive private output/known violations.
Only the uncertainty codes listed by `--help` are eligible. Discovery never adds approvals.
Synthetic localhost checks exercise real enforced/report-only response headers,
approved and blocked scripts and SRI; they do not establish production hosting
or compatibility of every native interactive widget with an enforced policy.

Run optional native accessibility checking only on trusted HTML:

```sh
quarto run _extensions/kai-prince-sfhea/content-security-protocol/cli.ts accessibility --execute-pages
```

This requires Quarto **1.11.5** and an installed supported Chromium browser.
Quarto can use `QUARTO_CHROMIUM` to select one; ordinary audit does not need a
browser. The command scans a private hash-bound copy at desktop/narrow viewports
and discovered light/dark modes. It executes page JavaScript, which may access
external resources; it is not a network sandbox. Raw cells/logs remain private.
The native scanner reports violations only, omitting uncertain/pass checks.
The adapter therefore always records `native-uncertain-checks-not-reported` as
needs review; zero violations never becomes a conformance pass. Exit 1 means
violations, 2 incomplete, 3 needs review. WCAG 2.2 AA tags are classified separately
from other native rules. Keyboard/screen-reader/math speech, dynamic states and
Word/PDF accessibility still require their own evaluation.

## Comparison, review and cryptographic readiness

```sh
quarto run _extensions/kai-prince-sfhea/content-security-protocol/cli.ts compare --previous previous-audit.json
quarto run _extensions/kai-prince-sfhea/content-security-protocol/cli.ts findings
quarto run _extensions/kai-prince-sfhea/content-security-protocol/cli.ts crypto
quarto run _extensions/kai-prince-sfhea/content-security-protocol/cli.ts clear-current
```

Comparison requires matching schema, runtime/version, policy and coverage and reports added,
resolved and unchanged finding IDs. IDs reflect versioned static element order,
not semantic identity. `exceptions --exceptions exceptions.json --as-of YYYY-MM-DD`
accepts `content-security-protocol-exceptions/v1` with entries `{id,reason,expires}`.
Only exact existing IDs are annotated; expiry is explicit, original findings stay
visible and exceptions do not authorize an enforced policy. Derived files are
private append-only artifacts. `clear-current` invalidates status and retains
every historical generation; a subsequent audit reconstructs current state.

`crypto` inventories SHA-256/384/512 uses and the boundary between digest identity,
authenticity, TLS, signatures and post-quantum provider readiness. It references
ML-KEM/ML-DSA/SLH-DSA standards without implementing cryptography or claiming
that browser code upgrades hosting TLS. Trusted Types, response-time nonces,
dynamic native-runtime adapters, collectors, signatures and deployment remain
separately scoped experiments.

For a nonproject output tree use `audit --root <dir> --output-dir <subdir>
--config options.json`, with JSON extension options such as `{"enabled":true}`.
Use `--help` for command-specific options. Commands return completion/freshness
status, not certification of the website. An output directory supplied to status
or a derived command must match the current receipt; a mismatch is stale rather
than silently selecting a different tree. `clear-current` accepts only `--root`.

## Disable, update and remove

Set `content-security-protocol: {enabled: false}` to disable audit writes. For a
GitHub installation, update or remove the extension with:

```sh
quarto update extension kai-prince-sfhea/Content-Security-Protocol --no-prompt
quarto remove kai-prince-sfhea/content-security-protocol --no-prompt
```

When removing, also remove the metadata setting. For a local directory
installation, use `quarto remove content-security-protocol --no-prompt` instead.
User content and prior private reports remain yours; the latter must not be
treated as current.

For a local development update use
`quarto update extension "C:/path/to/content-security-protocol" --no-prompt`.
These experimental 0.x versions do not promise a stable API, CLI or stored-data
contract. Versions use semantic-version syntax; changes and migration boundaries
are recorded in [CHANGELOG.md](CHANGELOG.md), and breaking stored-contract changes
require an appropriate schema identifier change. Check that record before an
update rather than assuming every 0.x update is interchangeable.

Updating from 0.0.3 to 0.0.4 changes the runtime identity, so an earlier current
receipt becomes stale. Run a fresh `audit` with 0.0.4 and review its findings.
Historical reports remain immutable; the extension neither rewrites nor migrates
them automatically. Matching schema names alone do not authorize comparisons:
`compare` also requires matching runtime/version, policy and coverage, so a
0.0.3 report cannot be used for a direct 0.0.4 finding comparison.

The earlier prototype's `content-security-policy`, `csp_protocol`, hash/nonce,
rewriting, dynamic-style, scoring and automatic origin options are not activated
by this version. Migrate deliberately; no compatibility with its generated
`CSP.json` or `headers.txt` is claimed. Remove old manually registered Lua hooks.

| Prototype capability | 0.0.4 treatment |
| --- | --- |
| Automatic jsDelivr/Google Fonts/cdnjs or additional source flags | Replace with explicitly declared directive lists; no automatic domain approval. |
| Hash/prefer-hash toggles | Always compute candidates; only author-declared hashes grant comparison approval. |
| SRI injection/disable toggle | Read-only local candidates/comparison; no attribute rewriting. |
| Event extraction, style auto-nonce, strict-dynamic and static nonces | Retired automatic transformations; findings and fail-closed candidate preparation. |
| Worker/blob/dev WebSocket relaxations | Explicit supported policy sources only; unsupported runtime mechanisms stay unassessed. |
| Numeric scores and union/intersection headers | Retired; counts, per-page findings and versioned comparisons replace them. |
| Trusted Types, reporting endpoints, common HSTS/permissions/header bundle | Deferred to separately tested sink/host/privacy adapters; old options are refused. |
| Schema directory coupling and generated reports | Replaced by an independent output inventory and private immutable generations. |

## Dependencies, rights and AI transparency

Project code is licensed under [Apache License 2.0](LICENSE), with attribution
and assistance details in [NOTICE](NOTICE). Bundled third-party components retain
their original licence terms; Apache-2.0 does not replace those terms or authorize
publishing audited content, private reports or third-party resources.

Consumers use Quarto's bundled Deno runtime; npm and Node are not required for
ordinary rendering. The local HTML parser bundle contains **parse5 8.0.0 (MIT)**
and **entities 6.0.1 (BSD-2-Clause)**, with original licence texts under `vendor`.
It introduces no browser asset or remote module import. These are libraries,
not embedded Quarto extensions. No model, AI service or report collector runs.

Kai Prince set the aims, architectural direction and requested refinements.
[OpenAI Codex](https://openai.com/codex/) materially assisted planning,
research synthesis, redesign, implementation, performance changes, tests,
synthetic fixtures, expected results and documentation. AI assistance therefore
extends to the evidence used to evaluate this code. Automated checks and
AI-assisted reviews are not independent human review, proof of security or
accessibility conformance, or institutional approval. The maintainer remains
responsible for reviewing the code, primary sources, rights and reported results
before accepting or publishing a capability. Synthetic examples are test
material, not evidence of real-site or human acceptance.

For University of Manchester work, apply the relevant
[University AI Guidelines](https://www.staffnet.manchester.ac.uk/ai-hub/ai-guidelines-and-policies/ai-guidelines-overview/guidelines/)
and the applicable teaching, research, data-handling and approved-tool policies.
Declare material assistance, retain appropriate records and check outputs against
primary sources. Permission depends on the material, tool and context; this
disclosure and local processing do not establish University approval or permission
to send confidential, personal or unpublished material to an external AI service.

Developer tests, pinned build dependencies, fixtures and raw receipts live in a
separate developer workspace, outside the installed package. The full internal
suite cannot be reconstructed from this source folder alone. Licence and third-
party notices govern code reuse; they do not authorize publishing audited
content, private reports or third-party resources.

For a public [GitHub issue](https://github.com/kai-prince-sfhea/Content-Security-Protocol/issues),
provide the extension/Quarto versions and a minimal synthetic reproduction.
Do not attach private `.quarto` reports, credentials, confidential site content
or identifying URLs. Report paths, origins and hashes can themselves disclose
information; remove sensitive context before sharing an issue or diagnostic.
