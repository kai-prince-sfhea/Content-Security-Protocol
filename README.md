# Content Security Protocol

Experimental **0.0.7**. Publication assurance for Quarto:
a read-only audit, explicit host-header preparation and optional accessibility
checking. It inventories final files, proposes static inline hashes
and local SRI values, and compares discovered resource origins with an explicit
declared Content Security **Policy**. The repository retains its original name.

Ordinary auditing installs no CSP, changes no HTML/assets, fetches no remote
resources and assigns no security score. Optional accessibility checking executes
trusted page code on a private copy. No tool establishes that a website is secure.

## Install and enable

The GitHub command below follows the experimental `main` branch, including the
`report` command, composition-finalisation, prepared-model-pack integration,
explicit browser-state command and Cloudflare Pages header preparation.
This is development source, not a supported tagged release. A local-checkout
installation is also described below.

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

This is enough for a first audit. Render your existing project with the editor's
**Render Project** control or `quarto render`; no policy editing is required.

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
selects the command path and removal target. Confirm the installed namespace
using `quarto list extensions` before following any update instructions. Its
version column is native CLI presentation, not exact prerelease identity. For
the exact version, inspect the installed `_extension.yml` at the namespace below;
the audit's runtime identity additionally binds the installed runtime files.

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
quarto run _extensions/kai-prince-sfhea/content-security-protocol/cli.ts report
quarto run _extensions/kai-prince-sfhea/content-security-protocol/cli.ts audit
```

`audit` is useful after all output-changing hooks. `status` checks exact output,
declared source/configuration and runtime identities. Installation supplies
pre/post hooks automatically; ordinary renders invalidate old status before work
and publish a new generation only after the audit completes.

For ordinary author use, enable the extension, render your project, then use
`report` to read the current audit as Markdown. It checks the same freshness and
integrity as `status`, writes no new file and refuses stale results. To save a
private copy, append `> ../audit-report.md` to that command **only when the parent
is a private folder outside your published project**, or select an explicit
private destination. Keep running the command from the project folder. The
immutable `report.md` below can also be opened in your
editor. Neither a saved copy nor a historical generation establishes current
status after later edits.

The [example.qmd tutorial](example.qmd) guides the first audit, reading its
private report, editing a page and rerendering. This README contains the full
options, policy, companion-extension, hosting and accessibility references.

### Choose what to configure

| Your task | Author action |
| --- | --- |
| Start auditing an existing site | Set `enabled: true`; keep normal Render/Preview. |
| Read the latest verified findings | Run the installed `report` command above. |
| Check accessibility | Follow [hosting and accessibility](#hosting-and-accessibility); the explicit command executes trusted rendered page code. |
| Compare your intended hosting policy | Set `policy` in project YAML; discovery does not grant permissions. |
| Prepare headers for a host | Use the separate reviewed header preparation workflow below; ordinary render does not install a policy. |

This extension adds no reader interface or theme. Continue styling your site
with Quarto's `format.html.theme` / `css`; every final asset is still audited.
Keep security policy options at project/profile level, rather than repeating
them in individual pages.
Private generated reports and diagnostics currently use English; page `lang`
does not translate them.

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

## Behaviour alongside the other extensions

With Knowledge Graph Extraction's composition finalizer enabled, the ordinary
render audits **after** the graph publisher finishes. This includes its separate
named graph pages, the CV graph navigator added to Interactive CV pages and the
public graph entries added to website search. Keep using the same QMD/YAML and
normal Quarto Render or Preview; no audit script or manual hook ordering is
required for this combination.

The extensions bind the pending audit to the current render's graph run. If the
security hook runs first, its report stays pending until graph publication
finishes; if it runs later, it audits immediately. An interrupted graph build,
an obsolete marker or a disabled extension cannot certify a new current audit.
The private `.quarto/content-security-protocol/deferred-composition.json` marker
is temporary build state, never a website resource. This integration requires
Knowledge Graph Extraction 0.0.9's composition-finalizer support; older
copies still require the explicit `audit` command after graph output changes.

Accessible Maths, Maths Knowledge Graph, Local AI Websites, Generative Websites,
Interactive CV and citation features are assessed through their **rendered
bytes**, without installing extra copies, running an AI model or widening the
declared policy. Graph iframes, browser workers, model origins and interactive
scripts may produce policy findings. Review these against the features you
intend to enable; discovery never grants a permission automatically. An audit
is separate from optional accessibility execution and human accessibility review.

Other custom post-render hooks can still change output after the final graph
and audit stages. In that case `status` detects the change; run the explicit
`audit` command after your final custom hook or finished build.

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
| `prepared-model-packs` | `[]` | Explicit relative `models.json` paths for Local AI Websites' prepared, published packs. Allows bounded streamed model/WASM auditing; no directory exemption or automatic download. |

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
and `style-src`. The explicit `'wasm-unsafe-eval'` token is accepted **only in
`script-src`**. It permits WebAssembly compilation; it does not permit JavaScript
string evaluation. Broad `'unsafe-eval'` and `'unsafe-inline'` remain refused.
`data:`/`blob:` are admitted only for the documented non-script resource
directives. Wildcards, nonce delivery, arbitrary paths/credentials and
unimplemented directives are refused. `none` must be the sole source.

If you intend a selected browser runtime to compile WebAssembly, declare that
choice in ordinary project YAML:

```yaml
content-security-protocol:
  enabled: true
  policy:
    script-src: ["'self'", "'wasm-unsafe-eval'"]
```

This changes the **declared, undelivered policy**. Worker, connection, MIME,
CORS and isolation requirements still need their own checks; this snippet is
not a complete deployment policy. A discovered WASM file never adds the token
automatically. See the [CSP specification](https://www.w3.org/TR/CSP/).

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
report destinations are refused. Ordinary limits: 5,000 files, 128 MiB total,
32 MiB per file, 8 MiB per HTML page, 5,000 directories and depth 64. Generated report JSON
must also fit the 8 MiB state-reader limit; excessive findings stop publication
without truncating findings or marking an unreadable generation complete.
Native configuration inspection has a 30-second deadline and a 16 MiB limit on
each captured output stream. UTF-8 HTML is required. This assumes a trusted local
build tree and no concurrent writers; it is not an OS filesystem sandbox.

### Publishing large local AI assets

After explicitly preparing and selecting a public Local AI Websites pack, add
its manifest path relative to the project and output root:

```yaml
content-security-protocol:
  enabled: true
  prepared-model-packs:
    - local-ai-assets/models.json
```

The report describes each selected pack's WASM compilation capability using
exact manifest, receipt and final-file hashes. It separately records whether
`script-src` declares `'wasm-unsafe-eval'`; execution and delivered policy remain
untested. Recognized inert Local AI manifest references are checked against the
retained output and explicitly selected packs. Missing, malformed or unsupported
references produce bounded findings without echoing rejected marker values.

`wasm-compilation-permission-not-declared` and the prepared-pack reference
findings are compatibility gaps requiring review, rather than proof of a
security flaw. You may deliberately deny model execution. A header-workflow
acknowledgement binds that decision to an exact inventory; it does not grant a
permission. Read the normal `report` output after rendering; no author JavaScript
or extra manifest declaration is required.

The sibling `asset-receipt.json` must identify exactly the same runtime/model
paths, sizes and SHA-256 hashes as that manifest. Only its listed `wasm/*.wasm`
and `models/*.litertlm` binaries use the separate adapter budget: 128 MiB per
WASM binary, 4 GiB per model and 8 GiB total binaries across at most eight packs.
All files still count towards the 5,000-file inventory. JavaScript, JSON, HTML,
notices and unrelated siblings keep the ordinary file and aggregate limits.
Missing files, modified hashes, duplicate resources, hidden/traversing paths
and inconsistent receipts are refused. Unlisted large files are not exempt.

The adapter reads model/WASM files in at most 1 MiB chunks instead of retaining
whole files. It hashes every byte during both output scans and freshness checks.
Configured forbidden markers are decoded and scanned across chunk boundaries;
selecting a pack does not waive publication checks. Optional accessibility
checking streams those exact assets into its private static copy and verifies
that copy before running the native scanner. It does not consent to model
downloads or execute inference on the reader's behalf.

This verifies consistency with the author-selected prepared receipt. It does
not establish executable safety, complete transitive package integrity, model
quality or permission to redistribute the assets. Model publication and the
reader's separate model-download consent remain explicit decisions. Large
packs add full-file hashing time and optional accessibility-copy disk space;
there is no timestamp shortcut or persistent audit cache.

A clean non-HTML-only render may omit the browser pack entirely. If both its
manifest and receipt are absent, the report records an unpublished pack and
retains the incomplete-no-HTML assessment. Every remaining file still receives
ordinary hashing, publication checks and limits; no missing-pair exemption
applies to leftover binaries. A lone manifest/receipt, or missing pack metadata
alongside any retained HTML page, is an error. Complete retained packs still
undergo the usual exact checks even during a non-HTML render.

Tested target: Windows, Quarto **1.11.5 prerelease**, HTML website/book/manuscript
projects and installed-only operation. Native DOCX projects receive asset
inventory only and an incomplete HTML assessment. Unconfigured standalone HTML
remains a no-op. Explicit standalone audit uses a contained output directory and
JSON options; it also runs with Deno network denial. Native QMD preview/watch is
tested separately. Arbitrary Unicode paths, Reveal/dashboard behavior and other
platforms remain unverified.
A manifest constraint is not evidence for all accepted later versions.

## Hosting and accessibility

Prepare a private Netlify candidate without installing or deploying it (the default remains Netlify):

```sh
quarto run _extensions/kai-prince-sfhea/content-security-protocol/cli.ts headers
```

The default is report-only. The artifact is
`.quarto/content-security-protocol/headers-netlify.txt`. Existing `_headers`,
`_redirects` or `netlify.toml` configurations are conflicts requiring manual
reconciliation. Only bounded ASCII static routes/index aliases are supported;
functions, proxies, rewrites, custom 404 fallback and actual Netlify delivery are
outside this adapter's verification. Header-only controls remain header-only.

For a Cloudflare Pages static site, select the separate adapter explicitly:

```sh
quarto run _extensions/kai-prince-sfhea/content-security-protocol/cli.ts headers --adapter cloudflare-pages
```

This writes `.quarto/content-security-protocol/headers-cloudflare-pages.txt`.
It emits one uniform `/*` rule for static responses, including native aliases
and fallback paths. The complete header line must fit Cloudflare Pages' 2,000
character limit; the extension refuses an oversized policy without truncation.
The one rule stays within the documented 100-rule limit. Literal ASCII inventory
paths remain bounded. Existing Functions, Worker, routing, Wrangler, redirects
or competing header configuration require separate manual integration and are
refused. See the official [headers documentation](https://developers.cloudflare.com/pages/configuration/headers/)
and [serving rules](https://developers.cloudflare.com/pages/configuration/serving-pages/).

Adapter selection belongs to this explicit command. It adds no project YAML
mode, automatic `_headers` copy, report endpoint or deployment. Both adapters
use the same declared policy and current audit/review gate. Header-only controls
stay header-only. A private artifact does not deliver a policy: separately review
its exact text, installation, host configuration, redirects and actual responses
before choosing to deploy. Hosted Netlify/Cloudflare delivery remains unverified;
local response tests do not establish host conformance or security.

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
Native diagnostics are captured with a byte limit rather than silenced, so
browser-startup failures can be investigated privately. The public-facing
summary remains sanitized and an incomplete scan never becomes a pass.
The native scanner reports violations only, omitting uncertain/pass checks.
The adapter therefore always records `native-uncertain-checks-not-reported` as
needs review; zero violations never becomes a conformance pass. Exit 1 means
violations, 2 incomplete, 3 needs review. WCAG 2.2 AA tags are classified separately
from other native rules. Keyboard/screen-reader/math speech, dynamic states and
Word/PDF accessibility still require their own evaluation.

### Optional browser states from YAML

Use this separate workflow when you want automated checks after specific native
interactions. The existing `accessibility` command above retains its pinned
Quarto scanner and its violation-only uncertainty warning. Neither command runs
during ordinary rendering.

Add a profile to the same project-level mapping, then render normally:

```yaml
content-security-protocol:
  enabled: true
  interaction-profiles:
    - id: example-details
      version: 1
      pages:
        - path: example.html
          states:
            - id: opened
              actions:
                - click:
                    selector: "#audit-details .callout-header"
              ready:
                selector: "#audit-details .callout-body-container"
                state: visible
```

This matches the native collapsible callout in `example.qmd`. For your own QMD,
assign a stable native ID and select the actual controls in its rendered HTML.
Use actual output HTML paths, including any custom `output-file`; QMD paths,
queries, fragments, external URLs and private/extension paths are refused. The
profile declares tests; it grants no CSP permission and does not assert that an
interaction improves accessibility.

The explicit command requires an installed Chromium browser, a local pinned axe
script and an ordinary private workspace directory. This adapter pins axe
**4.10.3**, **553446 bytes**, SHA-256
`880970c081707360e64f34cea25ff91892f5bc95675b0776925b9709dd8a68bb`.
The tested Quarto 1.11.5 distribution contains it at
`C:/Program Files/Quarto/share/formats/html/axe/axe.min.js`; installation paths
vary. A different file refuses before browser execution. Supply absolute paths;
there is no tool, model or rule-library download:

```powershell
quarto run _extensions/kai-prince-sfhea/content-security-protocol/cli.ts accessibility-browser --execute-pages --interaction-profile example-details --browser "C:/path/to/msedge.exe" --axe "C:/Program Files/Quarto/share/formats/html/axe/axe.min.js" --workspace "D:/private-audit-workspace"
```

Those are host paths, not project YAML or website resources. As elsewhere, omit
the owner directory after a local-checkout installation. Keep test values
fictional/public; the profile and raw diagnostics stay private. Run the same
Quarto project profile used for the current audit. Changed output, sources,
effective configuration or installed audit code require a new audit before
execution; the command cannot turn stale results into a current receipt.

Each declared page includes an initial check. Every named state starts from a
fresh isolated browser context; its actions are ordered within that state.
States do not depend on earlier named states. The browser receives the unchanged
private output copy. Light/dark `colorSchemes` emulate the media preference;
they do not operate or certify a site's native theme switcher. Main-document
selectors are test data, never author JavaScript. Actions require one suitable
visible/enabled target; missing, ambiguous, covered or unavailable targets cannot
be counted as a completed state. Remote requests, downloads, frame limitations
and incomplete rule results are reported separately; the mechanism does not
claim an operating-system network sandbox.

| Profile field | Default / finite contract |
|---|---|
| `id`, `version`, `pages` | Required; version `1`, up to 128 unique HTML paths |
| `pages[].states` | Optional, up to 16 unique states; `initial` is reserved |
| `states[].actions` | Up to 16; `click: {selector}`, `fill: {selector, value}`, `select: {selector, value}`, `key: {selector, key}` |
| `states[].ready` | Optional `{selector, state: visible\|hidden}`; a condition, not an arbitrary sleep/script |
| `viewports` | `[{width: 1440, height: 900}, {width: 320, height: 568}]`; up to 4 unique integer sizes, width 240–4096 / height 200–4096 |
| `colorSchemes` | `[light, dark]`; unique subset of these two preferences |
| `timeoutMs`, `totalTimeoutMs`, `settleMs` | 30000 / 600000 / 100; bounded to 1000–30000 / up to 3600000 / 0–10000 respectively; total must cover one cell timeout |

There are at most eight profiles and 512 planned page/state/viewport/scheme cells
per profile, including initial cells. The normalized profile is limited to
128 KiB. Selectors are trimmed text up to 512 UTF-8 bytes; literal fill/select
values up to 2048 bytes. Keys are `Enter`, `Space`, `Tab`, `Escape`, the four
`Arrow…` keys, `Home`, `End`, `PageUp`, `PageDown`; combinations/scripts are not
supported. Fill/select operations use an instrumented native control path;
they do not prove physical typing or assistive-technology behaviour.

The private receipt distinguishes planned/completed/unavailable states and
reported violations, incomplete checks, passes and inapplicable rules. Full
rule-array coverage is separate from the old native API's omission warning.
It binds tool/profile/output identities and records execution limits. Exit codes
remain 1 for findings, 2 incomplete, 3 needs review; 0 means the bounded automated
command completed, never WCAG conformance, secure hosting or human acceptance.
The actual browser/tool combination and interactive components still need their
own acceptance evidence.

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
broader dynamic runtime/host adapters, collectors, signatures and deployment remain
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

Updating the installed runtime changes its identity, so an earlier current
receipt becomes stale. Run a fresh `audit` with the current version and review
its findings.
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
