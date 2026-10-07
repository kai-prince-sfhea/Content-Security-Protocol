# Content-Security-Protocol (Quarto Extension)

Adaptive Content Security Policy automation for Quarto sites.

## Installing

```bash
quarto add kai-prince-sfhea/content-security-protocol
```

This will install the extension under the `_extensions` subdirectory.
If you're using version control, you will want to check in this directory.

## Example

Here is the source code for a minimal example: [example.qmd](example.qmd).

## Features
- Per-page CSP generation with nonces, optional hash-only mode.
- Automatic detection & rewrite of inline event handlers (removes need for `unsafe-hashes`).
- Optional `hash-inline` to add SHA-256 hashes for inline scripts/styles.
- Subresource Integrity (SRI) injection for local assets + reporting of remote candidates.
- Strict scoring (0–100) with penalties only for real degradations.
- Site-wide union/intersection summary + recommended header + `headers.txt` artifact.
- Dynamic style nonce patch to auto-nonce runtime `<style>` insertions.
- MathJax, tippy/popper heuristics (worker-src, style-src-attr) without broad `unsafe-inline`.
- Configurable fallbacks & toggles (e.g., `worker-no-blob`, `disable-sri`).

## Configuration (YAML)
```
content-security-policy:
  strict-dynamic: true          # optional
  hash-inline: true             # add hashes for inline blocks
  hash-only-csp: false          # if true, removes nonces; rely on hashes
  preserve-inline-events: false # if true, don't rewrite inline event handlers
  worker-no-blob: false         # remove blob: from worker-src when set
  disable-sri: false            # skip SRI injection
  # Any other keys become directive overrides, e.g.
  connect-src: "'self' https://api.example.com"
```

Add under project or document metadata (`_quarto.yml` or document front matter).

## Scoring
Penalties: unsafe-inline (-12), unsafe-eval (-15), unsafe-hashes (-8), missing self / strict directives (see report). Bonus +5 for nonce + strict-dynamic. Stored in `_schema/CSP.json` and injected as `<meta name="csp-score">`.

## Generated Artifacts
- `_schema/CSP.json` – per-file breakdown + site summary.
- `_schema/sri-report.json` – local asset integrities, remote candidates.
- `_site/headers.txt` – recommended CSP & common security headers.

## Extension Order
Register filters in this order:
1. `quarto-pre/CSP-pre.lua`
2. `filters/CSP-filter.lua`
3. `quarto-post/CSP-post.lua`

## Migration from schema-integrated CSP
Remove CSP sections from prior `MathResources.lua` / `MathRendering.lua` once satisfied. This extension is standalone; it *reuses* `schema/` directory metadata if present, otherwise (future enhancement) can scan `_site`.

## Future Enhancements
- Trusted Types directive support
- `strict-dynamic` automatic enabling when safe
- Configurable host allowlist (currently hard-coded jsDelivr / Google Fonts)
- Fallback HTML crawler if `Directories.json` absent (partial stub present)

## Troubleshooting
If CSP meta still shows `'unsafe-hashes'`, verify inline event rewrite succeeded (no remaining `on*=` attributes) and you didn't set `preserve-inline-events`. Check `_schema/CSP.json` for directive map.
