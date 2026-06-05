# Vane Website — Architecture Reference

## Overview

The marketing site lives entirely in `public/`. It is a single-file architecture: one
`index.html` containing all HTML, CSS, and JavaScript. The only external files in `public/`
are assets that the HTML references:

```
public/
  index.html          The site (HTML + CSS + JS, ~600 lines each)
  passport-crypto.js  Testable ES module — all in-browser Ed25519 logic
  favicon.svg         Terracotta weathervane mark, 32×32
  og.svg              Open Graph share card, 1200×630
```

No build step, no bundler, no node_modules in `public/`. Open `index.html` directly in a
browser or serve it with any static file server.

---

## Running Locally

```bash
# Serve on http://localhost:8080 (any static server works)
npx serve public

# Or with Python
python3 -m http.server 8080 --directory public

# Or with Node's built-in http module
node -e "require('http').createServer(require('fs').createReadStream).listen(8080)"
```

Three.js is loaded from cdnjs via a `<script>` tag that is injected only when the
*How It Works* section scrolls into view (see Lazy-loading section). The playground
module (`passport-crypto.js`) is loaded as `<script type="module">` — both require
HTTP (not `file://`), so use a server rather than opening the file directly.

---

## Playground Module (`public/passport-crypto.js`)

### What it does

All in-browser cryptography is extracted into a pure ES module so it can be tested in
Node.js without any DOM mock. The module exports:

| Export | Description |
|---|---|
| `generateKeyPair()` | `subtle.generateKey({name:'Ed25519'}, true, ['sign','verify'])` |
| `buildPassportClaims(opts)` | Assembles the JWT claims object (SPIFFE IDs, delegation chain, exp = iat + 3600) |
| `signPassport(claims, privateKey)` | Produces a `CAP+JWT` token: `b64url(header).b64url(payload).b64url(sig)` |
| `verifyPassport(token, publicKey)` | Runs `subtle.verify` and returns `{valid, claims?, error?}` |
| `tamperToken(token)` | XORs the middle byte of the payload segment (idempotent — double-flip restores) |
| `decodePayload(token)` | Decodes payload without verifying |
| `decodeHeader(token)` | Decodes header without verifying |
| `validateJwtStructure(token)` | Structural check only (3 parts, valid base64url, parseable JSON) |
| `b64url(bytes)` | `Uint8Array → base64url string` |
| `b64urlStr(str)` | `UTF-8 string → base64url string` |
| `b64urlDecode(str)` | `base64url string → Uint8Array` |

### Key design decisions

- Uses `globalThis.crypto.subtle` so it works identically in browsers and Node.js 22+.
- `btoa` / `atob` are available globally in both environments since Node 16.
- No side effects, no `window` references, no DOM — safe to `import` from any test runner.
- The JWT type is `CAP+JWT` (Cryptographic Agent Passport), not standard `JWT`, to make
  demo tokens visually distinguishable from production tokens.

---

## Live Passport Playground

The playground is wired in `index.html` inside a `<script type="module">` block that
imports from `./passport-crypto.js`. The module script handles:

1. **Scope chip toggles** — `.pg-chip` buttons toggle the `.on` class; selected scopes
   are collected at issue time.
2. **Issue** — calls `generateKeyPair()`, then `buildPassportClaims()`, then
   `signPassport()`. The resulting JWT is stored in `currentToken` and `currentKp` (the
   key pair) is kept in memory for the session.
3. **Token display** — the JWT is split at `.` and rendered with three `<span>` elements
   (`.jwt-h`, `.jwt-p`, `.jwt-s`) to show the header/payload/signature in distinct colors.
4. **Verify** — calls `verifyPassport(currentToken, currentKp.publicKey)` and renders
   the decoded claims if valid.
5. **Tamper demo** — calls `tamperToken(currentToken)`, updates the display to show the
   payload segment with a strikethrough, then auto-verifies to show the red failure.
6. **Copy** — `navigator.clipboard.writeText(currentToken)` with an `execCommand` fallback.

State is held in two module-level variables (`currentToken`, `currentKp`). Issuing a new
passport replaces both.

---

## Three.js Merkle Tree Visualization

### Loading strategy

Three.js (~700 KB minified) is loaded lazily via `IntersectionObserver`:

```js
const merkleObs = new IntersectionObserver(entries => {
  if (!entries[0].isIntersecting || threeLoaded) return;
  threeLoaded = true; merkleObs.disconnect();
  const s = document.createElement('script');
  s.src = 'https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js';
  s.onload = () => initMerkle();
  document.head.appendChild(s);
}, { rootMargin: '300px' });
merkleObs.observe(canvas);
```

The `300px` root margin means the script starts loading 300 px before the section
scrolls into view — by the time the user reaches it, Three.js is already ready.

### Camera

Orthographic projection (`THREE.OrthographicCamera`) with a half-height frustum of 170
world units. This gives a clean diagram-style view with no perspective distortion —
appropriate for a data structure visualization.

### Node layout

Seven nodes positioned in world coordinates:

```
leaves  (level 0)  y = -100    ids 0,1,2,3  (r=14)
parents (level 1)  y =    0    ids 4,5       (r=17)
root    (level 2)  y = +130    id  6          (r=22)
```

The root is at the bottom (larger y = lower on screen because y is inverted in the
`OrthographicCamera` setup). Nodes build from leaves upward.

### Animation timeline

Leaf nodes appear first (t = 1.2 s, 2.8 s, 4.8 s, 6.2 s), parent nodes activate after
both children are present (t = 3.4 s, 6.8 s), and the root appears at t = 7.4 s.

The tamper demo runs at t = 11.5 s: leaf 1 → parent 4 → root turn red. The chain
resets at t = 16 s and loops.

HTML labels are positioned by projecting each node's 3D position through the camera
matrix into screen space and setting `transform: translate(x px, y px)` on `div.ml-lbl`
elements in an absolutely-positioned overlay.

### Reduced-motion fallback

When `(prefers-reduced-motion: reduce)` is true, the `<script>` block returns immediately
(no Three.js injected). CSS rules hide the canvas and show `.merkle-static`, a plain SVG
depicting the completed tree structure.

---

## Typography

**Headings**: Bricolage Grotesque — a variable grotesque with an optical-size axis
(`opsz 12..96`). Loaded as `wght@200..800`, `opsz@12..96`. Chosen for its unusual
geometry: squared-off apertures and strong weight contrast give headings a distinctive
editorial presence that avoids the genericness of Inter or Roboto. `font-optical-sizing: auto`
is set globally so the browser automatically picks the right opsz value for each font-size.

**Code / mono**: Geist Mono — clean tabular mono that pairs well with Bricolage and
signals engineering credibility without the retro overtones of JetBrains Mono.

Both are loaded from Google Fonts with `display=swap` to avoid layout shifts.

---

## Motion System

All animations follow Emil Kowalski's design engineering principles:

- Only `transform` and `opacity` are animated (GPU-composited, no layout/paint cost).
- Custom easing curves: `--ease-out: cubic-bezier(0.23, 1, 0.32, 1)` (enter/exit),
  `--ease-in-out: cubic-bezier(0.77, 0, 0.175, 1)` (on-screen motion).
- UI animations stay ≤ 300 ms. The playground token reveal is 400–500 ms (content-heavy
  transformation, not a simple state toggle).
- `transform: scale(0.97)` on `:active` for all interactive elements.
- Hero entrance uses `@keyframes hFadeUp` with sequential `animation-delay` (0.04 s steps)
  via the `@media (prefers-reduced-motion: no-preference)` guard.
- Scroll reveals use `IntersectionObserver` at `threshold: 0.16`. Each `.r` element in a
  section gets a `transitionDelay` of `i * 100ms` when its parent enters the viewport.
- All animation code is guarded: `if (reduceMotion) return` at the top of every effect.

---

## Performance Budget

Target: Lighthouse performance ≥ 90 on desktop.

| Strategy | Impact |
|---|---|
| No Three.js on first paint (lazy + `rootMargin: 300px`) | Removes ~700 KB from critical path |
| CSS grid background (no canvas element in hero) | Hero LCP is pure text |
| Google Fonts `display=swap` | No FOIT |
| Single HTML file — 1 TCP connection for the page | No render-blocking stylesheets |
| `will-change: transform` on smooth-wrapper only | GPU layer for scroll animation |
| `will-change: opacity, transform` on `.r` elements | Promotes reveal targets |
| Images: none (SVG favicon, SVG OG card — both vector) | Zero image weight |
| Three.js r128 (~730 KB) loaded async from CDN | Cached across sites |

Estimated first-paint weight: `index.html` (~60 KB uncompressed), `passport-crypto.js`
(~5 KB), two Google Fonts subsets (~30 KB combined). Under 100 KB before Three.js.
