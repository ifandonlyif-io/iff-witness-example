# IFF Witness Example

A public, standalone reference implementation of IFF Witness: compares an
x402 payment requirement against IFF's independently observed evidence,
explains it through 0G Compute, and produces a downloadable, offline
re-verifiable evidence bundle. Read `README.md` and `PROVENANCE.md` before
changing the runtime or deployment. Go plus browser JavaScript; no Deno
Deploy adaptation exists.

## Local checks

At the repository root: `go build ./...`, `go vet ./...`, `go test ./...`,
`go test -race ./...`.

`npm ci`, `npm run build`, `npm test`, `npm start`. Browser assets are
embedded in the Go executable; rebuild and restart to see asset changes. The
default mode is simulated rehearsal, not a real 0G call.

## Boundaries

- Never describe IFF monitor signatures as TEE execution or remote attestation.
  Consistency does not establish payment safety or service delivery.
- Do not add paid x402 transactions or arbitrary target-URL probing. Live
  checks use an allowlisted example and existing public IFF evidence. This
  repo intentionally has no live-probing code path at all (see PROVENANCE.md).
- All external Go HTTP requests must use `util.NewSafeHTTPClient`, including
  registry-derived provider URLs: public HTTPS/443, no redirects, validation
  at connection time, bounded bodies and timeouts. Generic `fetch` is not an
  equivalent substitute.
- Verify IFF receipt identity policy, signature, validity, nonce and request
  binding before sending its signed evidence to a model.
- Missing or unverifiable 0G evidence stays unverified. Router metadata is not
  an independent portable proof; do not fabricate or reconstruct signed bytes.
- Imported bundles cannot supply their own trusted keys. Preserve exact raw
  transcripts and bind the displayed bundle to any Agent service proof.
- Do not log, commit, return or include API keys in browser bundles or proof
  files. Web key settings are direct-loopback only and memory-only. Public
  hosting must use platform secrets or a separately reviewed authenticated
  administration design.
- The Router key is one process-wide value, not per-visitor; a public
  deployment's live mode is a shared key/budget for every visitor of that URL.
  `WITNESS_LIVE_PASSWORD` gates who may trigger `mode:"live"` at all — compare
  it in constant time (`crypto/subtle`), never log it, and never let it govern
  anything beyond that one gate (it is not the Router key and must not be
  conflated with it).
- Key changes cannot reset inference budgets. Cloud restarts and multiple
  instances make per-process limits unsuitable as a durable total budget.
- Do not import anything from IFF's private production monorepo. This repo's
  `internal/prober`, `receipt`, and `util` packages are deliberately trimmed,
  self-contained copies with no database or proprietary-service coupling —
  see PROVENANCE.md for exactly what was kept out and why, before adding a
  new dependency on IFF-internal code.
- Preserve MIT attribution and the provenance record in `PROVENANCE.md`.

Keep credentials, `.env`, dependency caches, screenshots, logs and local
outputs out of Git.
