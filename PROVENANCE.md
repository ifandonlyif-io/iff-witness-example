# Source provenance

This is a standalone, public reference implementation of **IFF Witness**,
originally built for the 0G Taipei Hackathon. It is not a copy of IFF's
production monitoring service's source tree or history — it's a from-scratch
extraction that keeps only what a third-party integrator needs to see: how
to read IFF's public evidence API, how to verify its signed receipts, and
how to explain that evidence through 0G Compute.

## What's original Witness work

The application itself — the Go server (`server.go`, `config.go`,
`settings.go`), the 0G Compute Router/proof adapter (`compute.go`,
`proofs.go`), the browser UI and its offline verifier
(`client/`, `web/`), the AgenticID/X-Agent-Proof offline demo
(`agentic/`, `scripts/build-agentic-demo.mjs`), and the controlled tamper
demonstration — was built for this project. It calls IFF's and 0G's already
**public** HTTP APIs; it does not use, and has never used, any IFF database,
scheduler, discovery pipeline, or other internal production service.

## What's adapted from IFF, and why

Three small packages are adapted from IFF's own verification logic — the
part of IFF's stack that's designed to be independently re-derivable by
anyone, as distinct from the operational service that produces it:

- **`receipt/`** — the IFF Service Receipt v1 envelope: Ed25519 signing and
  verification, canonical JSON validation, issuer/nonce/timestamp checks.
  No database dependency, no proprietary business logic — a signature
  format meant to be checked by people who aren't IFF. IFF also publishes an
  independent SDK covering the same receipt format at
  [`ifandonlyif-io/iff-x402-transparency`](https://github.com/ifandonlyif-io/iff-x402-transparency);
  the two have since diverged in some validation strictness (this copy is
  the one that's been exercised by Witness's own test suite), so this repo
  vendors its own copy rather than depending on that one directly.
- **`internal/prober/prober.go`** — x402 v2 `PaymentRequired` parsing and
  validation, built on the official
  [`x402-foundation/x402`](https://github.com/x402-foundation/x402) Go SDK.
  This is a **trimmed** extract: IFF's internal prober also does live SSRF-safe
  probing of a target endpoint and domain-ownership-challenge verification;
  neither is included here, because Witness never fetches a target endpoint
  itself — it only parses a `payment_required` payload the caller already
  obtained independently. What remains is pure parsing logic with no network
  access.
- **`util/safe_http.go`, `util/url_validator.go`** — a generic SSRF-safe HTTP
  client and public-HTTPS URL validator (reject loopback/private targets,
  disable redirects, bound response size and timeout). Generic security
  utility code with no service-specific logic.

The C1 payment-fingerprint algorithm itself is **not** vendored — Witness
depends directly on IFF's public
[`iff-x402-transparency/go`](https://github.com/ifandonlyif-io/iff-x402-transparency)
module (see `go.mod`), the same package any external integrator would use.

## What's deliberately left out

IFF's production monitoring service — the Postgres-backed endpoint
repository, discovery/claim pipeline, transparency-log storage, webhook and
manifest/anchoring workers, and their schema-coupled data types — is **not**
part of this repository and never has been. Witness only ever reads IFF's
already-public `/api/v3/evidence/check`, `/api/v3/receipts/keys`, and
`/api/v3/verify` HTTP responses; it does not need, and does not have, direct
access to how those responses are produced. Where this app needs to parse a
piece of that public JSON response, it defines its own minimal local type
for exactly the fields it reads (see the `evidenceCard` type in
`server.go`) rather than importing IFF's internal, much larger data model.

## License

MIT License, retained verbatim in [LICENSE](LICENSE). Preserve that notice
in redistributed copies. Third-party dependencies retain their respective
licenses; generated browser bundles preserve the notices included by the
build tool.
