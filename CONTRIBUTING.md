# Contributing

Small, reviewable changes with test coverage are preferred.

Before opening a pull request, run:

```bash
go build ./...
go vet ./...
go test ./...
go test -race ./...
npm ci
npm run build
npm test
```

Changes to signature verification, fingerprinting, or content-binding logic must keep the Go backend and the browser verifier (`client/verify.mjs`, `web/service-receipt.mjs`) producing identical results for the same input — a passing `npm run verify` against a bundle this server just issued is the fastest way to check that.

Do not weaken the stated limitations or introduce `safe`/`unsafe`, guaranteed-payment-safety, AI-reasoning-proof, or composite-score claims. A consistent x402 requirement is not a payment-safety guarantee; a valid inference signature is not proof the model's answer is correct; `tee_verified: true` in a Router response is a self-report, not an independent proof. Keep these distinctions explicit in any new check or UI text rather than collapsing them into a single pass/fail badge.

Never add production secrets, real API keys, or a real funded wallet's private key to this repository, including in example files, test fixtures, or commit history. The AgenticID demo key (`0x11` repeated 32 times) is deliberately public and test-only; if you add another test fixture, label it just as clearly.

Do not import from IFF's private production codebase. `internal/prober`, `receipt`, and `util` here are deliberately trimmed, self-contained copies — see [PROVENANCE.md](PROVENANCE.md) for what was left out and why. If a change would require pulling in database access, discovery/scheduling logic, or any other IFF-internal service code, it's out of scope for this repository.

Report security-sensitive findings through [SECURITY.md](SECURITY.md), not a public issue.
