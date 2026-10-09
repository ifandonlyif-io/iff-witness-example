# Witness MVP verification — 2026-09-05

## Apostille integration example — 2026-09-23

- The receiver view can generate a fresh downloadable signature/original pair and a changed-original challenge without prior guide steps. Chrome downloads were checked through the Go CLI (original exit 0; changed original exit 4), then imported through the in-app browser with the expected matching/mismatched results. Regeneration clears old selections and results; the 390 px download layout has no horizontal overflow. Chrome automation file selection needs the extension file-URL permission, so the import test used the in-app browser.

- Guided UI: sign → append one space → restore, with actual byte-count feedback, expected tamper mismatch explained as a successful detection, download handoff and a separate recipient flow. Browser checks cover all three steps, preserved guide progress across mode switches, one/two-file readiness, changed originals, invalid bundle errors, the guide size limit, switching back to the built-in sample and clearing stale results. The 390 px guide shows its first action without horizontal overflow; the desktop result comparison was visually inspected. Technical details are progressively disclosed; trust limits remain visible.

- All **52** JavaScript tests pass, including seven Apostille integration tests. The browser build checks the exact Core 0.4.0-alpha.1 release source and retains its full MIT notice. No dependency versions or existing evidence fixture bytes changed.
- Browser walkthrough exercised real local ML-DSA-65 signing, exact original matching, one-space tampering, restoration, recipient imports, and clearing stale results on file selection. The 390 px mobile layout has no horizontal overflow; the walkthrough produced no console errors/warnings.
- A real Chrome download of the Apostille bundle passes the Go CLI against the original fixture. The changed-original CLI check exits 4; producer-only verification with an explicit receiver policy and `--require-trusted` exits 3. The fixture SHA-256 remains `9f86cadf8b54580aaf5a29df6863eaaf3c4670947010f060730a4fd7c5d1e818`.
- Terminal tests verify after the signing process exits, refuse existing outputs, and export no private key files. File limits, modified envelopes, swapped delegation keys and mutable Node Buffer inputs are covered.
- Both Witness repositories' container build inputs include the new source pin check, MIT license, public fixture and page assets. Local Docker build/run checks serve the standalone page and generated script.
- Go build, tests, vet and race checks pass under this repository's documented scope. These pre-deployment checks perform no funded inference, paid transaction or hosted issuance. Identity trust, content truth and current authorization remain unestablished.

## Public example review fixes — 2026-09-08

- All **45** JavaScript tests, browser build, `go test ./...`, `go test -race ./...`, `go vet ./...`, and `go build ./...` pass.
- A compiled binary started from an empty temporary directory loads the embedded public fixture without `.env` or a runtime example file. Saving a deliberately fake Router key enables the live-mode selector; a rehearsal receipt verifies locally and consumes no inference budget. No funded inference was sent.
- Actual local HTTP checks: 40 incorrect-password attempts from one IP produce six HTTP 403 responses followed by 34 HTTP 429 responses. Regression tests also cover missing passwords, global limits across different source IPs, window expiry, and unchanged inference budget.
- Agent bundle tests accept the API's optional string password without changing original transcript bytes. Password edits still fail transcript verification; unknown fields, duplicate keys, and modified mode/scenario/nonce remain rejected. Nonempty captured passwords receive a sharing warning without being repeated in check details.
- The committed normal AgenticID demo still exits 0 in the offline CLI; its tampered companion exits 1. Both remain test vectors, not live Sandbox proofs. This check did not deploy or change any existing hosted service.

## Passed

- Full repository: `go test ./...`, `go build ./...`.
- Isolated service: race tests and `go vet ./...`.
- Linux/amd64 build with CGO disabled.
- Browser build and all **33** JavaScript tests (receipt, Compute, Agent transcript, full bundle binding, sandbox registration).
- Real Chrome interaction: original challenge returns `consistent`; controlled changed-payee challenge returns `diverged`.
- Tamper demo: changing the outer verdict leaves the original signature valid but fails signed-subject equality. The displayed authoritative verdict remains the signed value.
- Restore removes the content mismatch; evidence download and local re-import succeed. Imports without an independently expected nonce retain a replay warning.
- Downloaded browser evidence passes offline CLI integrity checks; unpinned identity and unavailable 0G evidence remain unverified, not green.
- Desktop 1440 px and mobile 390 px layouts inspected; mobile has no horizontal overflow. Keyboard focus has a visible outline. Browser console: zero errors/warnings during these flows.
- Included public fixture acquired through the production SSRF-safe client and official x402 parser. Its captured challenge fingerprint matches its existing public IFF card. See `examples/README.md` for exact source and time.
- Docker build context checked with the official Moby pattern matcher: required build inputs included; credentials, runtime examples and unrelated files excluded.

## Not yet verified

- **A funded, real 0G inference request.** No Router API key was supplied during this implementation. Rehearsal must not be presented as meeting the hackathon integration requirement.
- Independent end-to-end provider content binding across the live Router. Exact byte preservation and returned provider proof need inspection; unsigned Router metadata alone is insufficient.
- A real deployed AgenticID service and its returned X-Agent-Proof. The local verifier and registration adapter are implemented and tested with cryptographic fixtures only.
- Docker container build/run (local daemon unavailable), public hosting and public GitHub submission.

No production IFF routes, schema, monitoring jobs, keys or existing website files were edited. The live-mode API can request a receipt from an already-public endpoint, but cannot atomically rule out its removal between the public-card read and `/verify`.

## Local settings addition — 2026-09-06

- Footer opens a separate settings tab. Password input, save, immediate status update, clearing, and main-tab live-mode availability were exercised in real Chrome against an isolated test instance using a deliberately fake key; no inference was sent.
- Cross-tab updates send only a change notification through BroadcastChannel and then reload safe public configuration. Focus/visibility refresh remains a fallback; saved receipts are preserved and live mode is never selected automatically.
- Saving clears the input. Browser localStorage/sessionStorage remained empty; the API returns only configuration metadata, not the key. Saving/clearing leaves the attempt budget unchanged.
- Desktop 1440 px and mobile 390 px settings layouts visually inspected; no horizontal overflow.
- New backend tests pass for local-only access, strict Origin and JSON, duplicate/unknown keys, body/token bounds, secrets not returned, clear during IFF preflight, in-flight key rotation and concurrent updates. Race tests and vet pass.
- Full repository tests/build and all 33 existing JavaScript tests pass with the addition. Credentials set through the page are memory-only; this does not constitute a real funded 0G integration test.

## Public fingerprint settings — 2026-09-06

- The settings page separates the required 0G secret from optional public IFF receipt fingerprints. Saving or clearing either field preserves the other; canonical fingerprint validation rejects secret-like or malformed input. No production secret is requested.
- Real Chrome on an isolated instance: saved a deliberately fake Router key and a synthetic public fingerprint, cleared the fingerprint while retaining the key, then cleared the key. The input stayed empty after submission, browser storage stayed empty, the call budget stayed at 30/30, and no inference was sent. Footer opened a separate tab. Desktop and 390 px mobile layouts were inspected; mobile scroll width equalled client width. Console had zero errors/warnings.
- All **42** JavaScript tests pass, including six policy-refresh/concurrency tests and three settings-value tests. Changed pins trigger local reverification without replacing receipt bytes or nonce; stale asynchronous checks cannot overwrite newer trust policy.
- Original and standalone Go tests/build pass. Labs race tests and vet pass in both copies. Backend tests cover partial/atomic updates, strict JSON and 16-pin bounds, request-local trust snapshots, configuration copying, and concurrent updates. Existing local-only access controls and inference budgets remain unchanged.
- The local Demo was restarted with updated embedded assets. No funded live inference, public deployment, or production IFF modification was performed for this addition.
