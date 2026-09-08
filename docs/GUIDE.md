# IFF Witness — technical guide

Witness compares an x402 payment requirement with IFF's independent observations, explains that evidence through 0G Compute, and lets a caller inspect the resulting signatures and content bindings. It is an **independently run reference application**, not a change to IFF's monitoring or payment-safety claims.

介面使用繁體中文。操作順序：**選擇範例 → 查核 → 下載證據包 → 修改判定 → 驗證差異**。

## Fresh-clone quick start

From the repository root, the portable demo needs Git and the Go
toolchain requested by `go.mod`:

```sh
git clone https://github.com/ifandonlyif-io/iff-witness-example.git
cd iff-witness-example
go run ./cmd/witness
```

Open **http://127.0.0.1:8094**, follow **金鑰與驗證設定**, and paste a funded
0G mainnet Router key. The key remains only in the running process. Return to
the demo, select **真實 IFF + 0G**, and run the check. The committed public
fixture is embedded in the executable and selected automatically, even when
the binary is launched outside the repository; no PostgreSQL, Redis, wallet, `.env`,
Docker, or Node dependency install is required.

The first run may download the selected Go toolchain and modules. Internet
access is still required for that download and for a live IFF/0G run. Rehearsal
mode starts without a key, but does not count as a real 0G integration.

To use another example or port:

```sh
WITNESS_EXAMPLE_FILE=/absolute/path/to/example.json go run ./cmd/witness
WITNESS_LISTEN_ADDR=127.0.0.1:18094 go run ./cmd/witness
```

Never commit a Router key. The repository ignores `.env` files, dependency
caches, and local outputs.

## Local development

From the repository root, with Node.js 22+ and the Go toolchain specified by `go.mod`:

```sh
npm ci
npm run build
[ -f .env ] || cp .env.example .env
npm start
```

Open **http://127.0.0.1:8094**. The conditional copy preserves an existing `.env`; on a fresh clone it selects the included public fixture without adding a key. `npm start` reads only this directory's optional `.env`; `go run ./cmd/witness` reads the process environment directly. Browser assets are embedded into the Go binary, so rebuild/restart after editing them. No PostgreSQL, Redis, wallet, or production signing key is needed.

The default **rehearsal** mode makes no outbound request. It creates a real Ed25519 signature using a newly generated, process-local demo key. The signed issuer is `https://witness.example`, the endpoint and observations are simulated, the explanation is fixed text, and all 0G/AgenticID proof indicators remain unverified. A rehearsal is not a qualifying live 0G integration.

## Enable real IFF + 0G

For the local demo, use the footer's **金鑰與驗證設定** link. It opens a separate settings tab. Only one secret is required: a funded mainnet 0G Router key. Paste it and choose **儲存並啟用**; it takes effect immediately. Switch back to the Demo tab, whose configuration refreshes on focus or a same-origin settings notification, then explicitly choose live mode. Saving alone performs no inference or balance lookup.

Keys set through this page are held only in the running service's memory. They are not returned to the page, included in evidence, written to `.env`, or stored in localStorage/sessionStorage. The password field is cleared on submission. Clearing disables subsequent requests without falling back to an environment key, resetting the call budget, or cancelling/refunding already-dispatched inference. On restart, any original environment key becomes active again; otherwise the key must be entered again. The page cannot revoke a key at 0G.

The settings API is restricted to a directly connected loopback listener and loopback client with a matching local Host. Public-origin deployments and proxy-forwarded requests are rejected. Mutations require the exact Origin and bounded JSON; there is no cross-origin access. For public hosting, use the platform's secret configuration, not this local-only convenience page.

Because the Router key is one process-wide value, not per-visitor, a public deployment's live mode is effectively a single shared key with a shared call budget for every visitor of that URL — not each visitor bringing their own key. Set `WITNESS_LIVE_PASSWORD` (a shared passphrase, distinct from the Router key) to gate who can trigger a live check at all on a public deployment; leave it unset for local/loopback use.

The same page has a separate optional **IFF 收據公鑰指紋** form. These are public verification-policy values, **not a second secret or an IFF production signing key**. Obtain the complete fingerprints through an independently trusted channel. Each is `sha256:` followed by 64 lowercase hexadecimal characters; enter at most 16, one per line or comma-separated. Public fingerprints are shown again when loading the page; the Router secret is never returned. Each form updates only its own field, so saving or clearing fingerprints preserves the Router key. Existing displayed evidence is reverified locally after policy changes; no new inference is sent. Already-started server checks retain their initial pin snapshot. Runtime fingerprint overrides also reset to the original environment configuration on restart. Do not copy untrusted pins out of an uploaded bundle and treat them as independently verified identities.

Alternatively, create an untracked `.env` from `.env.example`, then supply:

The example configuration already selects [IFF's public monitoring fixture](../examples/README.md). Its payment asset is synthetic, not USDC, and it processes no payment. The saved challenge is a historical capture; current availability and freshness are checked during a live run. For the included example, the only required new credential is your funded Router key.

- `WITNESS_0G_API_KEY`: a funded 0G **mainnet Router** key. Enter it only through the supported direct-localhost settings tab or secure environment configuration, never a public page, committed file, or proof bundle. Do not reuse a production IFF secret.
- Optional `WITNESS_EXAMPLE_FILE`: overrides the embedded public fixture with one endpoint that already has a public IFF card and observed payment fingerprint. Use an absolute path or a path relative to the process working directory (the repository root under `npm start`). An unreadable or invalid override stops startup; it never silently falls back to another endpoint.
- Optional `WITNESS_IFF_KEY_IDS`: comma-separated full receipt-key fingerprints obtained through an independently trusted channel. Without pins, the server accepts keys recognized by the configured HTTPS IFF origin; the browser does not promote a bundled key directory into an independent trust anchor.
- Optional `WITNESS_LIVE_PASSWORD`: a shared passphrase required (in the UI's own "真實查核密碼" field) for any `mode:"live"` check; rehearsal never requires it. Compared in constant time server-side. Unset by default — set it before making a deployment's live mode reachable by anyone who isn't supposed to spend its Router budget.

Example file shape (replace with a real previously observed endpoint and its actual unpaid x402 challenge):

```json
{
  "id": "my-observed-endpoint",
  "label": "My x402 demo",
  "url": "https://your-public-endpoint.example/paid-resource",
  "payment_required": {
    "x402Version": 2,
    "resource": { "url": "https://your-public-endpoint.example/paid-resource", "mimeType": "application/json" },
    "accepts": [{
      "scheme": "exact", "network": "eip155:8453", "amount": "1000",
      "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      "payTo": "0x1111111111111111111111111111111111111111",
      "maxTimeoutSeconds": 60, "extra": { "name": "USD Coin", "version": "2" }
    }]
  }
}
```

The `.example` values above are documentation placeholders, not real services. Witness never fetches the target endpoint itself and never pays it. Supply the challenge you already obtained independently. The browser only chooses between the server's allowlisted original and a controlled `payTo` mutation; it cannot submit arbitrary URLs. The first displayed payment option represents that configured challenge, **not an assertion that IFF published a historical raw payee**.

Restart the app and select **真實 IFF + 0G**. The server first reads the existing public evidence card, then requests an opt-in IFF receipt. The receipt's issuer, time, nonce, request fingerprint and outer response must match before any inference call. Unknown/unreadable endpoints are refused before `/verify`; this prevents the normal unknown-URL discovery side effect in the intended demo flow. It does not provide a transactional guarantee against an endpoint being removed between those public requests.

The default model ID is `0gm-1.0-35b-a3b`. `WITNESS_0G_MODEL` can select another compatible model, but the current integration requires `private` (TeeML) routing. The backend uses the official mainnet Router, `verify_tee: true`, no automatic retry/fallback, 600 output tokens, fixed price ceilings, a bounded input and timeout. Mainnet Compute and optional testnet AgenticID are separate environments with separate balances.

`WITNESS_MAX_LIVE_CHECKS` defaults to **30 attempted inference calls per process** (allowed range 1–500). Failed Router attempts also count; rehearsal and a failed IFF check do not. The API exposes remaining calls. This counter resets when the process restarts and is not a durable billing budget. There are also per-IP/global minute limits and two concurrent checks. Set a key-level spending limit in the provider console before any public deployment.

Validly shaped check requests, including missing or incorrect live-password attempts, share the limits of 6 per source IP and 20 globally per minute. Rate-limited requests return HTTP 429 with `Retry-After: 60`. Authentication failures never call IFF/0G or consume inference budget. A reverse proxy's connection address is used unless you provide a separately reviewed trusted-proxy design.

No live request should be claimed until an actual funded call and its returned artifacts have been inspected. Missing proof, an omitted verification flag, failed signature checks and network errors are displayed distinctly; the application never substitutes simulated evidence for a live failure.

## Exact 0G integration points

| File | Integration |
|---|---|
| `compute.go` | Calls `https://router-api.0g.ai/v1/chat/completions`; supplies verified IFF signed subject; retains exact HTTP request/response JSON, provider and `ZG-Res-Key`. |
| `proofs.go` | Reads 0G mainnet service registry at a fixed block through the configured official RPC, fetches the provider signature, recovers EIP-191 signer, compares exact request/response SHA-256 digests. |
| `client/verify.mjs` | Local IFF Ed25519 verification, C1 fingerprint recomputation, evidence-to-prompt binding, model consistency, output matching and raw provider proof verification. |
| `client/agentic.mjs` | Optional offline X-Agent-Proof signature and HTTP transcript verification with external identity/domain pins. |
| `client/agent-bundle.mjs` | Binds the signed Agent HTTP route, request and entire response to the displayed Witness bundle; rejects swapped explanations or evidence. |
| `agentic/register-service.mjs` | Registers the loopback Go API inside an **existing** 0G Sealed Sandbox; it neither mints nor funds/deploys an agent. |

The provider signature currently binds exact request/response digests, not simply the assistant's text. Router modifications to a response or request may make retained Router bytes differ from provider-signed bytes. In that case, a signature can be valid while independent content binding is **unavailable**. Witness deliberately does not guess how to reverse those transformations. `tee_verified: true` is a Router report, not a portable independent proof by itself. A complete end-to-end Compute proof requires every relevant identity, signature and content-binding check, not an aggregate badge.

To independently pin a provider for offline verification, configure both `WITNESS_0G_PROVIDER` and `WITNESS_0G_SIGNER` using the independently confirmed provider and signing addresses. These are **verification policy**, not a routing override. Optional AgenticID verification uses all of `WITNESS_AGENT_SIGNER`, `WITNESS_AGENT_CHAIN_ID`, and `WITNESS_AGENT_CONTRACT`. All are public identity values. Data inside an uploaded bundle never becomes its own trust policy.

Sources: [Router](https://docs.0g.ai/developer-hub/building-on-0g/compute-network/router/overview), [verification trust model](https://docs.0g.ai/developer-hub/building-on-0g/compute-network/router/features/verifiable-execution), [actual broker signing implementation](https://github.com/0gfoundation/0g-serving-broker/blob/main/api/inference/internal/ctrl/signing.go), [SDK response verification](https://github.com/0gfoundation/0g-compute-ts-sdk/blob/main/src.ts/sdk/inference/broker/response.ts), [AgenticID setup](https://github.com/0gfoundation/0g-agentic-id/blob/main/sdk/typescript/README.md).

## Download and verify offline

After a check, use **下載證據包**. Importing is entirely local to the browser. The verifier preserves the original IFF and Compute raw JSON strings. It does not upload the imported file or automatically fetch a URL inside it.

The optional CLI also works with no network:

```sh
npm run verify -- /absolute/path/to/bundle.json /absolute/path/to/trusted-policy.json
```

The separate policy file can contain `expectedIssuer`, `trustedKeyIDs`, `expectedNonce`, `trustedComputeSigners` (provider-address-to-signer map), and `agentic` (`expectedSigner`, `chainId`, `contractAddress`). Omitting it leaves identities unverified. Exit code 1 means a failed check; 2 means unreadable/invalid input. **Exit code 0 means only that no check failed, not that every claim is verified**; inspect the individual states.

A ready-to-use policy file is committed at `examples/trusted-policy.json`, pinning IFF's published production signing key and the AgenticID demo signer described below. Download a **live-mode** bundle from this app and immediately run `npm run verify -- your-bundle.json examples/trusted-policy.json` with no setup. Rehearsal-mode bundles intentionally cannot be pinned this way: the demo signing key is freshly generated in process memory on every restart, so `iff_issuer` correctly stays `unverified` for a rehearsal bundle checked against this file. IFF's signing key can rotate; re-fetch `https://ifandonlyif.io/api/v3/receipts/keys` if this stops matching.

## AgenticID / X-Agent-Proof demo (offline test vector)

`examples/agentic-demo-bundle.json` and `examples/agentic-demo-bundle-tampered.json` are complete Witness bundles with a self-signed `agent` envelope attached, built by `node scripts/build-agentic-demo.mjs` against a running rehearsal server. The signing key is the same public, deterministic **TEST-ONLY** key already used in `client/agentic.test.mjs` (`0x11` repeated 32 times) — never a funded wallet, never a real 0G Sealed Sandbox.

To see these verify live in the running app, export the matching trust pins before starting the server (also already present in `examples/trusted-policy.json`'s `agentic` block, for the CLI path):

```sh
export WITNESS_AGENT_SIGNER=0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A
export WITNESS_AGENT_CHAIN_ID=16602
export WITNESS_AGENT_CONTRACT=0x2222222222222222222222222222222222222222
go run ./cmd/witness
```

Then use **匯入證據包重新驗證** with `agentic-demo-bundle.json`: every `agentic-*` and `agentic-bundle-*` check passes except the two that are unverified/warning by design (no live chain query, no attestation claim). Import `agentic-demo-bundle-tampered.json` instead — its visible `explanation.text` was edited after signing — and only `agentic-bundle-response` flips to `fail`, the same "signature still valid, content altered" story as the existing IFF tamper demo, extended to the Agent envelope. Both files verify identically offline via `npm run verify -- examples/agentic-demo-bundle.json examples/trusted-policy.json`.

**This is a test vector, not a live sandbox proof.** State that plainly when demoing it: the signing spec and offline verifier are implemented and exercised end-to-end in this exact UI, but this repository has no 0G-hosted Sealed Sandbox access, so no sandbox-issued X-Agent-Proof exists here. See [agentic/README.md](../agentic/README.md) for what a real sandbox integration additionally requires.

## Scope: what this repository does not include

- **Multi-agent collaboration.** This is one verifier hop: it checks one x402 challenge against one IFF observation and one 0G explanation. `/api/check` plus the X-Agent-Proof/bundle-binding check above is the mechanism another Agent's payment-release step could call as an attested hop, but no second Agent identity is wired up here.
- **A live AgenticID/Sealed Sandbox proof.** See the AgenticID demo section above.
- **Any IFF production service.** No database, discovery pipeline, scheduler, worker, webhook, monitor keys, or anchor process — see [PROVENANCE.md](../PROVENANCE.md) for exactly what was, and wasn't, brought in from IFF's own codebase.
- **Docker/public hosting**, exercised only informally; see [QA.md](../QA.md).

Receipts have a five-minute action window. Old signatures remain cryptographically verifiable, but the time check becomes a warning. Refresh the receipt for a live presentation. A restarted rehearsal server uses a new demo key; old demonstration signatures still verify, but do not match the new process's demo identity.

See [optional AgenticID integration](../agentic/README.md) for sealed service registration and the exact signed transcript. That optional route is API-only and needs a real already-running sandbox; these files do not assert that a sandbox was provisioned or an identity was minted.

## Isolation and deployment

Service Receipt v1 `compute_proof` semantics remain unchanged from IFF's own definition. Optional 0G claims apply only to the evidence actually verified here, never to IFF's original probe execution. The current runtime is Go plus browser JavaScript; Deno Deploy adaptation has not been implemented.

For a separate service, build from the repository root using `Dockerfile`, set `WITNESS_LISTEN_ADDR=0.0.0.0:8094` and `WITNESS_PUBLIC_ORIGIN` to its real HTTPS origin, and configure the platform to route to port 8094. Mount the example file read-only and supply the key through the host's secret settings.

Platform health checks must send the hostname from `WITNESS_PUBLIC_ORIGIN` in the `Host` header, including for `GET /health`; an internal IP/port hostname receives `403`. `Dockerfile.dockerignore` uses a default-deny build context, allowing only the current Go dependency closure, browser source, and the one committed public example fixture. Update that allowlist when adding build inputs.

## Checks

```sh
npm test
npm run build
go test -race ./...
go vet ./...
go test ./...
go build ./...
```

Tests cover receipt/content tampering, request binding, reused/nonmatching nonces, expiry, unknown trust roots, exact signed bytes, public C1 test vectors, SSRF/redirect limits, live-mode failures without fallback, credit budgets, and optional AgenticID domain/transcript mutation. Real service availability, a funded inference, a hosted AgenticID deployment and public hosting are separate integration checks.
