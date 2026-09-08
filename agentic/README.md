# Optional AgenticID service proof

This integration runs the standalone Witness service **inside an existing 0G Sealed Sandbox** and registers `POST /api/check` with the sealed proxy. The proxy adds the real `X-Agent-Proof` header. Nothing in this directory mints an agent, deposits funds, deploys a sandbox, or changes the production IFF monitor. A local rehearsal without that header remains explicitly unverified for AgenticID.

## Prerequisites

Before deployment, use the current official AgenticID setup and confirm its hosted environment is available. The documented SDK is `@0gfoundation/0g-agenticid-sdk`; `AgenticID.fromAttestor('https://agenticid.0g.ai')` obtains the current contract/RPC/framework configuration. Addresses must come from the intended deployment, not copied from unrelated examples.

- An existing running agent, using a framework/runtime supported by that attestor. A newly built custom framework or sealed image requires operator allowlisting and is outside this integration.
- An owner wallet with gas, acknowledged trust-root components, a funded sandbox balance (the documented deployment preflight is at least 0.1 OG), and the separate AgentSeal gas balance for the agent's own on-chain activity.
- A 0G Router key/credits, configured securely as `WITNESS_0G_API_KEY` for the Witness process when using live inference. Never put a wallet or provider secret into browser code, receipt files, or this repository.
- A Linux binary matching the sandbox architecture, and Node.js for the registration helper. The official hosted environment, account access, balances and live proofs have **not** been provisioned or validated by adding these files.

See the [official SDK setup](https://github.com/0gfoundation/0g-agentic-id/blob/main/sdk/typescript/README.md) and [deployment/diagnostic guide](https://github.com/0gfoundation/0g-agentic-id/blob/main/sdk/typescript/GUIDE.md).

## Run the isolated API inside the sandbox

Build the browser assets first, using the Witness package's build command. Then build the Go executable from the repository root for the sandbox's actual architecture; for an x86-64 Linux sandbox:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/iff-witness-example-linux-amd64 ./cmd/witness
```

Use the hosted sandbox's supported owner workflow to install the binary and this registration helper. Configure the Witness environment described in the parent README. Run the executable with `WITNESS_LISTEN_ADDR=127.0.0.1:8094`; the API key belongs only in the process environment. Keep the service running with the sandbox's supported process supervisor. Do not copy IFF production signing keys, database credentials, worker credentials, or anchor wallets into the sandbox.

After the service is listening, execute **inside that sandbox**:

```sh
node agentic/register-service.mjs --port 8094
```

The helper reads the existing service registry and writes it back with this entry added:

```json
{"path":"/api/check","method":"POST","backend":"http://127.0.0.1:8094"}
```

All helper I/O uses the local Unix socket from `SEAL_SIGN_SOCK` (default `/run/seal-sign.sock`). It never contacts a remote host or signs a transaction. Unrelated services are preserved. An existing `/api/check` with a different method/backend is refused unless the operator explicitly supplies `--replace`. Avoid running other registry writers concurrently because the official API replaces the complete list. Registration is runtime state; repeat it after a sandbox restart.

This registers **only the API**. It does not publish Witness's `/`, assets or `/api/config` through sealed; unregistered paths are rejected. The simplest initial demo uses a service client to capture the sealed response and imports the resulting receipt into the local Witness verifier. Direct cross-origin browser calls are not enabled by this helper, and Witness's same-origin protection must not be disabled to make them work.

The official registration behavior and loopback requirement are implemented in [services.go](https://github.com/0gfoundation/0g-agentic-id/blob/main/sealed/internal/proxy/services.go). Agent services under `/api/*` are signed; owner chat/framework routes are not. `/hello` is a signed introduction, not proof that `/api/check` ran.

## Preserve the exact proof transcript

Capture the header from the **actual sealed service response**, before parsing or reformatting either body. Save this shape as the receipt's optional AgenticID envelope:

```json
{
  "proof": "0x<SIGNATURE>.<BASE64URL_ENVELOPE>",
  "transcript": {
    "method": "POST",
    "uri": "/api/check",
    "status": 200,
    "rawRequest": "<exact UTF-8 request bytes as a JSON string>",
    "rawResponse": "<exact UTF-8 response bytes as a JSON string>"
  }
}
```

For non-UTF-8 bytes, use `rawRequestBase64` / `rawResponseBase64` instead of the corresponding raw text field. Do not supply both forms. Empty bodies must be present as empty strings; omitted bytes cannot be verified. The verifier bounds each body to 2 MiB.

`POST /api/check` accepts `mode`, `scenario`, `nonce`, and an optional string
`password` for the shared live-mode gate. Bundle verification compares the first
three fields with the displayed check and permits only that optional extra
field; the signature still covers the entire original request, including the
password. Unknown fields and changes to signed bytes remain invalid.
**Do not publicly share a captured transcript containing a real password.** The
verifier warns when it finds a nonempty password. Removing or redacting that
field after signing invalidates the transcript; use a credential-free rehearsal
for publicly shared test vectors.

The official task digest is `keccak256(method || requestURI || keccak256(rawRequest) || keccak256(rawResponse) || decimalStatus)`. The EIP-191 signature covers the ABI encoding of the chain ID, identity registry, submitter, agent ID, timestamp, deadline, task digest, packed iData hash digest, and framework hash. The verifier follows [the current proxy implementation](https://github.com/0gfoundation/0g-agentic-id/blob/main/sealed/internal/proxy/proxy.go#L683-L819).

Import and call the browser-compatible verifier:

```js
import { verifyAgentProof } from '../client/agentic.mjs';

const result = verifyAgentProof(envelope, {
  expectedSigner: independentlyPinnedAgentSeal,
  chainId: independentlyPinnedChainId,
  contractAddress: independentlyPinnedAgenticIDContract,
});
```

`now`, if supplied, is Unix seconds. The only return statuses are `pass`, `fail`, `unverified`, and `warning`. A parsed SDK proof object is also accepted in `proof`. Identity/domain values embedded in an imported receipt do not become trusted automatically.

If a client adds this envelope to a parsed Witness bundle after receiving the response, it must also check that the displayed bundle equals the original response JSON (excluding the newly attached transport envelope). Otherwise someone could modify a displayed explanation while retaining the original signed transcript. This envelope verifier verifies the transcript; it does not infer an application's surrounding display schema.

## What the indicators mean

The offline verifier can check exact HTTP bytes and compare a recovered signing key to independently established identity/domain pins. It does not query a chain, establish the latest identity/iData state, check an image allowlist, or validate hardware remote attestation. A missing independent pin stays `unverified`. The standard SDK's `verifyProof()` reads chain state; “no gas required” does not mean “no network required.”

An expired submission deadline is a warning: it does not retroactively invalidate the historical signature. The signed assertion does not prove the endpoint is currently unchanged, that an explanation is correct, that a payment is safe, or that an external IFF observation ran inside a TEE. A saved file also cannot establish that its envelope originally arrived on the sealed proxy's live HTTP-header channel. See the official [signature primitive](https://github.com/0gfoundation/0g-agentic-id/blob/main/sdk/typescript/src/ServeProof.ts), [chain-aware checks](https://github.com/0gfoundation/0g-agentic-id/blob/main/sdk/typescript/src/ServeSession.ts), and [trust model](https://github.com/0gfoundation/0g-agentic-id/blob/main/sealed/TRUST_MODEL.md).

For the tampering demo, verify a captured response, change a character in its raw response, and verify again: the transcript check must fail. Change the pinned chain or contract: the signature comparison must fail. Tests use a public deterministic test key and local Unix sockets; they neither call 0G nor spend funds:

```sh
node --test client/agentic.test.mjs agentic/register-service.test.mjs
```
