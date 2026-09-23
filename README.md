# IFF Witness Example

**English** · [繁體中文](README.zh-TW.md)

**Checks have grounds. Explanations have receipts.**

Run Witness on your laptop to compare an x402 payment requirement with [IFF](https://ifandonlyif.io) evidence, optionally ask 0G to explain the verified result, and download a bundle that can be checked again locally. This public example runs independently of IFF's production service.

**Start locally. No deployment, API key, wallet, database, Docker, or Node.js installation is needed for the rehearsal demo.**

## Apostille example: sign the evidence file

**[Try the hosted Apostille example](https://iff-witness-production.up.railway.app/apostille.html)** — no installation required. Generate a matching test-file pair in your browser, download it, and check the original or a deliberately changed copy.

Open **[the local Apostille example](http://127.0.0.1:8094/apostille.html)** after starting Witness. Create a real local source signature over the bundled rehearsal file or your own saved Witness bundle, add one space to the original, and see original-file verification fail while the signature remains valid. Download both files and verify them again without the signing keys.

No account, API key, wallet, hosted issuance or 0G credits are needed. Results remain `producer_only` with unknown issuer trust; this does not upgrade any inner IFF/0G/AgenticID evidence. See the [browser and terminal walkthrough](examples/APOSTILLE.md).

## 1. Install the prerequisites

| Tool | When you need it | Installation |
|---|---|---|
| Git | Download and update this repository | [Install Git for your OS](https://git-scm.com/install/) |
| Go | Start the web app | [Install Go](https://go.dev/doc/install); use Go **1.26.6 or newer** to match or exceed the requested toolchain |
| Node.js + npm | Only for the optional CLI verifier, frontend development, or `npm start` | [Install a supported Node.js LTS](https://nodejs.org/en/download); these instructions require **22.9.0+** |

Choose the installer for your operating system and processor. After installing, reopen Terminal on macOS/Linux or PowerShell on Windows, then check:

```sh
git --version
go version
```

Both commands should print a version. [go.mod](go.mod) declares a minimum Go version of 1.25.0 and requests toolchain 1.26.6. An older installation with automatic toolchain selection enabled may download the requested toolchain on first use; see [Go's toolchain documentation](https://go.dev/doc/toolchain). The first run needs internet access for Git, Go modules, and any toolchain download.

## 2. Download and start

In a folder where you keep projects, run these commands one at a time. They work in macOS/Linux terminals and Windows PowerShell:

```sh
git clone https://github.com/ifandonlyif-io/iff-witness-example.git
cd iff-witness-example
go run ./cmd/witness
```

The initial download/build may take a while. When the terminal shows this message, leave it running:

```text
IFF Witness is listening on 127.0.0.1:8094 (rehearsal is the default)
```

Open **[http://127.0.0.1:8094](http://127.0.0.1:8094)** in a current browser. Do not open `web/index.html` directly: the page needs the local Go server. The interface is in Traditional Chinese.

The browser assets and [public endpoint fixture](examples/README.md) are included in the executable. You do not need to create `.env`, install JavaScript dependencies, or configure an example path for this route.

- **Stop:** press `Ctrl+C` in the server terminal.
- **Start again:** run `go run ./cmd/witness` from the `iff-witness-example` folder.
- **Use another laptop:** repeat the installation and clone steps there. Do not copy private keys or the other laptop's `.env`.

## 3. Confirm the demo works — no key required

Keep **演練資料** (rehearsal) selected:

1. Select **原始範例**, then **執行查核**. The verdict should be `consistent`.
2. Select **模擬更換收款地址** and run again. The verdict should be `diverged`.
3. Select **修改判定並驗證**. The signature can remain valid, but the outer result should fail the signed-content comparison.
4. Select **還原原始證據**, then **下載證據包**. Use **匯入證據包重新驗證** to check the saved file locally.

Rehearsal uses simulated observations, a real process-local Ed25519 demo signature, and fixed explanation text. It makes **no external service requests** and spends no 0G credits. Missing 0G/AgenticID proofs stay `unverified`; that is expected, not an installation failure.

## 4. Optional: enable real IFF + 0G

You can skip this section if you only want to try the UI or verifier. Live inference can consume paid Router credits; Witness itself never pays the x402 endpoint.

1. Obtain a **mainnet Router inference API key** with available credits through [0G's official Router quickstart](https://docs.0g.ai/developer-hub/building-on-0g/compute-network/router/quickstart). The mainnet console is [pc.0g.ai](https://pc.0g.ai). Testnet keys/balances and Direct/Advanced provider balances are separate from this app's mainnet Router integration; see the [Router overview](https://docs.0g.ai/developer-hub/building-on-0g/compute-network/router/overview).
2. Keep your local Witness server running. Open **金鑰與驗證設定** in the page footer, or visit [the local settings page](http://127.0.0.1:8094/settings.html).
3. Paste the Router API key into **0G Router API 金鑰** and select **儲存並啟用**. Never enter a wallet private key, IFF signing key, or management key here. **IFF 收據公鑰指紋** is optional public trust-policy data, not another secret.
4. Return to the demo tab, explicitly select **真實 IFF + 0G**, choose a scenario, and select **執行查核**.
5. Inspect the separate IFF and 0G verification results, then download the bundle. A live verdict depends on current public evidence; it is not guaranteed to be `consistent`.

Saving a key does not send inference or check its balance. A key entered through the settings page stays in server memory, is not written to `.env` or included in bundles, and must be entered again after restarting. If you supplied a key through the environment, that environment value becomes active again on restart.

Live mode verifies the IFF receipt before calling 0G. The default limit is **30 attempted inference calls per process**, including failed Router attempts. This is not a durable spending cap: restarts reset it, so also configure provider-side spending controls. Missing proofs or unpinned identities remain unverified; the Router's self-report is not an independent proof.

## 5. Optional: verify a saved bundle without running the server

Install Node.js + npm from section 1. From this repository's root, check the versions and install dependencies:

```sh
node --version
npm --version
npm ci
npm run verify -- examples/agentic-demo-bundle.json examples/trusted-policy.json
```

This bundled example is a **self-signed test vector using a public test key**, not a real Sealed Sandbox proof. It should exit with code 0, although expired IFF receipts and unpinned identities can show warnings or unverified states. The verification command works offline after dependencies have been installed; it needs no Go server, API key, or wallet.

Try the deliberately tampered file separately:

```sh
npm run verify -- examples/agentic-demo-bundle-tampered.json examples/trusted-policy.json
```

Expected: `agentic-bundle-response` fails and the command exits with code **1**. This failure is the demonstration working correctly.

For your own download, replace the paths below with your bundle and an independently trusted policy:

```sh
npm run verify -- /path/to/bundle.json /path/to/trusted-policy.json
```

Exit **0** means no check failed, **not** that every claim is verified. Exit **1** means at least one failed check; **2** means unreadable/invalid input. Never establish trust using keys copied out of the file being checked. The example policy includes test-only AgenticID pins and is not a production identity policy. See [offline verification and trust policies](docs/GUIDE.md#download-and-verify-offline).

## 6. Update or build an executable

Stop the server first. From the repository root, if you have no conflicting local edits:

```sh
git pull --ff-only
go run ./cmd/witness
```

If Git reports local changes or divergent history, preserve your work and resolve that first; do not reset files just to update. The standard Go-only route uses the committed browser build, so `npm ci` is not required to run it.

To build instead of using `go run`:

macOS/Linux:

```sh
go build -o bin/witness ./cmd/witness
./bin/witness
```

Windows PowerShell:

```powershell
go build -o bin/witness.exe ./cmd/witness
.\bin\witness.exe
```

The executable includes the UI and default fixture. Build on the destination laptop, or use a binary built for its OS/CPU; a macOS binary will not run on Windows. Runtime keys and trust settings are not embedded.

## 7. Optional: frontend development and `.env`

Only use this route if you want to edit the interface or load local settings from a file. **Go is still required:** `npm start` launches the same Go server.

1. Stop the existing server and install Node.js + npm from section 1.
2. In the repository root, install and rebuild browser assets:

   ```sh
   npm ci
   npm run build
   ```

3. If you want file-based configuration, copy `.env.example` to `.env` **only when `.env` does not already exist**. This step is optional; using the local key-settings page avoids storing the Router key in a file.
4. Start:

   ```sh
   npm start
   ```

`npm start` reads the optional `.env`; `go run ./cmd/witness` and the compiled executable read process environment variables only. Changing `.env` requires a restart. Changing `client/` requires `npm run build` and a server restart; there is no automatic frontend reload. Never commit `.env` or share it with evidence bundles.

For checks before contributing:

```sh
npm test
go test ./...
go vet ./...
```

The full test checklist is in [CONTRIBUTING.md](CONTRIBUTING.md).

## Troubleshooting

| Symptom | What to check |
|---|---|
| `git` or `go` not found | Finish the relevant installer, reopen the terminal, and repeat the version checks. |
| Toolchain/module download fails | Check your internet/proxy configuration and the Go version requested by `go.mod`. Do not lower the module version or disable verification to get past it. |
| `go.mod file not found` | Run commands inside `iff-witness-example`, where `go.mod` is located. |
| `address already in use` | Stop the other instance or choose a different port using the commands below. |
| Browser cannot connect | Keep the server terminal running; use `http://127.0.0.1:8094`, not HTTPS or a directly opened HTML file. |
| Live mode stays disabled | Save a Router key, then refocus the demo tab. If the example is missing, update the repo and inspect any explicit `WITNESS_EXAMPLE_FILE` override. |
| Settings return 403 | Settings are available only over a direct local connection. Use the local URL, not a public domain, tunnel, or reverse proxy; public hosting needs platform secrets. |
| `npm start` reports an unknown `--env-file-if-exists` option | Upgrade Node.js to a supported LTS, at least 22.9.0. [Flag documentation](https://nodejs.org/api/cli.html#--env-file-if-existsfile). |
| HTTP 429 / temporary request limit | Wait at least 60 seconds. Incorrect live passwords also count toward the limit. |
| Inference budget exhausted | Review usage and provider spending limits first. The default is 30 attempts per process; do not treat restarting as a cost-control strategy. |
| IFF/0G unavailable, `stale`, or proof `unverified` | These can be external availability, freshness, or trust/proof limitations, not installation errors. Check the individual messages; do not disable signature checks. |

To use another port, stop the server and run **one** version appropriate to your shell:

macOS/Linux:

```sh
WITNESS_LISTEN_ADDR=127.0.0.1:18094 go run ./cmd/witness
```

Windows PowerShell:

```powershell
$env:WITNESS_LISTEN_ADDR = "127.0.0.1:18094"
go run ./cmd/witness
```

Then open [http://127.0.0.1:18094](http://127.0.0.1:18094). PowerShell keeps that variable in the current session; change it back to `127.0.0.1:8094` or open a fresh terminal for the default port.

## Scope and further reading

**A consistent requirement does not mean payment is safe. An inference signature does not mean the answer is correct.** Witness never claims that IFF's external observations ran in a TEE. Rehearsal and the committed AgenticID test vector are not evidence of a live 0G integration.

You do **not** need Railway or another hosting platform to follow this README. Public deployment is separate: the settings page is local-only, the Router key/budget is shared by the server, and public live access should be password-gated. Read the [deployment guide](docs/GUIDE.md#isolation-and-deployment) before exposing the app; do not simply change the listener to `0.0.0.0`.

- [Technical guide and configuration](docs/GUIDE.md)
- [Optional AgenticID / Sealed Sandbox integration](agentic/README.md)
- [Source provenance](PROVENANCE.md) · [Example source](examples/README.md) · [QA and untested integrations](QA.md)
- [0G implementation](compute.go) · [Proof verification](proofs.go) · [Browser verifier](client/verify.mjs)
- [MIT License](LICENSE) · [Third-party licenses](docs/licenses/README.md) · [Security reporting](SECURITY.md)

Built on independent evidence from [IFF](https://ifandonlyif.io). Copyright (c) 2024 [IfAndOnlyIf.io](https://ifandonlyif.io).
