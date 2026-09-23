# Apostille example: sign a Witness artifact, verify the original

這個範例替 Witness 證據包加上 Apostille Core 0.1 來源簽章，再修改原件的一個位元組，展示「簽章有效」與「原件相符」是不同檢查。使用本機臨時金鑰，不需帳號、錢包、API key 或 0G 額度。

## Browser walkthrough

Open the **[hosted Apostille example](https://iff-witness-production.up.railway.app/apostille.html)** without installing anything. To run it locally, start Witness as usual and open **http://127.0.0.1:8094/apostille.html**, or follow the Apostille link on the home page.

The default **跟著做一次** path guides you through three steps. Each step shows what just happened, the measured result and what to expect next:

1. Choose **簽署範例檔案**. The original is the exact committed `agentic-demo-bundle.json` file, a public rehearsal fixture with a self-signed AgenticID test proof. The page signs it, checks the signatures and confirms the original matches. No live IFF/0G request occurs.
2. Choose **加一個空白並查驗**. One ASCII space is appended to a copy of the original while the signature bundle stays unchanged. The page shows the actual byte-count increase and highlights the added space. A valid signature plus an original-file mismatch is the expected success for this tamper test.
3. Choose **還原原件並查驗**. Both checks pass again. Only after the original has been restored does the handoff section appear. Choose **查看下載與交接方式**, then download **both** the original and signature bundle. Download feedback reports which file is still needed; confirm the files in your browser's downloads.
4. Switch to **查驗收到的檔案**. Select the signature bundle and corresponding original; the page counts the two required files and enables **查驗這兩份檔案** when both are selected. Matching and mismatched originals have separate explanations and next actions. Changing either file clears the old result. You can also reload the page or use another Witness instance; the signing keys are not needed.

The guide and recipient views retain separate state when switching between them. **重新開始** clears guide progress; **換成自己的 Witness 檔案** optionally uses a local original smaller than 1 MiB, leaving room for the extra test byte. Recipient originals may be up to 1 MiB. Technical hashes, key fingerprints and protocol result fields are available under **查看技術細節**. Trust and content-truth limits stay visible beside the results.


### Need test files first?

Open **查驗收到的檔案** and choose **產生一組測試檔案**. No previous guide progress is required. The page uses the public rehearsal fixture, creates fresh ephemeral signing keys locally, and checks that the original passes while the changed copy fails before offering downloads.

- Download the numbered pair: `apostille-<group-id>.json` (signature bundle) and `witness-<group-id>-original.json` (original). The shared group ID helps distinguish downloads from different runs.
- Choose **下一步：選擇下載的檔案**, select the signature bundle in field 1 and the original in field 2, then verify. Expected: signature valid and original matching.
- Expand **再挑戰：測試「原件不符」**, download `witness-<group-id>-changed.json`, and replace only field 2 with that file. Keep the same signature bundle. Expected: signature still valid, original not matching, because one space was appended.

Download feedback reports which required file remains. Confirm your browser saved both files. **重新產生一組** makes a new group and clears the recipient's selected files and previous verification result, so the new group is never shown with a stale pass. Existing guide progress is retained. Generated files contain public sample data and public signature material, not private keys or a hosted issuer certificate.

The page uses the existing Witness visual style, local assets and `connect-src 'none'`. Selected files are never uploaded. Browser WebCrypto Ed25519 support and a secure context (HTTPS or loopback HTTP) are required. New administrator/agent keys are non-exportable and short-lived in memory; they are not registered with IFF or saved for future signing. This is an integration example, not a production key-management system.

## Terminal walkthrough

Use Node.js 22.9.0 or later. These commands run from the directory containing `package.json` and work without installing npm dependencies; the offline Core modules are included in the source. Git and the first Go build still need their normal dependency downloads.

Generate an example in a **new directory** (the parent must already exist):

```sh
npm run apostille -- demo my-apostille-demo
```

It writes only:

- `witness-original.json`: the exact public Witness rehearsal fixture.
- `apostille-bundle.json`: real Core 0.1 delegation, acceptance and origin statement, with `certificate: null`.
- `witness-with-space.json`: original bytes plus one ASCII space, for the negative check.

The printed results must show `original.original_matches: true` and `changed.original_matches: false`, while both retain `signature_check: valid`. All signing keys are discarded; no seed or key file is exported.

Re-verify after the signing process has exited:

```sh
npm run apostille -- verify my-apostille-demo/apostille-bundle.json my-apostille-demo/witness-original.json
npm run apostille -- verify my-apostille-demo/apostille-bundle.json my-apostille-demo/witness-with-space.json
```

The first command exits **0**; the changed-original command intentionally exits **1**. To sign a Witness bundle you already downloaded:

```sh
npm run apostille -- sign my-witness-bundle.json my-apostille-bundle.json
npm run apostille -- verify my-apostille-bundle.json my-witness-bundle.json
```

Output files/directories must be new; existing files are never overwritten. Regular original files are limited to 1 MiB and signature bundles to 256 KiB. Exit 0 means the example's signature and original comparison passed; it does **not** mean issuer trust, content truth or current authorization is established. Exit 1 means verification, signing or validation failed; exit 2 means usage or a common file-access error.

## Verify with the separately released Go CLI

With a Go toolchain, install the released CLI and add `GOBIN` (or `GOPATH/bin`) to `PATH`:

```sh
go install github.com/ifandonlyif-io/iff-apostille/cmd/apostille@v0.1.0-alpha.1
apostille verify --offline --bundle my-apostille-demo/apostille-bundle.json --artifact my-apostille-demo/witness-original.json
apostille verify --offline --bundle my-apostille-demo/apostille-bundle.json --artifact my-apostille-demo/witness-with-space.json
```

The original succeeds; the changed artifact exits **4** in the Go CLI. These are producer-only signatures: `--require-trusted` requires explicit `--issuer` and `--key-id` policy flags and still rejects producer-only bundles because they have no issuer certificate. Use independent exact issuer/key pins and a receiver policy for any separately obtained issuer certificate; never promote an embedded public key to a trust anchor.

## What stays separate

Apostille signs the original file's SHA-256, size and media type. It does not reinterpret the file, reissue an IFF Service Receipt, register or publish an agent, call 0G, pay an endpoint, or add a monitor/log/reputation entry. Existing inner transcript strings and proof bytes are retained in the original exactly.

Verify IFF/0G/AgenticID evidence separately in Witness or with `npm run verify`. Even a valid Apostille signature can wrap an invalid inner receipt or a false explanation. The example verifier does not establish organization identity, current delegation validity/revocation, payment safety, legal effect or TEE execution. Producer-only freshness and authorization remain `unknown`.

## Source and checks

The browser/CLI helper uses byte-for-byte copies of `web/apostille-core.mjs` and `web/apostille-json.mjs` from the public [Apostille v0.1.0-alpha.1 release](https://github.com/ifandonlyif-io/iff-apostille/releases/tag/v0.1.0-alpha.1), commit `d2c72c8b323a4bcd8f107c1b917209fecccbde0f`. This avoids depending on an unpublished npm package or importing private IFF code.

[`SOURCE.json`](../client/third-party/apostille/SOURCE.json) records exact source paths and SHA-256 hashes. `npm run build` checks these copies before bundling. Update them only from a reviewed public release; preserve the [MIT License](../client/third-party/apostille/LICENSE), which is also included in the generated browser script.

```sh
node scripts/check-apostille-source.mjs
npm run build
npm test
```

Tests exercise real signatures, changed original bytes, altered envelopes, swapped delegation keys, input limits, immutable snapshots, and CLI verification after signing keys have gone away. They do not call a hosted service or spend credits.
