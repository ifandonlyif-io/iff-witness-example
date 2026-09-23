# Captured IFF fixture challenge

`iff-fixture.json` is a fixed live-endpoint configuration captured from an
existing IFF monitoring fixture. The addresses are the fixture's actual public
challenge values, not payment destinations selected for this application.
This is a test asset address, **not USDC**, and the fixture does not process
payments. Do not fund these addresses or interpret this example as a real paid
service.

## Use

Witness embeds this public fixture and selects it by default. No `.env` is
needed. To explicitly load the repository copy instead, set this in the local,
untracked `.env` and restart with `npm start`:

```dotenv
WITNESS_EXAMPLE_FILE=examples/iff-fixture.json
```

A funded mainnet 0G Router key is still required for real inference. Merely
loading this example does not issue an IFF receipt or contact 0G.

## Source and capture

- Source: [unpaid fixture endpoint](https://x402-fixture.ifandonlyif.io/paid-resource),
  captured **2026-09-05 15:09:06 UTC** (**23:09:06 Asia/Taipei**).
- Acquisition: one unpaid `GET`, HTTP **402**. The `PAYMENT-REQUIRED` response
  header was decoded from standard Base64, then parsed and validated through
  IFF's existing official x402 v2 parser. `payment_required` preserves that
  decoded JSON value without fabricated resource metadata or token decimals.
- Response body: `This is an unpaid x402 v2 monitoring fixture; no payment is processed.`
- Independent existing evidence: [public IFF card](https://ifandonlyif.io/api/v3/evidence/endpoints/70ece389-9cb2-45d3-931c-54b62d71a129),
  read at **2026-09-05 15:09:07 UTC**. At capture it reported `tier: verified`,
  `ownership.status: verified`, `operational_status: passing`, and
  `freshness.status: fresh`; the latest observation was
  `2026-09-05T15:08:42.524829Z` with a 300-second expected interval.
- The captured challenge's C1 set fingerprint matched the card exactly:
  `10e4012a7b9385c2fa27ed889c2c2fa7f302c076eadab169064cb7af5b5b4523`.
- The endpoint was already known to IFF's monitor prior to this capture; this
  capture did not register or submit it for discovery.

Both public reads used `util.NewSafeHTTPClient` with public HTTPS/443,
connection-time address validation, redirects disabled, 15-second timeouts,
and a 128-KiB body cap. No payment, `/verify` POST, owner action, or
probe-triggering API was performed during acquisition.

These are **capture-time facts**, not a guarantee of future availability,
freshness, unchanged payment requirements, or safety. Witness rechecks the
current public evidence before attempting a live receipt request. If the
fixture changes, the original example may legitimately return `diverged` or
`stale`; refresh the source challenge through the same safe acquisition
process before the presentation. The configured original and the UI's
controlled `payTo` mutation remain visibly distinct from an actual attack.

## Other files in this directory

- `trusted-policy.json`: an offline-verifier trust policy pinning IFF's
  published production signing key and the AgenticID demo signer. See
  [docs/GUIDE.md#download-and-verify-offline](../docs/GUIDE.md).
- `agentic-demo-bundle.json` / `agentic-demo-bundle-tampered.json`: a
  self-signed AgenticID/X-Agent-Proof test vector (public deterministic key,
  no live sandbox). See
  [docs/GUIDE.md#agenticid--x-agent-proof-demo-offline-test-vector](../docs/GUIDE.md).

## Apostille source-signature example

[APOSTILLE.md](APOSTILLE.md) shows how to sign the exact Witness rehearsal file with Core 0.1, detect changed original bytes, and re-verify with Node or the released Go CLI. The original test fixture stays unchanged; the new signatures are local producer-only examples.
