# Security policy

Please report vulnerabilities privately to `ben@tokimi.space`.

Do not open a public issue for a suspected signature-verification bypass, fingerprint-canonicalization mismatch, SSRF issue, tamper-detection bypass, leaked credential, or any way to make the UI display an unverified claim as verified. Include the affected version or commit, reproduction steps, and whether you believe the live demo deployment is affected.

We will acknowledge a report, preserve relevant evidence, and coordinate a disclosure timeline appropriate to the impact. A response is not a promise of a bounty.

The public security boundary is intentionally precise: an IFF receipt signature is provenance/tamper evidence, not proof that IFF's observation ran inside a trusted execution environment; a 0G Router's `tee_verified` flag is a self-report, not an independent proof; a consistent x402 requirement does not establish payment safety or service delivery; and a signed explanation does not establish that the model's answer is correct.
