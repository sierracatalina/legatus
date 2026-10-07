# Verified PCP adapter

`conformance.pcp_verifier.PCPVerifier` verifies the `pcp1` detached proof with
Ed25519 and RFC 8785 canonicalization before calling PCP for authorization.
Install `requirements.txt` to enable this adapter. The fixture runner itself
still runs with only the Python standard library.

The adapter checks the strict request, canonical unpadded base64url, duplicate
header keys, exact five-field protected header, profile context, proof copy,
signer, key ownership, move purpose, and the exact six-field signing object.
It validates requests and responses against the pinned canonical PCP schemas,
and retains Legatus's stricter move payload and response identifier checks.

Supply three trusted callbacks:

- `resolve_key(signer_id, key_id)` returns a `TrustedKey` from an independently
  authenticated principal key set, or `None` for an unknown key. Candidate
  content cannot establish key ownership. Only a public Ed25519 key is needed.
- `authorize(request, protected)` receives copies after signature verification.
  PCP must still authenticate the referenced principal-signed grant and check
  subject, configured audience, exact purpose, action and resource scope, time,
  revocation, and atomic budget reservation. It returns the strict PCP verifier
  disposition, including a live `authorization_id` only when authorized.
- `finalize(request)` uses the same authenticated PCP integration to validate
  stored reservation identity and journal evidence and commit or release it
  idempotently. The adapter checks the strict result and matching outcome.

Create `Runtime(verifier=adapter)` to use it. Callback outages or malformed
results return `unavailable`; an invalid proof maps to `LEGATUS_E_SIG` through
the runtime. A signature never supplies action authority by itself.

`Runtime()` now refuses to start without an explicit verifier. For synthetic
reference work only, use `Runtime(fixture_mode=True)` or explicitly supply
`FixtureVerifier`. `SIG_PENDING` is rejected by `PCPVerifier`. Journal replay
checks in the fixture harness do not authenticate the source of a journal.

## Schema provenance

`schemas/pcp-source.json` records the immutable PCP source commit and
SHA-256 for all nine `pcp*.schema.json` files. Their upstream `$id`, references,
titles and bytes are preserved. The current source is the merged Purpose-bound
Capability Protocol rename, PCP PR #3, at commit
`1655898fbf0f64a8754b3856f462ebef743611f6`.

Run `python scripts/check_pcp_schemas.py` for local drift detection. With an
upstream git checkout, use `--upstream <checkout>` to compare each file with
the exact recorded commit. The canonical PCP carrier schema leaves payload
validation to Legatus; `schemas/envelope.schema.json` and the runtime continue
to enforce the move contract.

## Evidence and limits

Tests verify a Node-generated synthetic signature containing non-ASCII and
astral text against independently reconstructed signing bytes. The committed
fixture contains only the public key, envelope, proof and canonical bytes.
Negative checks cover tampering, wrong/unknown/misbound keys, noncanonical
headers and signatures, duplicate keys, unknown context, extra algorithm
fields, proof binding mismatches, authority denials, unavailable callbacks,
duplicate acknowledgement, and release after a signed illegal transition.

The adapter supplies real proof verification. It does not implement a PCP
service, durable grant store, revocation service, budget ledger, authenticated
transport, or durable Legatus journal. Those remain deployment dependencies.
