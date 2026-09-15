# Known limitations

Legatus v0.1 is a protocol draft with an executable in-process reference model.

## Defined in this revision

- Timeout is a durable journal record and replay preserves post-timeout legality.
- One authoritative writer, linearizable fencing, or consensus is mandatory for partition safety.
- The PCP profile binds protected key id, grant id, exact move purpose, signer, and unsigned envelope under Ed25519 over RFC 8785 JCS.
- PCP `allow` is an idempotent authorization reservation; Legatus records its identifier and finalizes deterministic commit or release outcomes.
- Envelope, journal, acknowledgement, error, verifier, PCP-result, finalization, and transcript schemas are bounded and machine-readable.
- Transcript fixtures carry the explicit `unsigned_fixture` integrity mode.

## Residual limits

### Storage and partition safety

`JournalStore` is an in-memory reference. It demonstrates monotonic writer epochs and atomic journal-position compare-and-set inside one process. It provides no disk durability, multi-process lease service, quorum, leader election, or consensus implementation.

### PCP cryptography

`FixtureVerifier` accepts only `SIG_PENDING` and performs no cryptography, grant lookup, expiry/revocation evaluation, or budget accounting. Its synthetic finalizer stores requests in memory. Production adapters must implement [the PCP verifier and reservation-finalization profile](../spec/02-signer-verification.md), persist PCP reservation state, and disable fixture verification.

The reference runtime can retry failed finalization during its process lifetime and reconstruct commit handoffs from journaled authorization identifiers after restart. A rejected candidate has no Legatus journal record, so a process crash can lose an in-memory release handoff. PCP reservation expiry bounds that case. Production deployments may add a durable outbox. Journal append and PCP finalization remain two systems joined through idempotency and reconciliation rather than one distributed transaction.

The in-process ambiguity resolver holds the fixture journal lock while calling the synthetic finalizer so its absence decision stays stable. A production adapter should use its fenced writer protocol and durable handoff mechanism; it should avoid holding a storage transaction open across PCP network I/O.

### Transcript evidence

The v0.1 transcript is an unsigned fixture export. Action and receipt references remain opaque until their owning systems authenticate and authorize them. An authenticated transcript requires a separately specified integrity profile.

### Transport and operations

The repository includes no HTTP, MCP, A2A, Nostr, or file adapter. The 64 KiB reference body limit, durable acknowledgement behavior, failover, crash recovery, and fault injection need validation in each production runtime.

### Scope of the runner

The deterministic runner covers the included reference cases. It provides no exhaustive model check, formal proof, production interoperability certificate, performance score, or availability claim.
