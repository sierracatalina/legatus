# Changelog

## v0.1 — 2026-09-15

- Defined the seven coordination moves, envelope, state machine, shared clock, typed errors, runtime paths, transcripts, transport profiles, conformance vectors, and operations drills.
- Assigned signer verification to PCP and completion evidence to a receipt system.
- Made timeout a durable, replay-validated journal record.
- Required one authoritative writer, a linearizable fenced lease, or consensus for append safety.
- Defined the `pcp-legatus-v1` verifier request, Ed25519/JCS proof binding, and proof-versus-authority error mapping.
- Defined PCP authorization reservation commit/release finalization, journal-bound recovery, and ambiguous-append reconciliation.
- Defined the collision-free PCP idempotency key over the exact thread/envelope JCS identity.
- Defined an explicit unsigned fixture transcript profile.
- Added bounded JSON Schemas for envelopes, journal records, acknowledgements, errors, PCP verification/finalization exchange, and transcripts.
- Added a dependency-free deterministic reference runner and regression tests.
