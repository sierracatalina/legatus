# Runtime paths: commit, timeout, abort, and recovery

This document defines the durable journal and single-writer rules used to apply the [core protocol](01-envelope-transitions-clock-errors.md).

## 1. Durable journal

A runtime keeps one append-only journal. It contains two record kinds:

- `envelope` — one committed Legatus envelope
- `timeout` — a runtime-generated clock event that durably records a transition to `paused`

The [journal record schema](../schemas/journal-record.schema.json) bounds both kinds. `position` is gapless across the journal. `writer_epoch` is monotonic and identifies the writer lease that appended the record. Each envelope record carries the opaque PCP `authorization_id` returned for that exact candidate. Envelope `clock.seq` counts envelopes only; a timeout record advances journal position while preserving envelope sequence.

Thread state is the deterministic fold of journal records in position order. RAM state, queues, transport messages, and chat content are excluded from the fold.

## 2. Single-writer safety

Exactly one authoritative writer may acknowledge appends for a thread at any instant. Every envelope or timeout append MUST be one atomic transaction that:

1. verifies the current writer lease or consensus term;
2. compares the expected journal position and thread sequence with durable state;
3. appends one record and applies its state change; and
4. makes the record durable before returning an acknowledgement.

A deployment may use one durable process, a fenced lease backed by a linearizable store, or a consensus group. Read replicas never acknowledge commits. A stale or isolated writer returns retriable `LEGATUS_E_WRITER_UNAVAILABLE` before protocol evaluation and appends nothing.

The reference `JournalStore` demonstrates the fencing and compare-and-set contract in one process. It does not implement distributed consensus.

## 3. Commit path

An authoritative writer processes a candidate in this order:

1. parse one JSON object and reject duplicate members;
2. apply bounded schema and type checks;
3. resolve duplicate envelope identifiers;
4. persist any timeout due under an independently authoritative runtime clock value;
5. check thread, causality, sequence, and clock;
6. request the PCP disposition defined by [signer verification](02-signer-verification.md);
7. check floor, approver, pending gate, terminal state, and transition legality;
8. after proof and floor eligibility succeed, treat the candidate `clock.now` as an authenticated clock observation, persist any resulting timeout, and re-evaluate transition legality; and
9. atomically append and apply one envelope journal record containing the PCP authorization identifier; and
10. send PCP an idempotent `commit` finalization naming the envelope, thread, and durable journal position.

A rejected candidate appends no envelope record. A timeout persisted at step 4 remains a valid independent clock event. When PCP already returned `allow`, a deterministic floor, gate, transition, or timeout-induced transition rejection sends PCP an idempotent `release` finalization.

An accepted candidate returns [ack.schema.json](../schemas/ack.schema.json) with `outcome: committed`. The acknowledgement includes the envelope sequence, durable journal position, PCP authorization identifier, and authorization state. `authorization_state: committed` means PCP acknowledged the commit finalization. `reconciliation_required` means the journal commit is durable and the idempotent PCP handoff still needs retry.

### Idempotency

Envelope identifiers are unique across one journal. Identical canonical candidate content submitted under an already committed identifier returns the original acknowledgement with `outcome: duplicate`; no journal record is appended. Different content under that identifier returns `LEGATUS_E_DUP_ID` using [error.schema.json](../schemas/error.schema.json).

An identical duplicate also retries the original PCP `commit` finalization. It never asks PCP to verify a new proof or reserves budget a second time.

## 4. Durable timeout path

When state is `running` or `awaiting_approve`, an active deadline exists, and authoritative `runtime.now > deadline_now`, the writer atomically appends a timeout journal record before changing state.

The record captures `thread`, `after_seq`, `now`, `deadline_now`, and the pending envelope identifier or null. Applying it:

1. sets state to `paused`;
2. preserves envelope sequence, floor, and pending;
3. advances the stored logical-clock value to the record’s `now`; and
4. permits only `resume`, `fail`, or `cancel` next.

Timeout remains outside the seven move types and appends no envelope. A runtime MUST reject a timeout record whose prior state, deadline, sequence, or pending identifier does not match the journal fold.

The writer evaluates timeout whenever its authoritative logical clock advances and immediately before transition evaluation. A candidate cannot bypass a due timeout by advancing `clock.now`; after its proof and floor eligibility succeed, the timeout record is appended before its move. A malformed proof, unauthorized signer, or otherwise ineligible candidate cannot force a timeout through an untrusted clock value. A resume following timeout is therefore ordered after a durable timeout record and remains legal after a crash.

## 5. Abort path

Abort is a committed `cancel` envelope. It moves the thread to `cancelled`, clears pending and floor, preserves the full journal, and makes every later envelope illegal.

## 6. Recovery

Recovery starts from `void` and folds every journal record in ascending position:

1. reject gaps, duplicate positions, decreasing writer epochs, duplicate envelope identifiers, invalid envelopes, or invalid timeout records;
2. apply envelope and timeout records exactly where they occur;
3. rebuild acknowledgements with `authorization_state: reconciliation_required` until PCP confirms journaled commits;
4. acquire a current writer lease before accepting new work; and
5. append a timeout record before accepting a candidate if the recovered thread has crossed an active deadline.

The same journal produces the same state. A supplied later clock may cause the authoritative writer to append one new timeout record during recovery. Recovery never reconstructs an unrecorded historical timeout between committed envelopes.

### PCP handoff recovery

Recovery reconstructs a `commit` handoff for every observed envelope record using its journaled authorization identifier and position. The caller invokes the idempotent PCP reconciliation step after replay. A crash after append and before PCP response therefore converges through the journal without treating replay alone as PCP confirmation.

A compare-and-set rejection after PCP `allow` has an ambiguous result until a fresh fenced read completes. The adapter keeps the reservation live, reloads the authoritative journal, and resolves by exact envelope identifier, canonical candidate, and authorization identifier. A matching record commits. Proven absence releases. Authorization identity conflict remains pending and emits no release.

An in-memory failed `release` request may be retried idempotently. PCP owns reservation expiry for a process crash before any envelope journal record exists. Production adapters may add a durable outbox while preserving the exact finalization request schema.

## 7. Submit and response surfaces

Transport carries one candidate JSON object. The runtime returns exactly one of:

- a Legatus acknowledgement;
- a Legatus error;
- an out-of-band PCP authority result; or
- a transport-level availability failure before the authoritative writer receives the candidate.

Natural-language messages and arbitrary inter-agent objects return `NOT_A_SUBMIT`. A transport MUST reject payloads exceeding 64 KiB before parsing.

## 8. Conformance requirements

A conforming runtime MUST:

1. preserve journal order and durability across crash recovery;
2. record timeout before any post-timeout envelope;
3. serialize appends through one authoritative writer or consensus group;
4. fence stale writers and use atomic compare-and-set;
5. pass the PCP verifier request without interpreting its opaque proof;
6. distinguish invalid proof from PCP authority denial;
7. implement typed acknowledgement and error schemas; and
8. couple PCP reservations to deterministic commit or release finalization; and
9. preserve the journal when a thread fails or is cancelled.

The implementation of distributed consensus, PCP cryptography, context disclosure, receipt verification, and product execution remains outside this repository.
