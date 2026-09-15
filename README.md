# Legatus v0.1

Legatus is a transport-independent coordination protocol for delegated work. It defines a signed envelope, a shared logical clock, typed state transitions, deterministic errors, recovery rules, and a causal transcript format.

MIT License. Copyright 2026 Sierra Catalina. See [LICENSE](LICENSE).

## Moves

Legatus v0.1 defines seven in-band moves:

1. **delegate** — assign work to a principal under an existing PCP grant
2. **handoff** — transfer control of an in-flight thread
3. **approve** — satisfy an authority or human gate
4. **fail** — record a failed thread or move while preserving retry eligibility
5. **retry** — begin a new attempt after failure on the same thread
6. **cancel** — stop a thread or move
7. **resume** — continue after a pause, timeout wait, or approval

Adding, renaming, or removing a move requires a new protocol version. Negotiation and access-grant lifecycle events stay outside the coordination state machine.

## Boundaries

| Component | Responsibility |
| --- | --- |
| **Legatus** | Envelope schema, seven moves, transition table, shared clock, typed errors, commit, timeout, recovery, and transcript format |
| **PCP** | Identity, authority grants, signer verification, reservation accounting, expiry, revocation, and recovery |
| **Context Layer** | Context bundles, policy, disclosure, and provenance |
| **Receipt system** | Evidence that an out-of-band action completed |
| **Product runtime** | Planning, routing, execution, and user interface |

A Legatus envelope may carry opaque references to neighboring systems. It does not contain grant bodies, private context, receipt bodies, or transport credentials.

## Protocol map

| Document | Contract |
| --- | --- |
| [Overview](spec/00-overview.md) | Scope, moves, boundaries, and versioning |
| [Envelope, transitions, clock, and errors](spec/01-envelope-transitions-clock-errors.md) | Normative in-band protocol |
| [Envelope extract](spec/envelope.md) | Compact schema and invariants |
| [Signer verification](spec/02-signer-verification.md) | Dependency on PCP identity and signature verification |
| [Runtime paths](spec/03-runtime-paths.md) | Commit, timeout, abort, recovery, and submission |
| [Conformance vectors](spec/04-conformance-vectors.md) | Portable protocol cases |
| [Causal transcript](spec/05-causal-transcript.md) | Human-readable thread export |
| [Operations harness](spec/06-ops-harness.md) | Retry, partition, recovery, and incident drills |
| [Transport and governance](spec/07-transport-governance.md) | Versioning, transport profiles, and interoperability |
| [Machine schemas](schemas/) | Bounded envelope, journal, response, PCP, and transcript contracts |
| [Conformance status](docs/harness.md) | Current evidence and its limits |
| [Known limitations](docs/known-limitations.md) | Open protocol issues that block production claims |

## Core invariants

- `legatus` is the integer **0**.
- Thread states are `void`, `running`, `awaiting_approve`, `paused`, `failed`, and `cancelled`.
- Completion evidence is represented by an out-of-band receipt.
- A timeout durably appends a journal record, pauses the thread, preserves envelope sequence, and preserves `pending`.
- Exactly one authoritative writer, a fenced linearizable lease, or consensus serializes journal appends.
- Every PCP authorization reservation resolves through idempotent `commit` after durable append or `release` after deterministic rejection.
- Each thread has at most one floor holder and one pending approval gate.
- A resume from `paused` with a frozen pending gate returns to `awaiting_approve` with the same pending identifier.
- A gated resume while another gate is frozen returns `LEGATUS_E_GATE_PENDING`.

## Implementation status

This repository includes a dependency-free Python reference model, a deterministic conformance runner, machine-readable JSON Schemas, and regression tests:

```shell
python -m conformance.run
python -m unittest discover -s tests -v
```

The runner exercises protocol transitions, durable timeout replay, writer fencing, PCP request/error mapping, reservation commit/release and crash reconciliation, strict bounds, idempotency, and the unsigned transcript marker. `JournalStore` is in-process test storage and `FixtureVerifier` performs no cryptography or budget accounting. Production conformance requires separate evidence for durable storage, distributed fencing or consensus, PCP cryptography and reservation persistence, transport adapters, and fault injection.
