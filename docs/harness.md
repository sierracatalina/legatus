# Conformance status

Legatus includes a deterministic, dependency-free Python reference model and regression suite. They execute locally without network, key, clock, or service access.

## Run

From the repository root:

```shell
python -m conformance.run
python -m unittest discover -s tests -v
bash scripts/leak-scan.sh .
bash scripts/test-leak-scan.sh
```

The runner writes one stable JSON report to standard output and exits nonzero when a case fails. The release-scan regression covers both a linked-worktree `.git` pointer and a matching path inside a release file. The executable checks cover:

- all seven moves across a lifecycle and approval flow;
- durable timeout, post-timeout resume, replay, and timeout-record tamper rejection;
- writer-epoch fencing and journal-position compare-and-set;
- exact PCP verifier request binding and proof/authority error mapping;
- collision-free PCP idempotency-key derivation from the exact two-field JCS identity;
- PCP reservation commit, deterministic release, failed-finalizer retry, and ambiguous-append reconciliation;
- bounded envelope validation and duplicate JSON-member rejection;
- duplicate acknowledgement semantics; and
- the explicit unsigned fixture transcript profile.

The regression tests inspect the same behaviors at smaller boundaries, including recovery and malformed verifier results. Written portable cases remain in [the conformance vectors](../spec/04-conformance-vectors.md), with distributed failure drills in [the operations harness](../spec/06-ops-harness.md).

## Determinism

The suite supplies every logical-clock value and uses an in-memory append-only journal. `FixtureVerifier` accepts only `SIG_PENDING`; it performs no cryptography or budget accounting. Its finalizer records deterministic synthetic commit and release handoffs. The code has no network client, environment-secret lookup, wall-clock read, random source, or external service call.

## Claim boundary

A passing local report establishes consistency between the included reference model, schemas, and covered fixtures at the tested revision. Production conformance also requires:

- a durable journal with atomic append and crash testing;
- a linearizable fenced lease or consensus implementation;
- an actual PCP Ed25519/JCS verifier integration;
- a durable PCP reservation ledger and idempotent finalization integration;
- transport-adapter and body-limit tests;
- authenticated action and receipt evidence; and
- published environment, revision, result artifact, and fault-injection evidence.

The suite publishes no latency, throughput, availability, or production-readiness score.
