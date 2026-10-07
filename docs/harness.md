# Conformance status

Legatus includes a deterministic, dependency-free Python reference model and an optional Ed25519/JCS PCP adapter. Full regression checks require `requirements.txt`; they use synthetic keys and trusted callback doubles without external service access.

## Run

From the repository root:

```shell
python -m conformance.run
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m conformance.trace
bash scripts/leak-scan.sh .
bash scripts/test-leak-scan.sh
python scripts/check_pcp_schemas.py
```

The runner writes one stable JSON report to standard output and exits nonzero when a case fails. The release-scan regression covers both a linked-worktree `.git` pointer and a matching path inside a release file. The executable checks cover:

- all seven moves across a lifecycle and approval flow;
- durable timeout, post-timeout resume, replay, and timeout-record tamper rejection;
- writer-epoch fencing and journal-position compare-and-set;
- exact PCP verifier request binding and proof/authority error mapping;
- real Ed25519 proof verification, independent Unicode signature bytes, fail-closed trusted-key binding, and strict PCP callback results;
- byte-identical upstream PCP schema pins and drift detection;
- collision-free PCP idempotency-key derivation from the exact two-field JCS identity;
- PCP reservation commit, deterministic release, failed-finalizer retry, and ambiguous-append reconciliation;
- bounded envelope validation and duplicate JSON-member rejection;
- duplicate acknowledgement semantics; and
- the explicit unsigned fixture transcript profile.
- optional execution-profile task digest checks, separate PCP action-authority and Context Layer disclosure-authorization gates, handoff recipient refresh, stale-view refusal, PCP-finalization gating, and replayable fork classification.

The regression tests inspect the same behaviors at smaller boundaries, including recovery and malformed verifier results. Written portable cases remain in [the conformance vectors](../spec/04-conformance-vectors.md), with distributed failure drills in [the operations harness](../spec/06-ops-harness.md).

## Determinism

The fixture runner supplies every logical-clock value and uses an in-memory append-only journal. Explicit fixture mode accepts only `SIG_PENDING`; its finalizer records synthetic commit and release handoffs. Separate adapter tests use a fixed public signature fixture and ephemeral synthetic keys. The runtime performs no network client or environment-secret lookup; trusted deployment callbacks provide live PCP state.

## Claim boundary

A passing local report establishes consistency between the included reference model, schemas, and covered fixtures at the tested revision. Production conformance also requires:

- a durable journal with atomic append and crash testing;
- a linearizable fenced lease or consensus implementation;
- independently authenticated principal key resolution and live PCP grant authorization for the Ed25519/JCS adapter;
- a durable PCP reservation ledger and idempotent finalization integration;
- transport-adapter and body-limit tests;
- authenticated action and receipt evidence; and
- immutable task storage, a real PCP action-grant verifier, a real Context Layer disclosure verifier, and an effect-side fence for the optional execution profile; and
- published environment, revision, result artifact, and fault-injection evidence.

The suite publishes no latency, throughput, availability, or production-readiness score.
