# Execution authority profile (out of band)

Legatus coordinates a floor holder. A committed move does not authorize reading task content, using Context Layer data, or sending an external effect. This optional profile defines the checks a product adapter must make at the point it reads a task and again at each effect dispatch. It preserves the v0 envelope, seven moves, PCP proof object, and core error order.

## Digest-bound task

For work using this profile, the opening signed `delegate.payload.task_ref` MUST be `sha256:` followed by 64 lowercase hexadecimal characters. The digest is SHA-256 of the exact immutable task manifest bytes. The product owns the manifest format, but those bytes MUST include a format/version marker and every field that can change the action's meaning, including instructions, arguments, resource targets, and any referenced revision. A referenced subresource must itself be immutable or digest-bound. A mutable URL, branch, issue number, or database row by itself is insufficient.

Before task interpretation and again before an effect, the adapter MUST fetch the pinned bytes, recompute the digest, and reject absence or mismatch. It MUST execute the bytes that were checked. The PCP detached proof already covers the signed `task_ref` through the envelope; this profile adds the byte-to-reference check. Legacy opaque `task_ref` values remain legal in core Legatus, but they are ineligible for this execution profile.

## Current floor, PCP grant, and Context Layer disclosure

At each effect dispatch, the adapter MUST read one current, authenticated, fenced journal view. It requires `running`, a current floor holder, no due timeout under an authoritative clock, and completed PCP commit finalization for the committed moves on the thread. It derives the **floor event** that installed the current floor: an ungated `delegate`, `handoff`, or `retry`, or the `approve` that completed a gated one. A handoff to the same principal still creates a new floor event. For an initially gated delegate, the opener holds the floor until approval; the approval installs the assignee and names the opener as `from_principal`.

The adapter MUST first obtain PCP action authorization under a live principal-signed grant for the current floor, requested action, destination, purpose, task digest, and current installation event. A committed Legatus move and completed PCP reservation finalization do not replace this action-time grant check.

The adapter MUST then ask a trusted Context Layer verifier to authenticate fresh recipient-bound disclosure authorization. The verification request binds `thread`, `from_principal` (null on initial delegation), `to_principal`/`recipient` (the current floor), `task_ref`, `task_digest`, `installing_envelope_id`, `installing_journal_position`, current `journal_position`, the PCP `grant_ref`, requested action, destination and purpose, and the opaque `disclosure_ref`. The verifier MUST check the bundle's issuer, integrity, recipient, disclosure policy, expiry, revocation, and issuance for that exact installation event. A bundle issued for a previous holder or prior event fails, including after a gated handoff whose effective event is the `approve`. An unverified field copied from a bundle is not evidence. Legatus never reissues a Context Layer bundle; the product obtains fresh disclosure authorization after the floor transfer commits.

The Context Layer verifier decides whether each particular context value may flow to each proposed action, destination, and purpose. Its approval authorizes bounded context access and onward disclosure only; it never supplies acting authority. The action adapter MUST satisfy both the PCP grant and the narrower Context Layer disclosure decision before dispatch.

## Effect fence and failure

The checks and effect dispatch MUST share a fence that prevents a later handoff, cancellation, timeout, or writer change from overtaking the authorized effect. A production adapter needs a durable journal-position precondition and an effect-side idempotency/fencing mechanism, or another transactionally equivalent design. If it cannot maintain that condition, it denies or retries without dispatching an effect. An authenticated fork quarantines the thread and stops effects until one history is chosen by the deployment's incident process; histories are never merged.

Profile denial is out of band. It does not add a Legatus move, mutate the journal, or fabricate a receipt. The Python [`run_authorized`](../conformance/execution_profile.py) helper exercises these checks with one in-process lock and separate synthetic PCP action-authority and Context Layer disclosure-authorization callbacks. The callbacks perform no cryptography; its lock is not a distributed effect fence. The helper's `LEGATUS_PROFILE_E_*` exceptions are fixture results, not core protocol error codes.

## Conformance evidence

Product conformance to this profile requires tests with an actual PCP grant verifier, a durable fenced journal, immutable task storage, a Context Layer disclosure issuer/verifier, and an effect adapter. Tests must cover altered task bytes, mutable task references, missing or invalid action grants, prior-recipient bundles, same-recipient and gated handoffs, expiry/revocation, stale readers/writers, a due timeout, PCP finalization uncertainty, and fork quarantine. The local reference tests cover deterministic boundary behavior only. Run `python -m conformance.trace` for the synthetic grant → disclosure → execution trace.
