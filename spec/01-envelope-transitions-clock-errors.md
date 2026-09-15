# Envelope, transitions, clock, and errors

This is the normative in-band contract for the envelope schema, seven move types, transition table, shared logical clock, and typed errors.

**V-011** and **V-011b** clarify frozen approval gates: timeout preserves `pending`, and a gated resume while another gate is frozen returns `GATE_PENDING`. See §5.

---

## 1. Objects

A **thread** is the unit of coordination. It has an id, a principal (the opener), a floor holder, a state, a seq, a now, and at most one pending gated envelope.

An **envelope** is one signed move on one thread. Exactly one of the seven types. Committing an envelope is the only way a move happens. Clock timeout is not an envelope (see §6).

**Floor** is the principal id allowed to append the next floor-held move. Approve is not floor-held. Cancel and fail may be signed by floor or by the thread principal.

v0 is **one floor per thread** and **one pending gate per thread**. Nested work is a new thread (new delegate, new thread id), not a second floor on the same thread.

---

## 2. Envelope schema

The normative machine contract is [envelope.schema.json](../schemas/envelope.schema.json). It uses JSON Schema draft 2020-12. Unknown keys, duplicate JSON members, out-of-range values, and invalid payload branches fail closed. `legatus` must be the integer `0`.

```json
{
  "legatus": 0,
  "id": "<envelope-id>",
  "thread": "<thread-id>",
  "type": "delegate" | "handoff" | "approve" | "fail" | "retry" | "cancel" | "resume",
  "parents": ["<envelope-id>", ...],
  "clock": {
    "seq": <uint>,
    "now": <uint>,
    "ts": "<RFC3339>"
  },
  "signer": "<principal-id>",
  "payload": { },
  "sig": "<opaque>"
}
```

### Field rules

- `id` and `thread` are 1–256 character opaque strings without control characters. Envelope identifiers are unique across one durable journal.
- `signer`, assignee, approver, and floor values are PCP principal URNs matching `urn:pcp:principal:…`. v0 compares these identifiers for exact equality when checking floor and approval authority.
- `type` is one of the seven. `negotiate`, `legation`, `recusal`, `recall`, `post`, `claim`, `lease`, `progress`, `complete`, `attest`, and any other string are `LEGATUS_E_UNKNOWN_TYPE`.
- `parents` is a duplicate-free array of at most 32 envelope ids. First envelope of a thread: `[]`. Every later envelope: at least the previous committed id in this thread.
- `clock.seq` is a gapless safe integer from 1 through 9,007,199,254,740,991.
- `clock.now` is a non-decreasing safe integer from 0 through 9,007,199,254,740,991. It is not wall time.
- `clock.ts` is optional RFC3339. Informational. Ignored for legality.
- A supplied `deadline_now` must be greater than or equal to both the envelope `clock.now` and any independently authoritative runtime now used for that submission. An already-expired new deadline is `LEGATUS_E_CLOCK_SKEW`.
- `payload` matches §3 for that type. Extra payload keys are `LEGATUS_E_SCHEMA`.
- `sig` is a required opaque PCP detached proof of 1–4,096 characters. Missing, malformed, or cryptographically invalid proof is `LEGATUS_E_SIG`. Grant and authority denials retain their out-of-band PCP disposition. See [signer verification](02-signer-verification.md).

No vault body, no grant body, no bundle, no receipt document, no transport metadata on this object.

---

## 3. Payload by move

All payload values that are principal ids are opaque strings. `task_ref` is an opaque string the rail does not interpret (not a Context Layer type).

### 3.1 delegate

- `assignee` string, required
- `task_ref` string, required, opaque
- `gate` boolean, default false
- `approver` string, required if `gate` is true, forbidden if false
- `deadline_now` uint, optional

Opens a thread. Illegal if thread already exists.

For `delegate`, `handoff`, `retry`, and `resume`, `deadline_now` replaces the active deadline. Omission clears it. Approve preserves the deadline carried by its pending move. Fail and cancel clear it.

### 3.2 handoff

- `to` string, required
- `gate` boolean, default false
- `approver` string, required if `gate` is true, forbidden if false
- `deadline_now` uint, optional

### 3.3 approve

- `of` string, required: envelope id of the pending gated move

Approve is positive only. Deny is fail or cancel. No `decision` field.

### 3.4 fail

- `of` string, optional: envelope id (default: last committed)
- `code` one of `FAIL_TIMEOUT` | `FAIL_REFUSED` | `FAIL_FAULT` | `FAIL_OTHER`, required
- `note` string, optional, non-normative

### 3.5 retry

- `of` string, required: the fail envelope id being retried
- `assignee` string, optional (default: assignee from the last delegate or retry on this thread)
- `gate`, `approver`, `deadline_now` as in delegate

### 3.6 cancel

- `of` string, optional
- `code` one of `CANCEL_STOP` | `CANCEL_SUPERSEDED` | `CANCEL_OTHER`, required
- `note` string, optional, non-normative

### 3.7 resume

- `of` string, optional (default: last committed)
- `gate`, `approver` as in handoff
- `deadline_now` uint, optional (new deadline; omit to clear)

---

## 4. Thread states

Exactly one:

- **void** — no thread yet (not stored)
- **running**
- **awaiting_approve**
- **paused** — timeout path fired; the journal contains a timeout record, while envelope sequence remains unchanged
- **failed** — non-terminal until cancel; retry is legal
- **cancelled** — terminal

There is **no in-band success state**. Completion is a receipt. Receipts are out of band. A thread that finished work and was not failed or cancelled stays `running` until cancel (or is left running). Product layers may cancel with `CANCEL_STOP` after they see a receipt. Legatus does not wait on that receipt.

---

## 5. Transition table

Apply in this order: schema, type, duplicate id, thread and causality, clock, PCP proof, terminal state, signer/floor, then this table. First matching failure wins. The timeout ordering in §6 may append an independent clock record before the table is re-evaluated.

| From | Move | To | Notes |
| --- | --- | --- | --- |
| void | delegate, gate=false | running | Opener = signer. Floor = assignee. seq=1. |
| void | delegate, gate=true | awaiting_approve | Opener = signer. Floor stays opener until approve. pending = this envelope. |
| void | any other | — | `LEGATUS_E_ILLEGAL_TRANSITION` |
| running | handoff, gate=false | running | Floor = `to`. |
| running | handoff, gate=true | awaiting_approve | Floor unchanged until approve. pending = this envelope. |
| running | fail | failed | |
| running | cancel | cancelled | Terminal. |
| running | delegate / approve / retry / resume | — | `LEGATUS_E_ILLEGAL_TRANSITION`. New work is a new thread. |
| awaiting_approve | approve | running | `of` must equal `pending.id`. Then apply the pending move’s floor effect. pending cleared. |
| awaiting_approve | fail | failed | pending discarded. |
| awaiting_approve | cancel | cancelled | pending discarded. Terminal. |
| awaiting_approve | any other | — | `LEGATUS_E_GATE_PENDING` |
| paused | resume, gate=false, **frozen pending** | awaiting_approve | **V-011 thaw.** Same pending id. MUST NOT go running with pending cleared. |
| paused | resume, gate=false, **pending null** | running | After pending is gone. |
| paused | resume, gate=true, **frozen pending** | — | **V-011b** `LEGATUS_E_GATE_PENDING`. Do not drop the frozen gate. |
| paused | resume, gate=true, **pending null** | awaiting_approve | pending = this envelope. |
| paused | fail | failed | pending discarded. |
| paused | cancel | cancelled | Terminal. pending discarded. |
| paused | any other | — | `LEGATUS_E_ILLEGAL_TRANSITION` |
| failed | retry, gate=false | running | `of` must be the fail envelope. Floor = assignee. |
| failed | retry, gate=true | awaiting_approve | pending = this envelope. |
| failed | cancel | cancelled | Terminal. |
| failed | any other | — | `LEGATUS_E_ILLEGAL_TRANSITION` |
| cancelled | any | — | `LEGATUS_E_ALREADY_TERMINAL` |

Approve of a pending delegate: after approve, floor = that delegate’s assignee.

Approve of a pending handoff: floor = that handoff’s `to`.

Approve of a pending retry: floor = that retry’s assignee.

Approve of a pending resume: floor unchanged.

At most one pending. A second gated move while `awaiting_approve` is `LEGATUS_E_GATE_PENDING`.

### V-011 thaw (normative)

Timeout does not discard pending. Approve is illegal from `paused`, so resume is the thaw.

If the thread entered pause with a pending gated envelope, resume (`gate=false`) **MUST** land in `awaiting_approve` with that same pending id. It **MUST NOT** go to `running` with pending cleared. Discarding pending is **fail or cancel only**.

Collision: v0 one-pending. A gated resume while a frozen gate exists is `LEGATUS_E_GATE_PENDING` (V-011b). Do not drop the frozen gate to make room, including on ungated resume. Fail or cancel the frozen gate first. After pending is gone, ungated resume from paused lands `running`; gated resume becomes the new pending.

---

## 6. Commit, timeout, and abort paths

These are not extra move types.

- **Commit:** the envelope passed every check and the thread was updated. `seq` becomes this envelope’s seq. `now` becomes this envelope’s now if greater.
- **Timeout:** if the thread is `running` or `awaiting_approve`, an active `deadline_now` exists, and authoritative now is greater than that deadline, the writer durably appends a timeout journal record and sets state to `paused`. The record is not an envelope and does not advance envelope `seq`. It preserves floor and pending. Next legal moves: resume, fail, cancel.
- **Abort:** a committed cancel.

---

## 7. Shared clock

One logical clock per thread, two integers:

- **seq:** gapless, starts at 1, plus one per committed envelope. An envelope with `seq != thread.seq + 1` (or `!= 1` when void) is `LEGATUS_E_CLOCK_SKEW`.
- **now:** non-decreasing. An envelope with `now < thread.now` is `LEGATUS_E_CLOCK_SKEW`. Equal now is legal. A candidate's now becomes an authoritative clock observation only after proof and floor eligibility succeed; rejected outsiders cannot force timeout. Runtimes may also supply an independently authoritative now. Wall-clock `ts` is not used for legality.

Deadline is a now value, not a seq and not a timestamp. A timeout journal record makes the clock transition replayable without adding an eighth move.

Duplicate envelope id: `LEGATUS_E_DUP_ID`. Replay of a committed id is not a new commit.

---

## 8. Causality

- Every parent id must be a committed envelope on the same thread. Else `LEGATUS_E_CAUSALITY`.
- Envelope thread must equal the thread of every parent. Else `LEGATUS_E_THREAD_MISMATCH`.
- First envelope: parents empty. Non-first: parents must include the immediately previous committed id.
- Non-first envelope with empty parents: `LEGATUS_E_MISSING_PARENT` (causality subclass; use this when `parents` is `[]`).
- Happens-before is the transitive closure of parents. v0 is a single chain (one floor). Branches are a new thread.

---

## 9. Floor and signer

| Move | Signer must be | Else |
| --- | --- | --- |
| delegate (open) | the opener (any principal; becomes `thread.principal`) | — |
| handoff | floor | `LEGATUS_E_NO_FLOOR` |
| approve | `pending.approver` | `LEGATUS_E_NOT_APPROVER` |
| fail | floor or `thread.principal` | `LEGATUS_E_NO_FLOOR` |
| retry | `thread.principal` | `LEGATUS_E_NO_FLOOR` |
| cancel | floor or `thread.principal` | `LEGATUS_E_NO_FLOOR` |
| resume | floor | `LEGATUS_E_NO_FLOOR` |

After a successful ungated handoff, the previous floor is stale. A later envelope signed by the old floor is `LEGATUS_E_STALE_FLOOR` (same class as no floor; prefer this code when a prior handoff exists).

---

## 10. Typed errors

A rejected envelope is not committed. The candidate itself does not advance `seq` or `now`. A timeout that became due before transition evaluation may independently append and advance stored now.

**First-match order:** `SCHEMA`, `UNKNOWN_TYPE`, `DUP_ID`, `THREAD_MISMATCH`, `MISSING_PARENT`, `CAUSALITY`, `CLOCK_SKEW`, `SIG`, `ALREADY_TERMINAL`, `NO_FLOOR`, `STALE_FLOOR`, `NOT_APPROVER`, `GATE_PENDING`, `ILLEGAL_TRANSITION`.

| Code | Meaning |
| --- | --- |
| `LEGATUS_E_SCHEMA` | Missing required field, wrong JSON type, unknown key, payload shape wrong for the move. |
| `LEGATUS_E_UNKNOWN_TYPE` | `type` is not one of the seven. |
| `LEGATUS_E_DUP_ID` | `id` already committed. |
| `LEGATUS_E_THREAD_MISMATCH` | thread id disagrees with parents or with an existing thread. |
| `LEGATUS_E_CAUSALITY` | parent missing, not committed, or not previous. |
| `LEGATUS_E_MISSING_PARENT` | non-first envelope with empty parents. (Causality subclass; use this when `parents` is `[]`.) |
| `LEGATUS_E_CLOCK_SKEW` | seq not prev+1, or now went backwards. |
| `LEGATUS_E_SIG` | proof missing/malformed, signer is not a PCP principal URN, or PCP reports an invalid proof/signature. |
| `LEGATUS_E_NO_FLOOR` | signer is not allowed to append this move. |
| `LEGATUS_E_STALE_FLOOR` | signer held floor before a committed handoff. |
| `LEGATUS_E_NOT_APPROVER` | approve signed by someone other than `pending.approver`. |
| `LEGATUS_E_GATE_PENDING` | thread is `awaiting_approve` and the move is not approve, fail, or cancel; **or** (V-011b) gated resume while a frozen pending exists. |
| `LEGATUS_E_ALREADY_TERMINAL` | thread is `cancelled`. |
| `LEGATUS_E_ILLEGAL_TRANSITION` | move is not in the table for this state. |

`LEGATUS_E_WRITER_UNAVAILABLE` and `NOT_A_SUBMIT` are pre-protocol operational errors defined by [error.schema.json](../schemas/error.schema.json). PCP grant denials use [pcp-result.schema.json](../schemas/pcp-result.schema.json). Vault and receipt failures remain out of band.

---

## 11. Out of band (explicit)

Not in this contract:

- PCP grants, expiry, revocation, recovery, key ceremony
- Context Layer vault, bundles, policy, claim annotations
- receipt cryptography and receipt bodies
- product planning, routing, and execution
- transport (nostr, MCP, A2A, HTTP, file)
- operator chat and agent-messaging UIs. They are not a submit surface. A chat message is `NOT_A_SUBMIT`. No operator-chat message is a conforming envelope.

---

## 12. Conformance

A runtime conforms to this specification when it accepts every legal envelope, rejects every illegal envelope with the first-match code, persists timeout records in journal order, fences stale writers, keeps one floor and one pending gate per thread, honors V-011 and V-011b, and passes the executable conformance runner.

This repository currently publishes specification text and written fixtures without a production runtime.

---

## 13. Example (informative) — gated delegate

```json
{
  "legatus": 0,
  "id": "env_1",
  "thread": "thr_1",
  "type": "delegate",
  "parents": [],
  "clock": { "seq": 1, "now": 100, "ts": "2026-08-28T20:40:00Z" },
  "signer": "urn:pcp:principal:alice",
  "payload": {
    "assignee": "urn:pcp:principal:worker",
    "task_ref": "work-1",
    "gate": true,
    "approver": "urn:pcp:principal:alice",
    "deadline_now": 250
  },
  "sig": "opaque"
}
```

State after commit: `awaiting_approve`, floor remains the opener, and pending=`env_1`. If now exceeds 250 first, the journal records timeout before state becomes `paused`; pending remains `env_1`.
