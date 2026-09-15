# Envelope extract

Normative detail lives in [01-envelope-transitions-clock-errors.md](01-envelope-transitions-clock-errors.md). The machine schema is [envelope.schema.json](../schemas/envelope.schema.json).

`legatus` is the integer **0**. Unknown top-level keys are `LEGATUS_E_SCHEMA`.

```json
{
  "legatus": 0,
  "id": "<envelope-id>",
  "thread": "<thread-id>",
  "type": "delegate" | "handoff" | "approve" | "fail" | "retry" | "cancel" | "resume",
  "parents": ["<envelope-id>", ...],
  "clock": {
    "seq": "<uint, gapless, first commit = 1>",
    "now": "<uint, non-decreasing, shared clock>",
    "ts": "<optional RFC3339; ignored for legality>"
  },
  "signer": "<urn:pcp:principal:…>",
  "payload": { },
  "sig": "<opaque; missing or empty = LEGATUS_E_SIG>"
}
```

## States

Exactly one per thread: `void` (not stored) / `running` / `awaiting_approve` / `paused` / `failed` / `cancelled`.

No in-band success. Completion is a receipt (out of band).

## Invariants

1. One floor per thread. Nested work is a new thread.
2. One pending gate per thread. Zero or one pending envelope id. Never two.
3. Committing an envelope is the only way a move happens.
4. Timeout is a no-envelope pause represented by a durable timeout journal record. It changes journal position and stored now while preserving envelope seq, floor, and pending.
5. **V-011 thaw:** resume from `paused` with a frozen pending MUST land `awaiting_approve` with the **same pending id**. MUST NOT go `running` with pending cleared. Discard is fail or cancel only.
6. **V-011b:** gated resume while a frozen pending exists is `LEGATUS_E_GATE_PENDING`.
7. After pending is gone, ungated resume from `paused` lands `running`; gated resume becomes the new pending.
8. Approve is illegal from `paused`.
9. `cancelled` is terminal (`LEGATUS_E_ALREADY_TERMINAL`).
10. Operator chat and agent-messaging UIs are never envelopes. A chat message is `NOT_A_SUBMIT`.
11. Signer, assignee, approver, and floor identifiers are PCP principal URNs and compare by exact equality.
12. A work-bearing move replaces the active deadline; omission clears it. Approve preserves its pending move's deadline. Fail and cancel clear it.

## Payload keys (strict)

| type | required | conditional | optional |
| --- | --- | --- | --- |
| delegate | `assignee`, `task_ref` | `approver` iff `gate` true | `gate` (default false), `deadline_now` |
| handoff | `to` | `approver` iff `gate` true | `gate` (default false), `deadline_now` |
| approve | `of` | | |
| fail | `code` (`FAIL_TIMEOUT` \| `FAIL_REFUSED` \| `FAIL_FAULT` \| `FAIL_OTHER`) | | `of`, `note` |
| retry | `of` | `approver` iff `gate` true | `assignee`, `gate`, `deadline_now` |
| cancel | `code` (`CANCEL_STOP` \| `CANCEL_SUPERSEDED` \| `CANCEL_OTHER`) | | `of`, `note` |
| resume | | `approver` iff `gate` true | `of`, `gate`, `deadline_now` (omit to clear) |
