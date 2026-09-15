# Causal transcript

A causal transcript exports one thread for inspection and interchange. The v0.1 transcript profile is explicitly an **unsigned fixture format**. It MUST NOT be described or accepted as cryptographically signed evidence.

## 1. Contents

The transcript includes:

- the state reconstructed from the durable journal;
- every committed envelope through `seq_through`, including its opaque PCP authorization identifier;
- every timeout record through `journal_through` in `clock_events`;
- request, move, approval, action, and receipt links; and
- `integrity: {"mode":"unsigned_fixture"}`.

Action and receipt links are opaque references. Their presence proves only that the exporter received structurally valid references. The owning action or receipt system must authenticate and authorize dereference.

## 2. Machine schema

[transcript.schema.json](../schemas/transcript.schema.json) is normative. Identifiers and arrays are bounded, unknown fields fail closed, and principals use PCP URNs.

```json
{
  "legatus": 0,
  "kind": "transcript",
  "thread": "thread-1",
  "seq_through": 2,
  "journal_through": 3,
  "now": 260,
  "state": "awaiting_approve",
  "floor": "urn:pcp:principal:alice",
  "principal": "urn:pcp:principal:alice",
  "pending": "env-1",
  "stop": null,
  "clock_events": [
    {"kind":"timeout","journal_position":2,"after_seq":1,"now":251,"deadline_now":250}
  ],
  "links": [
    {"role":"request","envelope":"env-1","task_ref":"work-1"},
    {"role":"move","envelope":"env-1","type":"delegate","seq":1,"signer":"urn:pcp:principal:alice","authorization_id":"authorization-1"},
    {"role":"move","envelope":"env-2","type":"resume","seq":2,"signer":"urn:pcp:principal:alice","authorization_id":"authorization-2"}
  ],
  "integrity": {"mode":"unsigned_fixture"}
}
```

The example is structurally complete. The conformance runner produces executable examples from the reference journal.

## 3. Link rules

1. Exactly one `request` link names the opening delegate and its `task_ref`.
2. One `move` link appears for every committed envelope, in envelope-sequence order, and carries that envelope record's opaque `authorization_id`.
3. One `approval` link follows each committed approve move.
4. Every action or receipt `after` value names a committed envelope on the thread.
5. A receipt action, when present, names an action link in the same transcript.
6. A cancelled transcript includes `stop` naming its cancel envelope and code.
7. `clock_events` includes every timeout record for the thread in journal order.
8. Grant bodies, reservation state, context bundles, receipt bodies, credentials, and chat text are excluded.

## 4. Integrity boundary

The `unsigned_fixture` marker is the only v0.1 integrity mode. A consumer requiring authenticated evidence MUST reject this profile and obtain the durable journal or a receipt from its owning system.

A future signed-transcript profile requires a new integrity mode and must define canonical bytes, signer identity, key selection, signature encoding, covered fields, verification, and replay handling.
