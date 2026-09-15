# Conformance vectors

These fixtures exercise the [core protocol](01-envelope-transitions-clock-errors.md) and [runtime paths](03-runtime-paths.md). The dependency-free runner uses an explicit fixture verifier; signature cryptography remains a PCP dependency.

---

## 0. How to read a vector

Each vector is one step. `setup` is the thread after the named vector’s successful commit (or empty). `now` is the runtime clock at submit time. `candidate` is one JSON object, or none (timeout/checkout only).

The fixture proof is `SIG_PENDING`. The fixture verifier accepts that exact string and performs no cryptography. An “invalid signer” here is a wrong principal identifier, not a malformed signature.

Throwaway principals: **A** = `urn:pcp:principal:a`, **B** = `urn:pcp:principal:b`, **C** = `urn:pcp:principal:c`, and **X** = `urn:pcp:principal:x`. Thread `t1`. Envelope ids `e1`, `e2`, …

Expected is either a first-match error code (no commit) or a thread snapshot after commit/timeout/checkout: state, floor, pending, seq, `deadline_now`.

Omitted payload keys use the core-protocol defaults (`gate` false). `clock.ts` is omitted and ignored.

---

## 1. Positive: seven moves

### V-001 ungated delegate opens

setup: empty. now: 100. kind: positive.

```json
{"legatus":0,"id":"e1","thread":"t1","type":"delegate","parents":[],"clock":{"seq":1,"now":100},"signer":"urn:pcp:principal:a","payload":{"assignee":"urn:pcp:principal:b","task_ref":"work-1","gate":false},"sig":"SIG_PENDING"}
```

expected: commit. state=`running`, floor=`B`, pending=null, seq=1, deadline_now=null. SIG_PENDING.

### V-002 gated delegate

setup: empty. now: 100. kind: positive.

```json
{"legatus":0,"id":"e1","thread":"t1","type":"delegate","parents":[],"clock":{"seq":1,"now":100},"signer":"urn:pcp:principal:a","payload":{"assignee":"urn:pcp:principal:b","task_ref":"work-1","gate":true,"approver":"urn:pcp:principal:a","deadline_now":250},"sig":"SIG_PENDING"}
```

expected: commit. state=`awaiting_approve`, floor=`A`, pending=`e1`, seq=1, deadline_now=250. SIG_PENDING.

### V-003 approve gated delegate

setup: V-002. now: 110. kind: positive.

```json
{"legatus":0,"id":"e2","thread":"t1","type":"approve","parents":["e1"],"clock":{"seq":2,"now":110},"signer":"urn:pcp:principal:a","payload":{"of":"e1"},"sig":"SIG_PENDING"}
```

expected: commit. state=`running`, floor=`B`, pending=null, seq=2, deadline_now=250. SIG_PENDING.

### V-004 handoff ungated

setup: V-001. now: 120. kind: positive.

```json
{"legatus":0,"id":"e2","thread":"t1","type":"handoff","parents":["e1"],"clock":{"seq":2,"now":120},"signer":"urn:pcp:principal:b","payload":{"to":"urn:pcp:principal:c","gate":false},"sig":"SIG_PENDING"}
```

expected: commit. state=`running`, floor=`C`, pending=null, seq=2. SIG_PENDING.

### V-005 fail from running

setup: V-001. now: 120. kind: positive.

```json
{"legatus":0,"id":"e2","thread":"t1","type":"fail","parents":["e1"],"clock":{"seq":2,"now":120},"signer":"urn:pcp:principal:b","payload":{"code":"FAIL_FAULT"},"sig":"SIG_PENDING"}
```

expected: commit. state=`failed`, floor=`B`, pending=null, seq=2. SIG_PENDING.

### V-006 retry after fail

setup: V-005. now: 130. kind: positive.

```json
{"legatus":0,"id":"e3","thread":"t1","type":"retry","parents":["e2"],"clock":{"seq":3,"now":130},"signer":"urn:pcp:principal:a","payload":{"of":"e2","assignee":"urn:pcp:principal:b","gate":false},"sig":"SIG_PENDING"}
```

expected: commit. state=`running`, floor=`B`, pending=null, seq=3. SIG_PENDING.

### V-007 cancel from running (abort)

setup: V-001. now: 120. kind: positive.

```json
{"legatus":0,"id":"e2","thread":"t1","type":"cancel","parents":["e1"],"clock":{"seq":2,"now":120},"signer":"urn:pcp:principal:a","payload":{"code":"CANCEL_STOP"},"sig":"SIG_PENDING"}
```

expected: commit. state=`cancelled`, floor=null, pending=null, seq=2. SIG_PENDING.

### V-008 gated handoff then approve

setup: V-001. now: 120. kind: positive. Two steps.

Step a:

```json
{"legatus":0,"id":"e2","thread":"t1","type":"handoff","parents":["e1"],"clock":{"seq":2,"now":120},"signer":"urn:pcp:principal:b","payload":{"to":"urn:pcp:principal:c","gate":true,"approver":"urn:pcp:principal:a"},"sig":"SIG_PENDING"}
```

expected a: `awaiting_approve`, floor=`B`, pending=`e2`, seq=2.

Step b now: 121, signer A, type approve, `of` e2, seq 3, parents `[e2]`.

expected b: `running`, floor=`C`, pending=null, seq=3. SIG_PENDING.

---

## 2. Timeout, abort, checkout

### V-010 durable timeout pause

setup: V-002 (`deadline_now`=250, `awaiting_approve`). candidate: none. now: 251. kind: timeout.

expected: append timeout journal record at position 2 with `after_seq=1`, `now=251`, `deadline_now=250`, and `pending=e1`. State=`paused`, floor=`A`, pending=`e1`, envelope seq=1.

### V-011 resume after timeout (thaw)

setup: V-010. now: 260. kind: positive.

```json
{"legatus":0,"id":"e2","thread":"t1","type":"resume","parents":["e1"],"clock":{"seq":2,"now":260},"signer":"urn:pcp:principal:a","payload":{"gate":false},"sig":"SIG_PENDING"}
```

expected: commit at journal position 3. state=`awaiting_approve`, floor=`A`, pending=`e1` (unchanged), seq=2. `deadline_now` clears because resume omitted it.

**Normative (V-011):** resume from `paused` with frozen pending **MUST** land `awaiting_approve` with the **same pending id**. It **MUST NOT** go `running` with pending cleared. Discard is **fail or cancel only**. Timeout does not discard pending. Approve is illegal from `paused`, so resume is the thaw.

Collision: v0 one-pending. A gated resume while a frozen gate exists is `LEGATUS_E_GATE_PENDING`. Do not drop the frozen gate to make room, including on ungated resume. Fail or cancel the frozen gate first. After pending is gone, ungated resume from paused lands `running`; gated resume becomes the new pending.

### V-011b gated resume while frozen pending

setup: V-010. now: 260. kind: negative.

candidate: V-011 resume envelope except payload `gate`=true and `approver`=`A`.

expected: `LEGATUS_E_GATE_PENDING`. No commit. state stays `paused`, floor=`A`, pending=`e1`, seq=1.

### V-012 abort from paused

setup: V-010. now: 260. kind: positive (abort path).

```json
{"legatus":0,"id":"e2","thread":"t1","type":"cancel","parents":["e1"],"clock":{"seq":2,"now":260},"signer":"urn:pcp:principal:a","payload":{"code":"CANCEL_STOP"},"sig":"SIG_PENDING"}
```

expected: `cancelled`, floor=null, pending=null, seq=2.

### V-013 abort from failed

setup: V-005. now: 140. cancel by A, seq 3, parents `[e2]`, code `CANCEL_OTHER`.

expected: `cancelled`, floor=null, pending=null, seq=3.

### V-014 timeout applied before judging candidate

setup: V-002. independently authoritative runtime now: 251. candidate: handoff by A, seq 2, `to` C.

expected: timeout record commits first (`paused`), then the envelope gets `LEGATUS_E_ILLEGAL_TRANSITION`. No envelope commits. Envelope seq stays 1 and journal position becomes 2.

### V-014b authenticated candidate clock crosses deadline

setup: V-001 extended with `deadline_now=250`. candidate: otherwise legal handoff by B with `clock.now=251` and valid proof. expected: proof and floor eligibility succeed, timeout record commits, then the handoff gets `LEGATUS_E_ILLEGAL_TRANSITION` from `paused`. A bad proof or signer without floor using the same `clock.now` cannot append the timeout record.

### V-015 clean-checkout equals fold

kind: checkout. log: committed envelopes of V-001 then V-004 (e1 delegate, e2 handoff to C). now: 120 (not past any deadline).

expected: `running`, floor=`C`, pending=null, seq=2. Identical to V-004. Operator chat and agent-messaging UIs not in inputs.

### V-016 clean-checkout then timeout

kind: recovery. journal: V-002’s e1 only. authoritative now: 251.

expected: the authoritative writer appends V-010's timeout record, then returns `paused`, floor=`A`, pending=`e1`, seq=1. A read-only checker reports `awaiting_approve` until it observes that record.

### V-017 checkout cancelled thread

kind: checkout. log: V-007. now: 999.

expected: `cancelled`, floor=null, pending=null, seq=2. Further candidates: `ALREADY_TERMINAL`.

---

## 3. Negative first-match

### V-020 SCHEMA extra top-level key

setup: empty. candidate: V-001 plus `"foo":1`. expected: `LEGATUS_E_SCHEMA`. SIG_PENDING.

### V-021 SCHEMA missing assignee

setup: empty. delegate payload only `task_ref`. expected: `LEGATUS_E_SCHEMA`.

### V-022 UNKNOWN_TYPE negotiate

setup: empty. type=`negotiate`, otherwise V-001 shape. expected: `LEGATUS_E_UNKNOWN_TYPE`.

### V-023 UNKNOWN_TYPE attest

type=`attest`. expected: `LEGATUS_E_UNKNOWN_TYPE`.

### V-024 duplicate id, same canonical content

setup: V-001. resubmit e1 with identical canonical content. expected: the original typed acknowledgement with `outcome=duplicate`. No error, no append, seq stays 1.

### V-025 DUP_ID same id different bytes (conflict)

setup: V-001. candidate id e1 but assignee C. expected: `LEGATUS_E_DUP_ID`. Do not replace the log.

### V-026 THREAD_MISMATCH

setup: V-001. candidate handoff thread=`t2`, parents `[e1]`, seq 2, signer B. expected: `LEGATUS_E_THREAD_MISMATCH`.

### V-027 MISSING_PARENT

setup: V-001. handoff parents=`[]`, seq 2, signer B. expected: `LEGATUS_E_MISSING_PARENT`.

### V-028 CAUSALITY unknown parent

setup: V-001. parents `[e99]`, seq 2. expected: `LEGATUS_E_CAUSALITY`.

### V-029 CLOCK_SKEW seq skip

setup: V-001. handoff seq=3 (should be 2). expected: `LEGATUS_E_CLOCK_SKEW`.

### V-030 CLOCK_SKEW now backwards

setup: V-001 (thread.now=100). handoff seq=2, clock.now=99. expected: `LEGATUS_E_CLOCK_SKEW`.

### V-031 conflict two seq=2 different ids

setup: V-001. First, V-004 commits e2 seq 2. Second candidate e3 seq 2 handoff. expected: `LEGATUS_E_CLOCK_SKEW` (seq not 3).

### V-032 GATE_PENDING

setup: V-002. candidate handoff seq 2 signer A. expected: `LEGATUS_E_GATE_PENDING`. (now=110, before deadline.)

### V-033 approve from paused

setup: V-010. approve of e1, seq 2, signer A. expected: `LEGATUS_E_ILLEGAL_TRANSITION`.

### V-034 nested delegate on running thread

setup: V-001. type delegate seq 2 signer B (the current floor). expected: `LEGATUS_E_ILLEGAL_TRANSITION`. New work is a new thread.

### V-035 retry from running

setup: V-001. retry of e1. expected: `LEGATUS_E_ILLEGAL_TRANSITION`.

### V-036 resume from running

setup: V-001. resume. expected: `LEGATUS_E_ILLEGAL_TRANSITION`.

### V-037 ALREADY_TERMINAL

setup: V-007. any structurally valid type with correct clock and causality. expected: `LEGATUS_E_ALREADY_TERMINAL` before floor or move-specific transition checks.

### V-038 handoff from void

setup: empty. type handoff seq 1. expected: `LEGATUS_E_ILLEGAL_TRANSITION`.

---

## 4. Privilege / invalid signer (not SIG crypto)

### V-040 NO_FLOOR stranger handoff

setup: V-001. handoff signer=`X` to C. expected: `LEGATUS_E_NO_FLOOR`.

### V-041 STALE_FLOOR after handoff

setup: V-004 (floor=`C`). candidate fail signer=`B` (old floor). expected: `LEGATUS_E_STALE_FLOOR`.

### V-042 NOT_APPROVER

setup: V-002 (approver A). approve signer=`B`. expected: `LEGATUS_E_NOT_APPROVER`.

### V-043 retry must be principal

setup: V-005. retry signer=`B` (floor, not principal). expected: `LEGATUS_E_NO_FLOOR`.

### V-044 cancel by stranger

setup: V-001. cancel signer=`X`. expected: `LEGATUS_E_NO_FLOOR`.

### V-045 SIG_PENDING slot

kind: harness rule, not a commit. Every vector above uses `sig="SIG_PENDING"`. The fixture verifier accepts this exact value without cryptography. Missing sig field is `LEGATUS_E_SIG`: candidate V-001 with sig omitted → `LEGATUS_E_SIG`.

### V-046 PCP request binding

candidate: V-001 with `sig="pcp1.opaque-compact-fixture"`. expected verifier request keys are exactly profile=`pcp-legatus-v1`, signer_id=A, purpose=`legatus.delegate`, envelope equal to the full candidate, and proof equal to the whole candidate `sig`. The synthetic PCP side removes only `sig`, obtains protected key id `key-fixture-1` and grant id `urn:pcp:grant:fixture-1` from its proof fixture, and reconstructs exactly `{context, signer_id, key_id, grant_id, purpose, envelope}` for JCS verification. It adds no digest, idempotency, spend, or transport field to that protected object. This vector checks integration shape without performing cryptography.

PCP derives `legatus:sha256:38f95fbdb73b248fa82ccd3f9a91a7c5d6cf0d93edf1016b1b6ba060a3fa5c38` from the UTF-8 JCS bytes for `{"envelope_id":"env-1","thread":"thread-1"}`. The pairs `(thread="a:b", envelope_id="c")` and `(thread="a", envelope_id="b:c")` MUST produce the distinct suffixes specified in [the signer profile](02-signer-verification.md). PCP stores both fields separately and validates them again at finalization.

### V-046a reservation commit finalization

candidate: V-001. PCP returns `allow` with authorization id `authorization-1`. expected: the durable envelope journal record carries `authorization_id=authorization-1`; Legatus then sends exactly `{profile:"pcp-legatus-v1",authorization_id:"authorization-1",outcome:"commit",envelope_id:"e1",thread:"t1",journal_position:1}`. A valid PCP finalization result produces an acknowledgement with `authorization_state=committed`.

### V-046b deterministic reservation release

setup: V-001 committed. candidate: a validly proven seq=2 handoff signed by a principal without the floor. PCP returns `allow` with `authorization-2`. expected: `LEGATUS_E_NO_FLOOR`, no candidate envelope append, and an exact finalization request with outcome=`release` and journal_position=null.

### V-046c post-append finalizer outage

candidate: V-001. Envelope append succeeds and the PCP finalizer is unavailable. expected: committed envelope record, acknowledgement `authorization_state=reconciliation_required`, and a pending idempotent commit handoff. After restart, journal replay reconstructs the same authorization identifier; the reconciliation call resends `commit`. Successful PCP finalization updates the reconstructed acknowledgement state to `committed`.

### V-046d ambiguous append reconciliation

two fenced views race the same V-001 candidate after PCP returns the same idempotent authorization. One append wins and one compare-and-set fails. expected loser response: retriable `LEGATUS_E_WRITER_UNAVAILABLE`, with no immediate PCP release. A fresh fenced journal read finds the exact envelope, authorization identifier, and position, then sends `commit`. If the candidate is absent under that fence, it sends `release`. An authorization mismatch or collision remains unresolved.

### V-047 invalid proof mapping

candidate: V-001. PCP disposition: `bad_signature`. expected: `LEGATUS_E_SIG`; no journal append.

The same result applies to `proof_signer_mismatch`, `proof_key_mismatch`, `proof_purpose_mismatch`, and `proof_envelope_mismatch`.

### V-048 authority denial mapping

candidate: V-001. PCP disposition: `revoked`. expected: out-of-band `pcp_result` with code=`revoked`, retriable=false, envelope id and thread; no Legatus error and no journal append.

### V-049 malformed verifier result

candidate: V-001. PCP returns an object outside [pcp-verifier-result.schema.json](../schemas/pcp-verifier-result.schema.json). expected: out-of-band `pcp_result` with code=`unavailable`, retriable=true; no journal append.

---

## 5. UTF-8 boundaries

### V-050 UTF-8 task_ref

setup: empty. V-001 with `task_ref`=`工作-1 café 🐉`. expected: same as V-001 (commit, `running`, floor=`B`). Opaque string, UTF-8 legal.

### V-051 empty task_ref

`task_ref`=`""`. expected: `LEGATUS_E_SCHEMA` (non-empty required).

### V-052 empty id

`id`=`""`. expected: `LEGATUS_E_SCHEMA`.

### V-053 NUL in task_ref

`task_ref` contains U+0000. expected: `LEGATUS_E_SCHEMA`. (Boundary: opaque does not mean any bytes; v0 strings are UTF-8 without NUL.)

### V-054 unsafe integer

V-001 with `clock.now=9007199254740992`. expected: `LEGATUS_E_SCHEMA`.

### V-055 duplicate parent

setup: V-001. candidate parents=`["e1","e1"]`. expected: `LEGATUS_E_SCHEMA`.

### V-056 parent-array bound

candidate with 33 parent identifiers. expected: `LEGATUS_E_SCHEMA`.

### V-057 duplicate JSON member

candidate text contains two `id` members. expected: parser rejection as `LEGATUS_E_SCHEMA`; no verifier request and no append.

### V-058 wrong principal namespace

V-001 with signer=`urn:pcp:agent:a`. expected: `LEGATUS_E_SIG`. V-001 with assignee=`urn:pcp:agent:b` and a valid signer returns `LEGATUS_E_SCHEMA`.

### V-059 malformed timestamp

V-001 with `clock.ts="tomorrow"`. expected: `LEGATUS_E_SCHEMA`.

---

## 6. Chat is not an envelope

### V-060 operator chat — NOT_A_SUBMIT

candidate: the string `delegate this to B` (not JSON). expected: `NOT_A_SUBMIT`. Runtime does not parse, does not SCHEMA, does not commit. Operator chat is not a submit surface.

### V-061 inter-agent message without `legatus:0`

candidate: an inter-agent message object without `legatus:0`. expected: `NOT_A_SUBMIT`. Same as V-060.

---

## 7. Transcript fixture integrity

### V-070 unsigned fixture transcript

setup: any committed thread. expected export: it validates against [transcript.schema.json](../schemas/transcript.schema.json), includes `integrity={"mode":"unsigned_fixture"}`, contains every timeout journal record in `clock_events`, carries each move's journaled authorization identifier, and has no transcript-level `sig` field.

---

## 8. Coverage map

| protocol behavior | vectors |
| --- | --- |
| seven moves | V-001…V-008, V-011, V-011b (`GATE_PENDING`) |
| durable timeout / recovery | V-010, V-011, V-014, V-014b, V-016 |
| abort | V-007, V-012, V-013 |
| clean-checkout | V-015, V-016, V-017 |
| replay / duplicate | V-024, V-025 |
| conflict | V-025, V-031 |
| signer / privilege / PCP mapping | V-040…V-049, including V-046a…V-046d |
| UTF-8 and wire bounds | V-050…V-059 |
| first-match errors | V-020…V-038, V-011b |
| operator chat / inter-agent not submit | V-060, V-061 |
| transcript integrity marker | V-070 |

Run `python -m conformance.run` for the deterministic executable subset and `python -m unittest discover -s tests -v` for its regression suite. The runner is a reference-model check; cryptographic PCP integration, durable storage, and distributed consensus require separate production tests.
