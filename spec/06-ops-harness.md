# Operations harness

This document defines retry, partition, recovery, and incident drills. The included reference runner executes the deterministic in-process subset. It does not issue PCP grants or operate a production runtime.

---

## 1. Harness scope

The drill pack provides inputs, expected core-protocol and runtime-path outcomes, and incident controls.

Four drills:

1. Retry (transport vs typed retry move)
2. Partition / reconnect
3. Recovery (crash and clean-checkout)
4. Incident (stop, export, do not drop the log)

The measurement appendix describes timing fields for a production runtime. This specification sets no SLO.

---

## 2. Retry

Two different things named retry. Do not mix them.

**Transport retry:** the same candidate is submitted again after a disconnect or lost acknowledgement. Identical canonical candidate content returns the original typed acknowledgement with `outcome=duplicate`. Different content under the same id returns `LEGATUS_E_DUP_ID`. Neither path appends or advances envelope sequence.

**Typed retry:** a new envelope, type `retry`, after fail. New id, seq+1. Not a resend.

**PCP outage during proof verification:** return an out-of-band PCP `unavailable` result with `retriable=true`. Do not commit, invent a fail envelope, or write a grant. The sender may transport-retry the same candidate after verification recovers. The dependency-free fixture uses `SIG_PENDING`.

### Fixtures

**H-001** setup V-001 committed. Resubmit e1 with identical canonical content. expected: original ack with `outcome=duplicate`, original journal position, seq=1, and one journal record.

**H-002** setup V-001. Resubmit e1 with assignee C. expected: `LEGATUS_E_DUP_ID`, journal still records assignee B.

**H-003** setup V-005 (failed). Typed retry e3 (V-006). expected: commit, `running`, floor=`B`, seq=3.

**H-004** setup V-001. Typed retry while running. expected: `LEGATUS_E_ILLEGAL_TRANSITION` (V-035).

**H-005** PCP unavailable. Candidate otherwise V-001. expected: out-of-band PCP `unavailable`, retriable=true, no commit, no fail envelope, and no grant write. Missing, malformed, or bad proof maps to `LEGATUS_E_SIG`.

**H-006** PCP allows a candidate that fails a deterministic floor or transition check. expected: typed Legatus rejection, no envelope append, and idempotent PCP `release` with null journal position. A transient release failure stays queued for retry; PCP reservation expiry bounds cleanup after process loss.

---

## 3. Partition and reconnect

A partition separates a current writer from a stale writer or read replica.

Exactly one writer lease or consensus leader may acknowledge an envelope or timeout record. An isolated node without current authority returns retriable `LEGATUS_E_WRITER_UNAVAILABLE` and appends nothing. Read replicas derive state from their observed journal prefix; a replica reports the pre-timeout state until it receives the durable timeout record.

A fork contains two different committed envelopes at the same sequence or two journal records at the same position. It proves that the storage, lease, or consensus contract failed. Reconnect detects and quarantines the fork; it never merges it.

**Reconnect:** followers fetch the authoritative journal by position and replay missing records. A node must reacquire a strictly higher fenced epoch before it may acknowledge new appends. Any due timeout becomes a journal record through the authoritative writer.

### Fixtures

**H-010** two nodes observe V-002's envelope record. The authoritative writer advances now to 251 and appends the V-010 timeout record. expected: replicas remain `awaiting_approve` until they receive position 2; after replay, all report `paused`, pending=`e1`.

**H-011** writer A commits V-004. Partitioned stale writer B tries a different seq=2 envelope. expected: B returns `LEGATUS_E_WRITER_UNAVAILABLE`, acknowledges no commit, and appends nothing. After replaying A's record, a fresh submission of B's candidate returns `LEGATUS_E_CLOCK_SKEW`.

**H-012** reconnect after H-010. expected: both replay the timeout record and report `paused`, pending=`e1`, seq=1, journal position=2.

**H-013** two durable histories already forked. expected: harness marks `INCIDENT_FORK` and reports a storage or fencing violation. It performs no automatic merge. Export each history separately. A cancel may be appended only after one history becomes authoritative.

**H-014** two in-process views hold the same writer epoch and journal position. View A appends first. View B tries to append from its stale position. expected: the journal compare-and-set rejects B with `LEGATUS_E_WRITER_UNAVAILABLE`; B must rebuild before retrying.

**H-015** failover requests an epoch less than or equal to the current epoch. expected: lease acquisition fails. A successful failover uses a strictly higher epoch, after which the prior writer cannot append envelopes or timeout records.

**H-016** writer loses journal compare-and-set after PCP `allow`. expected: retain the authorization reservation and return retriable `LEGATUS_E_WRITER_UNAVAILABLE`. Under a current writer fence, refresh the journal. Commit the reservation when the exact candidate and authorization identifier are present. Release it after absence is established. Keep an authorization mismatch or collision unresolved.

---

## 4. Recovery

Crash is loss of RAM. The durable journal is the recovery source. Recovery folds envelope and timeout records in position order, acquires a current writer lease, appends any newly due timeout, then accepts candidates. In-flight candidates without a durable acknowledgement are absent. Senders transport-retry as in H-001.

Commit durability: ack only after append. A crash between append and ack looks like H-001 to the sender.

Crash during apply after append: recovery replays apply. If apply cannot, the thread is unreadable and requires incident handling.

### Fixtures

**H-020** commit V-001, crash, checkout now=100. expected: `running`, floor=`B`, seq=1. Identical to V-015 style fold.

**H-021** candidate parsed and validated, then the process crashes before append. expected: void or prior state and no acknowledgement. Sender retries, receiving H-001 if another writer committed it or a fresh commit if the journal lacks it.

**H-022** journal has V-002's envelope only; authoritative now=251 after restart. expected: recovery appends a timeout record at position 2, then reports `paused`, pending=`e1`. A second recovery replays that record without appending another.

**H-023** corrupt skip of seq 2 with seq 3 present. expected: unreadable thread. No skip. Incident.

**H-024** crash after durable envelope append and before PCP finalization response. expected: replay the envelope and its authorization identifier, report `authorization_state=reconciliation_required`, and resend the same idempotent commit finalization. PCP validates the stored `thread` and `envelope_id` fields directly and returns its prior final outcome on duplicate finalization.

---

## 5. Incident controls

An incident is a fork, an unreadable thread, a stuck gate the human wants stopped, or any case the operator must act without a new move type.

Allowed operator acts (all in-band or already specified):

- cancel by floor or principal (stop) through the abort path.
- fail by floor or principal.
- causal-transcript export of the chosen log. Action and receipt references are optional.
- Do not drop the log. Do not “soft abort” in chat. Do not write a grant. Do not mint a receipt.

Who pages whom is out of band (ops roster). The rail only needs: stop is cancel, evidence is the transcript, recovery is checkout.

### Fixtures

**H-030** running thread, operator cancel by principal A (V-007). expected: `cancelled`, floor=null, log kept.

**H-031** after H-030, export a causal transcript. expected: stop cites the cancel envelope; links include request + moves; receipt omitted legal.

**H-032** chat message “kill t1”. expected: `NOT_A_SUBMIT` (V-060). State unchanged.

**H-033** `INCIDENT_FORK` from H-013. expected: two causal-transcript exports, no merged log, no auto-cancel of both.

---

## 6. Performance appendix (no SLO)

When a runtime exists, the harness may time:

- commit ack of V-001
- reject ack of V-022 (`UNKNOWN_TYPE`)
- timeout journal append and apply of V-010
- checkout of a log of N envelopes

Record n, p50, p99, hardware, operating system, runtime versions, and the exact runtime revision. Publish thresholds separately from observed measurements.

---

## 7. Coverage

| behavior | fixtures |
| --- | --- |
| transport retry / PCP idempotency | H-001, H-002, H-005, H-006 |
| typed retry | H-003, H-004 |
| partition / reconnect / fencing | H-010…H-016 |
| recovery / checkout | H-020…H-024 |
| incident / stop / export | H-030, H-031, H-032, H-033 |
| benchmark | §6 method only |

---

## 8. Non-goals

- No production-runtime claim.
- No PCP grants, keys, or identity recovery.
- No new move types. No negotiate.
- No receipt cryptography.
- No production durability, consensus, cryptography, performance, or SLO claim from the in-process reference runner.
