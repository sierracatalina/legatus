# Transport and governance

This page is how v0 stays one contract across wires and implementations. It does not add moves, clocks, or error codes.

---

## 1. Versioning

The envelope field `legatus` is the integer **0**. A transcript uses the same integer plus `kind: transcript`.

Changes that add, drop, or rename a move, change first-match errors, change timeout preservation of `pending`, or change the five transcript roles require a new protocol version and integer.

Editorial corrections, examples, and fixture identifiers may retain the same integer. New moves and state-machine changes require a new integer.

Unknown `legatus` values: a v0 runtime rejects with `SCHEMA` (or a future version-mismatch code in v1). v0 does not mint that code. Independent implementations must not silently accept `legatus: 1` as v0.

---

## 2. Transport profiles

The rail is transport-agnostic. A transport carries one candidate JSON object in and returns one typed acknowledgement, typed Legatus error, or out-of-band PCP authority result. It does not interpret moves.

v0 profiles (names only; bytes on the wire are the envelope):

| Profile | Carry | Must not |
| --- | --- | --- |
| **T-HTTP** | POST one JSON body, respond with one typed result | batch several types in one body |
| **T-MCP** | one tool call = one candidate | treat the MCP session as floor |
| **T-A2A** | one A2A message = one candidate | revive July floor-control as a second protocol |
| **T-NOSTR** | one event content = one candidate | use kind/tag as a move type |
| **T-FILE** | one `.json` file = one candidate or one causal transcript | auto-commit on file drop |

Operator chat and agent-messaging UIs are outside the transport profiles. A human may copy JSON from chat into T-HTTP or T-FILE. The chat message itself is `NOT_A_SUBMIT` (V-060).

A profile is conformant when it delivers unaltered candidate bytes, returns a result matching the published schemas, adds no envelope keys, and does not wrap natural language into an envelope. It rejects duplicate JSON members and payloads exceeding 64 KiB before parsing.

New transports are new profile rows, not new `legatus` integers, unless they require new envelope fields.

---

## 3. Independent interop policy

An independent implementation must:

1. Speak `legatus: 0` envelopes and reject every move type outside the seven defined values, including `negotiate` and `attest`.
2. Validate [the envelope](../schemas/envelope.schema.json), [acknowledgement](../schemas/ack.schema.json), [error](../schemas/error.schema.json), [journal record](../schemas/journal-record.schema.json), and [PCP result](../schemas/pcp-result.schema.json) contracts.
3. Pass the conformance vectors, including durable timeout replay, V-011 thaw, V-011b `GATE_PENDING`, fencing, and PCP mapping, plus applicable operations drills H-001 through H-033.
4. Export causal transcripts whose five roles match and whose integrity mode is explicit. Missing receipt remains legal.
5. Integrate [the PCP verifier and reservation-finalization profile](02-signer-verification.md) without issuing grants or maintaining PCP budget state inside Legatus.
6. Serialize journal appends through one authoritative writer, a linearizable fenced lease, or consensus.

Two runtimes interoperate when they pass the same published fixtures, replay each other's authoritative journal records in position order, refuse fork merging, and produce the same state from the same journal. A later authoritative clock value may append one new timeout record; that record then becomes part of the shared state.

## 4. Machine contracts

All schemas use JSON Schema draft 2020-12, forbid unknown object fields, bound identifiers and arrays, and restrict integers to the interoperable JSON safe range. JSON parsers must reject duplicate object members before schema validation.

| Object | Schema |
| --- | --- |
| candidate envelope | [envelope.schema.json](../schemas/envelope.schema.json) |
| commit/duplicate acknowledgement | [ack.schema.json](../schemas/ack.schema.json) |
| Legatus/pre-protocol error | [error.schema.json](../schemas/error.schema.json) |
| durable envelope/timeout record | [journal-record.schema.json](../schemas/journal-record.schema.json) |
| PCP verifier request/result | [request](../schemas/pcp-verifier-request.schema.json) / [result](../schemas/pcp-verifier-result.schema.json) |
| PCP finalization request/result | [request](../schemas/pcp-finalize-request.schema.json) / [result](../schemas/pcp-finalize-result.schema.json) |
| out-of-band PCP denial | [pcp-result.schema.json](../schemas/pcp-result.schema.json) |
| unsigned fixture transcript | [transcript.schema.json](../schemas/transcript.schema.json) |

## 5. Governance

Protocol governance covers version assignment, normative text, conformance fixtures, and transport profiles. Operational keys, identity grants, product branding, and deployment policy remain outside this specification.

---

## 6. Compatibility matrix (v0)

| Peer sends | v0 does |
| --- | --- |
| `legatus` 0, seven types, valid envelope shape | typed ack, first-match error, or PCP authority result |
| unknown type / extra keys / empty strings | `UNKNOWN_TYPE` or `SCHEMA` |
| operator chat, inter-agent message, natural language | `NOT_A_SUBMIT` |
| causal transcript as a candidate envelope | `SCHEMA` or `UNKNOWN_TYPE` (`kind` is not a move). Transcripts are exports, not submits. |
| credential object (`iss`/`aud`/`sub`/`scope`) | `SCHEMA`. Not an envelope. |

---

## 7. Non-goals

- No production-runtime claim or adapter implementation.
- No PCP grants, keys, or issuer.
- No receipt crypto. No new SLO.
- Operator chat is not a submit surface. A chat message is `NOT_A_SUBMIT`.
- The dependency-free reference runner establishes deterministic state-machine behavior. Production conformance also requires durable-store, PCP cryptography, consensus/fencing, adapter, and fault-injection evidence.
