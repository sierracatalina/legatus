# PCP signer and authority verification

Legatus consumes one verifier disposition from PCP before committing an envelope. The strict Legatus envelope keeps `signer` and `sig`; key and grant metadata stay inside the opaque detached proof carried by `sig`.

## Proof contract

`signer` MUST be a `urn:pcp:principal:…` identifier. `sig` MUST carry the whole opaque compact PCP detached proof. The proof's protected content includes `key_id`, `grant_id`, and the exact purpose `legatus.<move>`.

PCP verifies an Ed25519 signature over the RFC 8785 JCS encoding of the following object. These six fields are exact; profiles must not add a digest, idempotency key, spend record, or transport field to the signed object.

```json
{
  "context": "pcp-legatus-v1",
  "signer_id": "urn:pcp:principal:…",
  "key_id": "<protected-key-id>",
  "grant_id": "urn:pcp:grant:…",
  "purpose": "legatus.<move>",
  "envelope": {
    "legatus": 0,
    "id": "env-1",
    "thread": "thread-1",
    "type": "delegate",
    "parents": [],
    "clock": {"seq": 1, "now": 100},
    "signer": "urn:pcp:principal:alice",
    "payload": {"assignee": "urn:pcp:principal:worker", "task_ref": "work-1"}
  }
}
```

The context string prevents cross-protocol signature reuse. The unsigned envelope binds the thread, move, parents, clock, payload, and signer. PCP MUST require the proof signer to equal the envelope signer, resolve the protected key id under that signer, and require the protected purpose to equal `legatus.` plus the envelope type.

## Verifier request

Legatus sends PCP the full candidate envelope, its opaque proof, the expected signer, and the expected purpose:

```json
{
  "profile": "pcp-legatus-v1",
  "signer_id": "urn:pcp:principal:alice",
  "purpose": "legatus.delegate",
  "envelope": {
    "legatus": 0,
    "id": "env-1",
    "thread": "thread-1",
    "type": "delegate",
    "parents": [],
    "clock": {"seq": 1, "now": 100},
    "signer": "urn:pcp:principal:alice",
    "payload": {"assignee": "urn:pcp:principal:worker", "task_ref": "work-1"},
    "sig": "<opaque-compact-proof>"
  },
  "proof": "<opaque-compact-proof>"
}
```

The complete machine contract is [pcp-verifier-request.schema.json](../schemas/pcp-verifier-request.schema.json). PCP removes only `sig` when reconstructing the protected unsigned envelope. It MUST reject any mismatch between the duplicated proof value, signer, expected purpose, protected content, or candidate envelope.

## Dispositions and mapping

The verifier returns [pcp-verifier-result.schema.json](../schemas/pcp-verifier-result.schema.json).

| PCP disposition | Legatus surface | Commit |
| --- | --- | --- |
| `allow` with an authorization identifier | continue state-machine validation | eligible |
| malformed/unsigned proof, unknown key, bad signature, or proof signer/key/purpose/envelope mismatch | `LEGATUS_E_SIG` | no |
| missing, expired, revoked, scope-mismatched, or exhausted grant | out-of-band [PCP result](../schemas/pcp-result.schema.json) | no |
| verifier unavailable or malformed response | retriable out-of-band PCP `unavailable` result | no |

Protected purpose mismatch returns PCP code `proof_purpose_mismatch` and maps to `LEGATUS_E_SIG`. A valid proof whose referenced grant lacks the requested purpose returns `scope_mismatch` as an out-of-band PCP result. Authority denials retain their PCP code so callers can distinguish an invalid proof from an expired or revoked grant. They never become a Legatus state transition or a committed `fail` envelope.

`retriable` describes resubmission of the identical candidate. It is true only for `unavailable`; every proof or authority denial is false. A caller resolving a grant denial must obtain a new valid proof before submitting again.

## Authorization reservation and finalization

An `allow` result creates or returns an idempotent live PCP authorization reservation. PCP owns its budget ledger and reservation lifetime. Legatus records the returned `authorization_id` with a committed envelope and sends one of two idempotent finalization outcomes:

- `commit` after the envelope record is durable, with its positive journal position;
- `release` after a deterministic floor, gate, transition, or timeout-induced transition rejection, with a null journal position.

Legatus sends the exact [finalization request](../schemas/pcp-finalize-request.schema.json):

```json
{
  "profile": "pcp-legatus-v1",
  "authorization_id": "authorization-1",
  "outcome": "commit",
  "envelope_id": "env-1",
  "thread": "thread-1",
  "journal_position": 7
}
```

PCP returns the exact [finalization result](../schemas/pcp-finalize-result.schema.json):

```json
{
  "profile": "pcp-legatus-v1",
  "status": "finalized",
  "authorization_id": "authorization-1",
  "outcome": "commit"
}
```

PCP derives the reservation idempotency key as `legatus:sha256:<digest>`, where `<digest>` is the 64-character lowercase hexadecimal SHA-256 of the UTF-8 RFC 8785 JCS bytes for exactly `{"envelope_id":<envelope-id>,"thread":<thread-id>}`. The member names are exact. JCS orders them as `envelope_id`, then `thread`. The key is derived at verification and finalization; it is not an added field in either strict request schema.

For `envelope_id="env-1"` and `thread="thread-1"`, the canonical bytes represent `{"envelope_id":"env-1","thread":"thread-1"}` and the key is:

```text
legatus:sha256:38f95fbdb73b248fa82ccd3f9a91a7c5d6cf0d93edf1016b1b6ba060a3fa5c38
```

The delimiter-bearing pairs `(thread="a:b", envelope_id="c")` and `(thread="a", envelope_id="b:c")` produce distinct suffixes `8f1c8bf256a489d8b9a05375c45e7ac63838286790680c418e82ce8a94c14c5c` and `4aebc886d9c6ada7592289f28e3b5c1ed7ae6e1878b5e0c9da82e4ca693422d5`.

PCP also binds the authorization record to `request_digest`, defined as SHA-256 over RFC 8785 JCS of the exact six-field signed object in the proof contract. `envelope_digest` remains a separate receipt or evidence value. The idempotency key locates the thread/envelope reservation; `request_digest` detects any key, grant, purpose, signer, or envelope conflict at that identity. PCP stores `thread` and `envelope_id` as separate fields and compares them directly during finalization.

A finalizer timeout after durable append leaves the envelope committed and the acknowledgement reports `authorization_state: reconciliation_required`. Recovery reads the journaled authorization identifier and retries the same `commit` request. Repeated finalization calls are safe by PCP idempotency.

A lost compare-and-set has an ambiguous commit outcome: another writer may have committed the same candidate. Legatus retains the reservation, refreshes a fenced journal view, and compares canonical envelope identity plus authorization identifier. An exact committed record yields `commit`. Proven absence under the writer fence yields `release`. An authorization mismatch or collision stays unresolved for PCP adapter reconciliation.

An unavailable release handoff remains retryable during the process lifetime. PCP reservation expiry is the final cleanup boundary after a crash that left no journal record and no durable release handoff. Legatus does not maintain or debit the PCP budget ledger.

## Fixture mode

`SIG_PENDING` is permitted only in the dependency-free conformance fixture verifier. It performs no cryptography and MUST NOT be enabled by a production transport.

Key custody, grant contents, revocation, reservation accounting, expiry, and carrier binding remain PCP responsibilities. Legatus stores no grant or key material.
