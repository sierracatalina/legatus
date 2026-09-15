# Scope and protocol boundaries

Legatus v0.1 defines one profile: a transport-independent coordination rail for delegated work.

## The seven moves

1. **delegate** — assign work to a principal under an existing PCP grant.
2. **handoff** — transfer control of an in-flight thread.
3. **approve** — satisfy an authority or human gate.
4. **fail** — record a failed thread or move.
5. **retry** — begin a new attempt after failure on the same thread.
6. **cancel** — stop a thread or move.
7. **resume** — continue after a pause, timeout wait, or approval.

These are the only in-band move types in v0.1. Adding, renaming, or removing a move requires a new protocol version.

## Envelope

A Legatus envelope is a signed, typed, clocked JSON object that carries one move. The [core specification](01-envelope-transitions-clock-errors.md) defines its normative shape.

An envelope contains:

- one of the seven move types;
- an envelope identifier and thread identifier;
- causal parent identifiers;
- a shared logical-clock value;
- the identifier of a PCP principal;
- move-specific payload fields; and
- a signature verified through PCP.

An envelope must not contain a grant body, context bundle, receipt body, transport credential, or operator-chat message.

## In-band responsibilities

Legatus defines:

- the envelope;
- the seven move types;
- the transition table and thread state;
- causal links between envelopes;
- the shared logical clock;
- the durable envelope/timeout journal;
- commit, timeout, recovery, writer fencing, and abort behavior; and
- deterministic errors for invalid input and illegal transitions.

## External dependencies

- **Transport:** HTTP, MCP, A2A, Nostr, file exchange, or another carrier may transport unmodified candidate envelopes and acknowledgements.
- **PCP:** identifies principals, grants authority, verifies the `pcp-legatus-v1` detached proof, and owns authorization reservation accounting, expiry, and revocation.
- **Context Layer:** controls context bundles, disclosure policy, and provenance.
- **Receipt system:** records evidence of out-of-band action completion. Legatus may cite an opaque receipt identifier.
- **Product runtime:** plans, routes, executes, and presents work to a user.

Discovery metadata and operator chat may help a user prepare an envelope. They do not submit or authorize one. Only an authoritative writer or consensus group may acknowledge a journal append.

## Non-goals

- Issuing identities or authority grants.
- Reading or disclosing private context.
- Planning or executing product work.
- Issuing or verifying receipt bodies.
- Negotiating grants inside the coordination state machine.
- Treating UI text, chat text, or transport metadata as an envelope.

## Versioning

The version field `legatus: 0` identifies this protocol generation. Changes to move names, transition rules, error precedence, timeout behavior, or transcript roles require a new version. Editorial corrections and new conforming examples may remain within v0.1.
