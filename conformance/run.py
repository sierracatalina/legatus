"""Run deterministic, dependency-free Legatus conformance checks."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from conformance.legatus import (  # noqa: E402
    FixtureVerifier,
    JournalCorrupt,
    JournalStore,
    MAX_BODY_BYTES,
    MAX_SAFE_INTEGER,
    Runtime,
    make_envelope,
    parse_candidate,
    pcp_idempotency_key,
)


A = "urn:pcp:principal:a"
B = "urn:pcp:principal:b"
C = "urn:pcp:principal:c"
X = "urn:pcp:principal:x"


def env(
    envelope_id: str,
    move: str,
    seq: int,
    now: int,
    signer: str,
    payload: dict,
    parent: str | None = None,
    *,
    thread: str = "t1",
    sig: str = "SIG_PENDING",
) -> dict:
    return make_envelope(
        envelope_id,
        thread,
        move,
        seq,
        now,
        signer,
        payload,
        parents=[] if parent is None else [parent],
        sig=sig,
    )


def _expect(value, expected, message: str) -> None:
    if value != expected:
        raise AssertionError(f"{message}: expected {expected!r}, got {value!r}")


def case_seven_moves() -> None:
    runtime = Runtime()
    _expect(runtime.submit(env("e1", "delegate", 1, 10, A, {"assignee": B, "task_ref": "work-1"}))["state"], "running", "delegate")
    _expect(runtime.submit(env("e2", "handoff", 2, 11, B, {"to": C}, "e1"))["floor"], C, "handoff")
    _expect(runtime.submit(env("e3", "fail", 3, 12, C, {"code": "FAIL_FAULT"}, "e2"))["state"], "failed", "fail")
    _expect(runtime.submit(env("e4", "retry", 4, 13, A, {"of": "e3", "assignee": B}, "e3"))["state"], "running", "retry")
    _expect(runtime.submit(env("e5", "cancel", 5, 14, A, {"code": "CANCEL_STOP"}, "e4"))["state"], "cancelled", "cancel")


def case_gate_and_approve() -> None:
    runtime = Runtime()
    first = env("e1", "delegate", 1, 100, A, {"assignee": B, "task_ref": "work-1", "gate": True, "approver": A})
    _expect(runtime.submit(first)["state"], "awaiting_approve", "gated delegate")
    approved = runtime.submit(env("e2", "approve", 2, 101, A, {"of": "e1"}, "e1"))
    _expect((approved["state"], approved["floor"]), ("running", B), "approve")


def case_timeout_resume_replay() -> None:
    runtime = Runtime()
    first = env("e1", "delegate", 1, 100, A, {"assignee": B, "task_ref": "work-1", "gate": True, "approver": A, "deadline_now": 250})
    runtime.submit(first)
    timeout = runtime.advance_now("t1", 251)
    _expect(timeout["kind"], "timeout", "durable timeout")
    resumed = runtime.submit(env("e2", "resume", 2, 260, A, {"gate": False}, "e1"), runtime_now=260)
    _expect((resumed["state"], resumed["pending"]), ("awaiting_approve", "e1"), "resume thaw")
    recovered = runtime.recover({"t1": 260})
    _expect(recovered.threads["t1"].public(), runtime.threads["t1"].public(), "post-timeout recovery")


def case_timeout_precedes_candidate() -> None:
    runtime = Runtime()
    runtime.submit(env("e1", "delegate", 1, 100, A, {"assignee": B, "task_ref": "w", "deadline_now": 250}))
    rejected = runtime.submit(env("e2", "handoff", 2, 251, B, {"to": C}, "e1"))
    _expect(rejected["code"], "LEGATUS_E_ILLEGAL_TRANSITION", "post-timeout candidate")
    _expect((len(runtime.store.records), runtime.store.records[1]["kind"]), (2, "timeout"), "timeout order")


def case_rejected_clock_cannot_force_timeout() -> None:
    runtime = Runtime()
    runtime.submit(env("e1", "delegate", 1, 100, A, {"assignee": B, "task_ref": "w", "deadline_now": 250}))
    invalid = env("e2", "handoff", 2, 251, B, {"to": C}, "e1", sig="bad")
    _expect(runtime.submit(invalid)["code"], "LEGATUS_E_SIG", "invalid proof")
    outsider = env("e3", "handoff", 2, 251, C, {"to": A}, "e1")
    _expect(runtime.submit(outsider)["code"], "LEGATUS_E_NO_FLOOR", "missing floor")
    _expect((len(runtime.store.records), runtime.threads["t1"].state), (1, "running"), "untrusted clock isolation")


def case_recovery_appends_timeout_once() -> None:
    runtime = Runtime()
    runtime.submit(env("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w", "deadline_now": 2}))
    recovered = runtime.recover({"t1": 3})
    _expect((len(runtime.store.records), recovered.threads["t1"].state), (2, "paused"), "recovery timeout")
    recovered.recover({"t1": 4})
    _expect(len(runtime.store.records), 2, "timeout idempotency")


def case_timeout_tamper_rejected() -> None:
    runtime = Runtime()
    runtime.submit(env("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w", "deadline_now": 2}))
    runtime.advance_now("t1", 3)
    records = deepcopy(runtime.store.records)
    records[1]["deadline_now"] = 4
    try:
        Runtime(JournalStore(records, writer_id="writer-1", writer_epoch=1))
    except JournalCorrupt:
        return
    raise AssertionError("tampered timeout record replayed")


def case_writer_fencing() -> None:
    store = JournalStore(writer_id="writer-a", writer_epoch=1)
    old = Runtime(store, writer_id="writer-a", writer_epoch=1)
    old.submit(env("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}))
    store.acquire_writer("writer-b", 2)
    rejected = old.submit(env("e2", "handoff", 2, 2, B, {"to": C}, "e1"))
    _expect(rejected["code"], "LEGATUS_E_WRITER_UNAVAILABLE", "stale writer")
    current = Runtime(store, writer_id="writer-b", writer_epoch=2)
    _expect(current.submit(env("e2", "handoff", 2, 2, B, {"to": C}, "e1"))["outcome"], "committed", "current writer")


def case_writer_compare_and_set() -> None:
    store = JournalStore(writer_id="writer-a", writer_epoch=1)
    current = Runtime(store, writer_id="writer-a", writer_epoch=1)
    stale_view = Runtime(store, writer_id="writer-a", writer_epoch=1)
    current.submit(env("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}))
    other_thread = env("e2", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}, thread="t2")
    rejected = stale_view.submit(other_thread)
    _expect((rejected["code"], len(store.records)), ("LEGATUS_E_WRITER_UNAVAILABLE", 1), "stale position")


def case_pcp_binding() -> None:
    verifier = FixtureVerifier()
    runtime = Runtime(verifier=verifier)
    candidate = env("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"})
    runtime.submit(candidate)
    request = verifier.requests[0]
    _expect(request["profile"], "pcp-legatus-v1", "PCP profile")
    _expect(request["purpose"], "legatus.delegate", "PCP purpose")
    _expect(request["proof"], candidate["sig"], "opaque proof")
    _expect(request["envelope"], candidate, "signed envelope binding")


def case_pcp_integration_shape() -> None:
    proof = "pcp1.opaque-compact-fixture"
    observed: dict = {}

    def verifier(request: dict) -> dict:
        observed["request"] = deepcopy(request)
        unsigned = deepcopy(request["envelope"])
        del unsigned["sig"]
        observed["protected"] = {
            "context": "pcp-legatus-v1",
            "signer_id": request["signer_id"],
            "key_id": "key-fixture-1",
            "grant_id": "urn:pcp:grant:fixture-1",
            "purpose": request["purpose"],
            "envelope": unsigned,
        }
        observed["reservation"] = {
            "authorization_id": "fixture-auth",
            "thread": request["envelope"]["thread"],
            "envelope_id": request["envelope"]["id"],
            "idempotency_key": pcp_idempotency_key(
                request["envelope"]["thread"], request["envelope"]["id"]
            ),
            "request_digest_input": deepcopy(observed["protected"]),
        }
        return {"profile": "pcp-legatus-v1", "status": "allow", "authorization_id": "fixture-auth"}

    def finalizer(request: dict) -> dict:
        observed["finalization"] = deepcopy(request)
        reservation = observed["reservation"]
        if (
            request["authorization_id"] != reservation["authorization_id"]
            or request["thread"] != reservation["thread"]
            or request["envelope_id"] != reservation["envelope_id"]
            or pcp_idempotency_key(request["thread"], request["envelope_id"])
            != reservation["idempotency_key"]
        ):
            raise RuntimeError("finalization binding mismatch")
        return {
            "profile": "pcp-legatus-v1",
            "status": "finalized",
            "authorization_id": request["authorization_id"],
            "outcome": request["outcome"],
        }

    candidate = env(
        "env-1",
        "delegate",
        1,
        1,
        A,
        {"assignee": B, "task_ref": "w"},
        thread="thread-1",
        sig=proof,
    )
    _expect(Runtime(verifier=verifier, finalizer=finalizer).submit(candidate)["outcome"], "committed", "PCP integration commit")
    _expect(set(observed["request"]), {"profile", "signer_id", "purpose", "envelope", "proof"}, "request fields")
    _expect(observed["request"]["proof"], proof, "whole opaque proof")
    expected = {
        "context": "pcp-legatus-v1",
        "signer_id": A,
        "key_id": "key-fixture-1",
        "grant_id": "urn:pcp:grant:fixture-1",
        "purpose": "legatus.delegate",
        "envelope": {key: deepcopy(value) for key, value in candidate.items() if key != "sig"},
    }
    _expect(observed["protected"], expected, "protected JCS object")
    _expect(observed["reservation"]["request_digest_input"], expected, "reservation digest input")
    _expect(
        observed["reservation"]["idempotency_key"],
        "legatus:sha256:38f95fbdb73b248fa82ccd3f9a91a7c5d6cf0d93edf1016b1b6ba060a3fa5c38",
        "reservation idempotency key",
    )
    _expect(observed["finalization"], {
        "profile": "pcp-legatus-v1",
        "authorization_id": "fixture-auth",
        "outcome": "commit",
        "envelope_id": "env-1",
        "thread": "thread-1",
        "journal_position": 1,
    }, "PCP commit finalization")


def case_pcp_reservation_release() -> None:
    verifier = FixtureVerifier()
    runtime = Runtime(verifier=verifier)
    runtime.submit(env("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}))
    rejected = runtime.submit(env("e2", "handoff", 2, 2, C, {"to": A}, "e1"))
    _expect(rejected["code"], "LEGATUS_E_NO_FLOOR", "deterministic rejection")
    _expect(verifier.finalizations[-1], {
        "profile": "pcp-legatus-v1",
        "authorization_id": "fixture-authorization:e2",
        "outcome": "release",
        "envelope_id": "e2",
        "thread": "t1",
        "journal_position": None,
    }, "PCP release finalization")


def case_pcp_idempotency_key() -> None:
    left = pcp_idempotency_key("a:b", "c")
    right = pcp_idempotency_key("a", "b:c")
    _expect(left, "legatus:sha256:8f1c8bf256a489d8b9a05375c45e7ac63838286790680c418e82ce8a94c14c5c", "left PCP key")
    _expect(right, "legatus:sha256:4aebc886d9c6ada7592289f28e3b5c1ed7ae6e1878b5e0c9da82e4ca693422d5", "right PCP key")
    if left == right:
        raise AssertionError("delimiter-bearing identities collided")


def case_pcp_crash_reconciliation() -> None:
    verifier = FixtureVerifier(finalize_available=False)
    runtime = Runtime(verifier=verifier)
    ack = runtime.submit(env("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}))
    _expect(ack["authorization_state"], "reconciliation_required", "unfinalized commit ack")
    verifier.finalize_available = True
    recovered = runtime.recover()
    _expect(recovered.reconcile_pcp()[0]["finalized"], True, "recovered PCP commit")
    _expect(recovered.acks["e1"]["authorization_state"], "committed", "reconciled ack")


def case_pcp_ambiguous_append() -> None:
    verifier = FixtureVerifier()
    store = JournalStore(writer_id="writer-a", writer_epoch=1)
    winner = Runtime(store, writer_id="writer-a", writer_epoch=1, verifier=verifier)
    stale = Runtime(store, writer_id="writer-a", writer_epoch=1, verifier=verifier)
    candidate = env("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"})
    winner.submit(candidate)
    _expect(stale.submit(candidate)["code"], "LEGATUS_E_WRITER_UNAVAILABLE", "ambiguous append")
    resolution = stale.reconcile_ambiguous_pcp()[0]
    _expect((resolution["outcome"], resolution["finalized"]), ("commit", True), "journal identity reconciliation")


def case_pcp_error_mapping() -> None:
    candidate = env("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}, sig="bad")
    bad = Runtime(verifier=FixtureVerifier("bad_signature")).submit(candidate)
    _expect(bad["code"], "LEGATUS_E_SIG", "invalid proof mapping")
    purpose = Runtime(verifier=FixtureVerifier("proof_purpose_mismatch")).submit(candidate)
    _expect(purpose["code"], "LEGATUS_E_SIG", "protected purpose mapping")
    denied = Runtime(verifier=FixtureVerifier("revoked")).submit(candidate)
    _expect((denied["kind"], denied["code"]), ("pcp_result", "revoked"), "authority disposition")


def case_pcp_malformed_result() -> None:
    def malformed(_request: dict) -> dict:
        return {"profile": "pcp-legatus-v1", "status": "allow", "authorization_id": "a", "extra": True}

    result = Runtime(verifier=malformed).submit(
        env("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}, sig="proof")
    )
    _expect((result["kind"], result["code"], result["retriable"]), ("pcp_result", "unavailable", True), "malformed PCP result")


def case_schema_bounds() -> None:
    runtime = Runtime()
    too_long = env("x" * 257, "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"})
    _expect(runtime.submit(too_long)["code"], "LEGATUS_E_SCHEMA", "id bound")
    unsafe = env("e1", "delegate", 1, MAX_SAFE_INTEGER + 1, A, {"assignee": B, "task_ref": "w"})
    _expect(runtime.submit(unsafe)["code"], "LEGATUS_E_SCHEMA", "integer bound")
    try:
        parse_candidate('{"legatus":0,"legatus":0}')
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate JSON member accepted")
    try:
        parse_candidate('"' + ('x' * MAX_BODY_BYTES) + '"')
    except ValueError:
        pass
    else:
        raise AssertionError("oversized body accepted")


def case_protocol_boundaries() -> None:
    runtime = Runtime()
    _expect(runtime.submit({"message": "delegate this"})["code"], "NOT_A_SUBMIT", "non-submit object")
    wrong_signer = env("e1", "delegate", 1, 1, "urn:pcp:agent:a", {"assignee": B, "task_ref": "w"})
    _expect(runtime.submit(wrong_signer)["code"], "LEGATUS_E_SIG", "signer namespace")
    wrong_assignee = env("e1", "delegate", 1, 1, A, {"assignee": "urn:pcp:agent:b", "task_ref": "w"})
    _expect(runtime.submit(wrong_assignee)["code"], "LEGATUS_E_SCHEMA", "assignee namespace")
    timestamp = env("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"})
    timestamp["clock"]["ts"] = "tomorrow"
    _expect(runtime.submit(timestamp)["code"], "LEGATUS_E_SCHEMA", "RFC3339 timestamp")


def case_duplicate_is_ack() -> None:
    runtime = Runtime()
    candidate = env("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"})
    _expect(runtime.submit(candidate)["outcome"], "committed", "first submit")
    _expect(runtime.submit(candidate)["outcome"], "duplicate", "identical replay")
    changed = deepcopy(candidate)
    changed["payload"]["assignee"] = C
    _expect(runtime.submit(changed)["code"], "LEGATUS_E_DUP_ID", "conflicting replay")


def case_unsigned_transcript() -> None:
    runtime = Runtime()
    runtime.submit(env("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}))
    transcript = runtime.export_transcript("t1")
    _expect(transcript["integrity"], {"mode": "unsigned_fixture"}, "fixture integrity marker")
    if "sig" in transcript:
        raise AssertionError("unsigned fixture contains an ambiguous sig field")


CASES = (
    ("moves.seven", case_seven_moves),
    ("gate.approve", case_gate_and_approve),
    ("recovery.timeout-resume", case_timeout_resume_replay),
    ("recovery.timeout-precedes-candidate", case_timeout_precedes_candidate),
    ("recovery.rejected-clock-isolation", case_rejected_clock_cannot_force_timeout),
    ("recovery.timeout-on-restart", case_recovery_appends_timeout_once),
    ("recovery.timeout-tamper", case_timeout_tamper_rejected),
    ("writer.fencing", case_writer_fencing),
    ("writer.compare-and-set", case_writer_compare_and_set),
    ("pcp.binding", case_pcp_binding),
    ("pcp.integration-shape", case_pcp_integration_shape),
    ("pcp.idempotency-key", case_pcp_idempotency_key),
    ("pcp.reservation-release", case_pcp_reservation_release),
    ("pcp.crash-reconciliation", case_pcp_crash_reconciliation),
    ("pcp.ambiguous-append", case_pcp_ambiguous_append),
    ("pcp.error-mapping", case_pcp_error_mapping),
    ("pcp.malformed-result", case_pcp_malformed_result),
    ("schema.bounds", case_schema_bounds),
    ("schema.protocol-boundaries", case_protocol_boundaries),
    ("idempotency.duplicate", case_duplicate_is_ack),
    ("transcript.unsigned-fixture", case_unsigned_transcript),
)


def main() -> int:
    results = []
    for case_id, case in CASES:
        try:
            case()
        except Exception as exc:  # deterministic report boundary
            results.append({"id": case_id, "status": "fail", "error": f"{type(exc).__name__}: {exc}"})
        else:
            results.append({"id": case_id, "status": "pass"})
    passed = sum(result["status"] == "pass" for result in results)
    report = {
        "implementation": "legatus-python-reference/0.1",
        "protocol": "legatus/0.1",
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "cases": results,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
