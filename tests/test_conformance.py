from copy import deepcopy
import json
from pathlib import Path
import unittest

from conformance.legatus import (
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


def envelope(envelope_id, move, seq, now, signer, payload, parent=None, sig="SIG_PENDING"):
    return make_envelope(
        envelope_id,
        "thread-1",
        move,
        seq,
        now,
        signer,
        payload,
        parents=[] if parent is None else [parent],
        sig=sig,
    )


class ProtocolTests(unittest.TestCase):
    def test_all_schemas_are_strict_and_parse(self):
        root = Path(__file__).resolve().parents[1] / "schemas"
        schemas = list(root.glob("*.schema.json"))
        self.assertGreaterEqual(len(schemas), 10)
        for path in schemas:
            schema = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_seven_move_lifecycle(self):
        runtime = Runtime()
        self.assertEqual(runtime.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}))["state"], "running")
        self.assertEqual(runtime.submit(envelope("e2", "handoff", 2, 2, B, {"to": C}, "e1"))["floor"], C)
        self.assertEqual(runtime.submit(envelope("e3", "fail", 3, 3, C, {"code": "FAIL_FAULT"}, "e2"))["state"], "failed")
        self.assertEqual(runtime.submit(envelope("e4", "retry", 4, 4, A, {"of": "e3", "assignee": B}, "e3"))["state"], "running")
        self.assertEqual(runtime.submit(envelope("e5", "cancel", 5, 5, A, {"code": "CANCEL_STOP"}, "e4"))["state"], "cancelled")

    def test_gate_and_approve(self):
        runtime = Runtime()
        runtime.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w", "gate": True, "approver": A}))
        ack = runtime.submit(envelope("e2", "approve", 2, 2, A, {"of": "e1"}, "e1"))
        self.assertEqual((ack["state"], ack["floor"]), ("running", B))

    def test_timeout_record_makes_resume_replayable(self):
        runtime = Runtime()
        runtime.submit(envelope("e1", "delegate", 1, 100, A, {"assignee": B, "task_ref": "w", "gate": True, "approver": A, "deadline_now": 250}))
        timeout = runtime.advance_now("thread-1", 251)
        self.assertEqual((timeout["kind"], timeout["position"]), ("timeout", 2))
        ack = runtime.submit(envelope("e2", "resume", 2, 260, A, {"gate": False}, "e1"), runtime_now=260)
        self.assertEqual((ack["state"], ack["pending"]), ("awaiting_approve", "e1"))
        recovered = runtime.recover({"thread-1": 260})
        self.assertEqual(recovered.threads["thread-1"].public(), runtime.threads["thread-1"].public())

    def test_candidate_clock_cannot_bypass_due_timeout(self):
        runtime = Runtime()
        runtime.submit(envelope("e1", "delegate", 1, 100, A, {"assignee": B, "task_ref": "w", "deadline_now": 250}))
        result = runtime.submit(envelope("e2", "handoff", 2, 251, B, {"to": C}, "e1"))
        self.assertEqual(result["code"], "LEGATUS_E_ILLEGAL_TRANSITION")
        self.assertEqual((len(runtime.store.records), runtime.store.records[1]["kind"]), (2, "timeout"))
        self.assertEqual(runtime.threads["thread-1"].state, "paused")

    def test_rejected_candidate_clock_cannot_force_timeout(self):
        runtime = Runtime()
        runtime.submit(envelope("e1", "delegate", 1, 100, A, {"assignee": B, "task_ref": "w", "deadline_now": 250}))
        invalid_proof = envelope("e2", "handoff", 2, 251, B, {"to": C}, "e1", sig="bad")
        self.assertEqual(runtime.submit(invalid_proof)["code"], "LEGATUS_E_SIG")
        self.assertEqual((len(runtime.store.records), runtime.threads["thread-1"].state), (1, "running"))

        no_floor = envelope("e3", "handoff", 2, 251, C, {"to": A}, "e1")
        self.assertEqual(runtime.submit(no_floor)["code"], "LEGATUS_E_NO_FLOOR")
        self.assertEqual((len(runtime.store.records), runtime.threads["thread-1"].state), (1, "running"))

    def test_authoritative_clock_on_duplicate_still_records_timeout(self):
        runtime = Runtime()
        candidate = envelope("e1", "delegate", 1, 100, A, {"assignee": B, "task_ref": "w", "deadline_now": 250})
        runtime.submit(candidate)
        duplicate = runtime.submit(candidate, runtime_now=251)
        self.assertEqual((duplicate["outcome"], len(runtime.store.records)), ("duplicate", 2))
        self.assertEqual(runtime.threads["thread-1"].state, "paused")

    def test_recovery_appends_due_timeout_once(self):
        runtime = Runtime()
        runtime.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w", "deadline_now": 2}))
        recovered = runtime.recover({"thread-1": 3})
        self.assertEqual((len(runtime.store.records), recovered.threads["thread-1"].state), (2, "paused"))
        recovered_again = recovered.recover({"thread-1": 4})
        self.assertEqual((len(runtime.store.records), recovered_again.threads["thread-1"].state), (2, "paused"))

    def test_timeout_record_tamper_is_corruption(self):
        runtime = Runtime()
        runtime.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w", "deadline_now": 2}))
        runtime.advance_now("thread-1", 3)
        records = deepcopy(runtime.store.records)
        records[1]["pending"] = "invented"
        with self.assertRaises(JournalCorrupt):
            Runtime(JournalStore(records))

    def test_fencing_rejects_old_writer_after_failover(self):
        store = JournalStore(writer_id="a", writer_epoch=1)
        first = Runtime(store, writer_id="a", writer_epoch=1)
        first.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}))
        store.acquire_writer("b", 2)
        rejected = first.submit(envelope("e2", "handoff", 2, 2, B, {"to": C}, "e1"))
        self.assertEqual(rejected["code"], "LEGATUS_E_WRITER_UNAVAILABLE")
        second = Runtime(store, writer_id="b", writer_epoch=2)
        self.assertEqual(second.submit(envelope("e2", "handoff", 2, 2, B, {"to": C}, "e1"))["outcome"], "committed")

    def test_stale_same_epoch_view_loses_position_compare_and_set(self):
        store = JournalStore(writer_id="a", writer_epoch=1)
        first = Runtime(store, writer_id="a", writer_epoch=1)
        stale = Runtime(store, writer_id="a", writer_epoch=1)
        first.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}))
        other_thread = make_envelope("e2", "thread-2", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"})
        rejected = stale.submit(other_thread)
        self.assertEqual((rejected["code"], len(store.records)), ("LEGATUS_E_WRITER_UNAVAILABLE", 1))

    def test_stale_transcript_uses_one_observed_journal_prefix(self):
        store = JournalStore(writer_id="a", writer_epoch=1)
        current = Runtime(store, writer_id="a", writer_epoch=1)
        current.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}))
        stale = Runtime(store, writer_id="a", writer_epoch=1)
        current.submit(envelope("e2", "handoff", 2, 2, B, {"to": C}, "e1"))
        transcript = stale.export_transcript("thread-1")
        self.assertEqual((transcript["seq_through"], transcript["journal_through"]), (1, 1))
        self.assertEqual([link["envelope"] for link in transcript["links"] if link["role"] == "move"], ["e1"])

    def test_verifier_request_binds_envelope_proof_and_purpose(self):
        verifier = FixtureVerifier()
        runtime = Runtime(verifier=verifier)
        candidate = envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"})
        runtime.submit(candidate)
        self.assertEqual(verifier.requests[0], {
            "profile": "pcp-legatus-v1",
            "signer_id": A,
            "purpose": "legatus.delegate",
            "envelope": candidate,
            "proof": "SIG_PENDING",
        })

    def test_pcp_integration_shape_reconstructs_exact_protected_object(self):
        proof = "pcp1.opaque-compact-fixture"
        observed = {}

        def pcp_verifier(request):
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

        def pcp_finalizer(request):
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

        candidate = envelope("env-1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}, sig=proof)
        ack = Runtime(verifier=pcp_verifier, finalizer=pcp_finalizer).submit(candidate)
        self.assertEqual(ack["outcome"], "committed")
        self.assertEqual(set(observed["request"]), {"profile", "signer_id", "purpose", "envelope", "proof"})
        self.assertEqual(observed["request"]["proof"], proof)
        self.assertEqual(observed["protected"], {
            "context": "pcp-legatus-v1",
            "signer_id": A,
            "key_id": "key-fixture-1",
            "grant_id": "urn:pcp:grant:fixture-1",
            "purpose": "legatus.delegate",
            "envelope": {key: deepcopy(value) for key, value in candidate.items() if key != "sig"},
        })
        self.assertEqual(observed["finalization"], {
            "profile": "pcp-legatus-v1",
            "authorization_id": "fixture-auth",
            "outcome": "commit",
            "envelope_id": "env-1",
            "thread": "thread-1",
            "journal_position": 1,
        })
        self.assertEqual(observed["reservation"]["request_digest_input"], observed["protected"])
        self.assertEqual(
            observed["reservation"]["idempotency_key"],
            "legatus:sha256:38f95fbdb73b248fa82ccd3f9a91a7c5d6cf0d93edf1016b1b6ba060a3fa5c38",
        )

    def test_pcp_idempotency_key_uses_exact_jcs_identity(self):
        self.assertEqual(
            pcp_idempotency_key("thread-1", "env-1"),
            "legatus:sha256:38f95fbdb73b248fa82ccd3f9a91a7c5d6cf0d93edf1016b1b6ba060a3fa5c38",
        )
        left = pcp_idempotency_key("a:b", "c")
        right = pcp_idempotency_key("a", "b:c")
        self.assertEqual(left, "legatus:sha256:8f1c8bf256a489d8b9a05375c45e7ac63838286790680c418e82ce8a94c14c5c")
        self.assertEqual(right, "legatus:sha256:4aebc886d9c6ada7592289f28e3b5c1ed7ae6e1878b5e0c9da82e4ca693422d5")
        self.assertNotEqual(left, right)

    def test_pcp_reservation_commits_after_durable_append(self):
        verifier = FixtureVerifier()
        runtime = Runtime(verifier=verifier)
        ack = runtime.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}))
        authorization_id = "fixture-authorization:e1"
        self.assertEqual(runtime.store.records[0]["authorization_id"], authorization_id)
        self.assertEqual((ack["authorization_id"], ack["authorization_state"]), (authorization_id, "committed"))
        self.assertEqual(verifier.finalizations, [{
            "profile": "pcp-legatus-v1",
            "authorization_id": authorization_id,
            "outcome": "commit",
            "envelope_id": "e1",
            "thread": "thread-1",
            "journal_position": 1,
        }])
        mismatched = deepcopy(verifier.finalizations[0])
        mismatched["thread"] = "thread:1"
        with self.assertRaises(RuntimeError):
            verifier.finalize(mismatched)

    def test_pcp_reservation_releases_on_deterministic_rejection(self):
        verifier = FixtureVerifier()
        runtime = Runtime(verifier=verifier)
        runtime.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}))
        rejected = runtime.submit(envelope("e2", "handoff", 2, 2, C, {"to": A}, "e1"))
        self.assertEqual(rejected["code"], "LEGATUS_E_NO_FLOOR")
        self.assertEqual(verifier.finalizations[-1], {
            "profile": "pcp-legatus-v1",
            "authorization_id": "fixture-authorization:e2",
            "outcome": "release",
            "envelope_id": "e2",
            "thread": "thread-1",
            "journal_position": None,
        })
        self.assertEqual(len(runtime.store.records), 1)

    def test_pcp_commit_reconciles_after_crash_window(self):
        verifier = FixtureVerifier(finalize_available=False)
        runtime = Runtime(verifier=verifier)
        ack = runtime.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}))
        self.assertEqual(ack["authorization_state"], "reconciliation_required")
        self.assertEqual(runtime.pending_pcp_handoffs["fixture-authorization:e1"]["outcome"], "commit")

        verifier.finalize_available = True
        recovered = runtime.recover()
        self.assertEqual(recovered.acks["e1"]["authorization_state"], "reconciliation_required")
        self.assertEqual(recovered.reconcile_pcp(), [{
            "authorization_id": "fixture-authorization:e1",
            "envelope_id": "e1",
            "outcome": "commit",
            "finalized": True,
        }])
        self.assertEqual(recovered.acks["e1"]["authorization_state"], "committed")

    def test_malformed_pcp_finalizer_result_never_claims_committed(self):
        def malformed_finalizer(request):
            return {
                "profile": "pcp-legatus-v1",
                "status": "finalized",
                "authorization_id": request["authorization_id"],
                "outcome": request["outcome"],
                "extra": True,
            }

        verifier = FixtureVerifier()
        runtime = Runtime(verifier=verifier, finalizer=malformed_finalizer)
        ack = runtime.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}))
        self.assertEqual(ack["authorization_state"], "reconciliation_required")
        self.assertEqual(runtime.pending_pcp_handoffs["fixture-authorization:e1"]["outcome"], "commit")

    def test_pcp_failed_release_handoff_is_idempotently_retried(self):
        verifier = FixtureVerifier()
        runtime = Runtime(verifier=verifier)
        runtime.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}))
        verifier.finalize_available = False
        runtime.submit(envelope("e2", "handoff", 2, 2, C, {"to": A}, "e1"))
        self.assertEqual(runtime.pending_pcp_handoffs["fixture-authorization:e2"]["outcome"], "release")

        verifier.finalize_available = True
        results = runtime.reconcile_pcp()
        release = next(result for result in results if result["authorization_id"] == "fixture-authorization:e2")
        self.assertEqual(release, {
            "authorization_id": "fixture-authorization:e2",
            "envelope_id": "e2",
            "outcome": "release",
            "finalized": True,
        })
        self.assertNotIn("fixture-authorization:e2", runtime.pending_pcp_handoffs)

    def test_pcp_ambiguous_append_reconciles_by_journal_identity(self):
        verifier = FixtureVerifier()
        store = JournalStore(writer_id="a", writer_epoch=1)
        winner = Runtime(store, writer_id="a", writer_epoch=1, verifier=verifier)
        stale = Runtime(store, writer_id="a", writer_epoch=1, verifier=verifier)
        candidate = envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"})
        winner.submit(candidate)
        self.assertEqual(stale.submit(candidate)["code"], "LEGATUS_E_WRITER_UNAVAILABLE")
        self.assertIn("fixture-authorization:e1", stale.ambiguous_authorizations)

        reconciled = stale.reconcile_ambiguous_pcp()
        self.assertEqual(reconciled, [{
            "authorization_id": "fixture-authorization:e1",
            "envelope_id": "e1",
            "outcome": "commit",
            "finalized": True,
        }])
        self.assertEqual(verifier.finalizations[-1]["journal_position"], 1)

    def test_pcp_ambiguous_absence_releases_under_writer_fence(self):
        verifier = FixtureVerifier()
        store = JournalStore(writer_id="a", writer_epoch=1)
        winner = Runtime(store, writer_id="a", writer_epoch=1, verifier=verifier)
        stale = Runtime(store, writer_id="a", writer_epoch=1, verifier=verifier)
        winner.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}))
        other = make_envelope("e2", "thread-2", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"})
        self.assertEqual(stale.submit(other)["code"], "LEGATUS_E_WRITER_UNAVAILABLE")

        reconciled = stale.reconcile_ambiguous_pcp()
        self.assertEqual(reconciled[0]["outcome"], "release")
        self.assertIsNone(verifier.finalizations[-1]["journal_position"])

    def test_invalid_proof_maps_to_sig(self):
        runtime = Runtime(verifier=FixtureVerifier("bad_signature"))
        result = runtime.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}, sig="bad"))
        self.assertEqual((result["kind"], result["code"]), ("error", "LEGATUS_E_SIG"))
        self.assertEqual(len(runtime.store.records), 0)

        purpose = Runtime(verifier=FixtureVerifier("proof_purpose_mismatch"))
        result = purpose.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}, sig="proof"))
        self.assertEqual((result["kind"], result["code"]), ("error", "LEGATUS_E_SIG"))

    def test_authority_denial_remains_pcp_result(self):
        runtime = Runtime(verifier=FixtureVerifier("revoked"))
        result = runtime.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}, sig="proof"))
        self.assertEqual((result["kind"], result["code"], result["retriable"]), ("pcp_result", "revoked", False))
        self.assertEqual(len(runtime.store.records), 0)

    def test_verifier_outage_is_retriable_and_does_not_commit(self):
        runtime = Runtime(verifier=FixtureVerifier("unavailable", retriable=True))
        result = runtime.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}, sig="proof"))
        self.assertEqual((result["kind"], result["code"], result["retriable"]), ("pcp_result", "unavailable", True))
        self.assertEqual(len(runtime.store.records), 0)

    def test_malformed_verifier_result_is_unavailable(self):
        verifier = lambda request: {  # noqa: E731 - compact malformed fixture
            "profile": "pcp-legatus-v1",
            "status": "allow",
            "authorization_id": "a",
            "extra": True,
        }
        runtime = Runtime(verifier=verifier)
        result = runtime.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}, sig="proof"))
        self.assertEqual((result["kind"], result["code"], result["retriable"]), ("pcp_result", "unavailable", True))
        self.assertEqual(len(runtime.store.records), 0)

    def test_identical_duplicate_returns_typed_ack(self):
        runtime = Runtime()
        candidate = envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"})
        first = runtime.submit(candidate)
        duplicate = runtime.submit(candidate)
        self.assertEqual((first["outcome"], duplicate["outcome"]), ("committed", "duplicate"))
        self.assertEqual(first["journal_position"], duplicate["journal_position"])
        self.assertEqual(len(runtime.store.records), 1)

    def test_conflicting_duplicate_is_error(self):
        runtime = Runtime()
        candidate = envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"})
        runtime.submit(candidate)
        changed = deepcopy(candidate)
        changed["payload"]["assignee"] = C
        self.assertEqual(runtime.submit(changed)["code"], "LEGATUS_E_DUP_ID")

    def test_cancelled_state_precedes_floor_checks(self):
        runtime = Runtime()
        runtime.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}))
        runtime.submit(envelope("e2", "cancel", 2, 2, A, {"code": "CANCEL_STOP"}, "e1"))
        result = runtime.submit(envelope("e3", "handoff", 3, 3, C, {"to": B}, "e2"))
        self.assertEqual(result["code"], "LEGATUS_E_ALREADY_TERMINAL")

    def test_bounds_extra_keys_and_duplicate_json_members_fail(self):
        runtime = Runtime()
        too_long = envelope("x" * 257, "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"})
        self.assertEqual(runtime.submit(too_long)["code"], "LEGATUS_E_SCHEMA")
        unsafe = envelope("e1", "delegate", 1, MAX_SAFE_INTEGER + 1, A, {"assignee": B, "task_ref": "w"})
        self.assertEqual(runtime.submit(unsafe)["code"], "LEGATUS_E_SCHEMA")
        extra = envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"})
        extra["debug"] = True
        self.assertEqual(runtime.submit(extra)["code"], "LEGATUS_E_SCHEMA")
        with self.assertRaises(ValueError):
            parse_candidate('{"id":"a","id":"b"}')
        with self.assertRaises(ValueError):
            parse_candidate('"' + ('x' * MAX_BODY_BYTES) + '"')

    def test_non_submit_principals_and_timestamp_boundaries(self):
        runtime = Runtime()
        self.assertEqual(runtime.submit({"message": "delegate this"})["code"], "NOT_A_SUBMIT")
        wrong_signer = envelope("e1", "delegate", 1, 1, "urn:pcp:agent:a", {"assignee": B, "task_ref": "w"})
        self.assertEqual(runtime.submit(wrong_signer)["code"], "LEGATUS_E_SIG")
        wrong_assignee = envelope("e1", "delegate", 1, 1, A, {"assignee": "urn:pcp:agent:b", "task_ref": "w"})
        self.assertEqual(runtime.submit(wrong_assignee)["code"], "LEGATUS_E_SCHEMA")
        bad_timestamp = envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"})
        bad_timestamp["clock"]["ts"] = "tomorrow"
        self.assertEqual(runtime.submit(bad_timestamp)["code"], "LEGATUS_E_SCHEMA")

        expired_deadline = envelope("e1", "delegate", 1, 10, A, {"assignee": B, "task_ref": "w", "deadline_now": 9})
        self.assertEqual(runtime.submit(expired_deadline)["code"], "LEGATUS_E_CLOCK_SKEW")

        runtime_deadline = envelope("e1", "delegate", 1, 10, A, {"assignee": B, "task_ref": "w", "deadline_now": 11})
        self.assertEqual(runtime.submit(runtime_deadline, runtime_now=12)["code"], "LEGATUS_E_CLOCK_SKEW")

    def test_replay_rejects_extra_record_fields_and_epoch_regression(self):
        runtime = Runtime()
        runtime.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}))
        extra = deepcopy(runtime.store.records)
        extra[0]["debug"] = True
        with self.assertRaises(JournalCorrupt):
            Runtime(JournalStore(extra))
        epoch_ahead = deepcopy(runtime.store.records)
        epoch_ahead[0]["writer_epoch"] = 2
        with self.assertRaises(JournalCorrupt):
            Runtime(JournalStore(epoch_ahead, writer_epoch=1))

        two = Runtime()
        two.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}))
        two.submit(envelope("e2", "handoff", 2, 2, B, {"to": C}, "e1"))
        duplicate_authorization = deepcopy(two.store.records)
        duplicate_authorization[1]["authorization_id"] = duplicate_authorization[0]["authorization_id"]
        with self.assertRaises(JournalCorrupt):
            Runtime(JournalStore(duplicate_authorization))

    def test_unsigned_fixture_transcript_is_explicit(self):
        runtime = Runtime()
        runtime.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w"}))
        transcript = runtime.export_transcript("thread-1")
        self.assertEqual(transcript["integrity"], {"mode": "unsigned_fixture"})
        self.assertNotIn("sig", transcript)
        move = next(link for link in transcript["links"] if link["role"] == "move")
        self.assertEqual(move["authorization_id"], "fixture-authorization:e1")

    def test_transcript_includes_timeout_journal_events(self):
        runtime = Runtime()
        runtime.submit(envelope("e1", "delegate", 1, 1, A, {"assignee": B, "task_ref": "w", "deadline_now": 2}))
        runtime.advance_now("thread-1", 3)
        transcript = runtime.export_transcript("thread-1")
        self.assertEqual(transcript["clock_events"], [{
            "kind": "timeout",
            "journal_position": 2,
            "after_seq": 1,
            "now": 3,
            "deadline_now": 2,
        }])


if __name__ == "__main__":
    unittest.main()
