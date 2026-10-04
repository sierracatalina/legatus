from hashlib import sha256
import unittest

from conformance.execution_profile import ProfileDenied, journal_relation, run_authorized
from conformance.legatus import FixtureVerifier, JournalStore, Runtime, make_envelope


A = "urn:pcp:principal:a"
B = "urn:pcp:principal:b"
C = "urn:pcp:principal:c"
TASK = b'{"format":"task-manifest-v1","instruction":"send only the approved public summary"}'
TASK_REF = "sha256:" + sha256(TASK).hexdigest()
GRANT_REF = "urn:pcp:grant:effect-1"
EFFECT = {
    "action": "send",
    "destination": "urn:example:public-summary",
    "purpose": "x.xchat.fulfill",
}


def envelope(envelope_id, move, seq, signer, payload, parent=None):
    return make_envelope(
        envelope_id,
        "thread-1",
        move,
        seq,
        seq,
        signer,
        payload,
        parents=[] if parent is None else [parent],
    )


class ExecutionProfileTests(unittest.TestCase):
    def setUp(self):
        self.runtime = Runtime()
        self.runtime.submit(envelope("e1", "delegate", 1, A, {"assignee": B, "task_ref": TASK_REF}))
        self.action_grants = {(GRANT_REF, B, TASK_REF, tuple(EFFECT.items()))}
        self.disclosures = {("bundle-1", GRANT_REF, B, "e1", TASK_REF, tuple(EFFECT.items()))}
        self.executed = []

    def authorize_action(self, request):
        return (
            request["thread"] == "thread-1"
            and request["recipient"] == request["to_principal"]
            and (request["grant_ref"], request["recipient"], request["task_ref"], tuple(request["effect"].items()))
            in self.action_grants
        )

    def verify_disclosure(self, request):
        return (
            request["recipient"] == request["to_principal"]
            and (
                request["disclosure_ref"],
                request["grant_ref"],
                request["recipient"],
                request["installing_envelope_id"],
                request["task_ref"],
                tuple(request["effect"].items()),
            ) in self.disclosures
        )

    def execute(self, task, checkpoint):
        self.executed.append((task, checkpoint))
        return "sent"

    def run_effect(self, *, runtime=None, task=TASK, disclosure_ref="bundle-1", now=1):
        return run_authorized(
            runtime or self.runtime,
            "thread-1",
            authoritative_now=now,
            task_bytes=task,
            grant_ref=GRANT_REF,
            disclosure_ref=disclosure_ref,
            effect=EFFECT,
            authorize_action=self.authorize_action,
            verify_disclosure=self.verify_disclosure,
            execute=self.execute,
        )

    def assert_denied(self, code, **kwargs):
        with self.assertRaises(ProfileDenied) as caught:
            self.run_effect(**kwargs)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(self.executed, [])

    def test_digest_pinned_task_and_current_disclosure_execute(self):
        result = self.run_effect()
        self.assertEqual(result["result"], "sent")
        self.assertEqual(result["checkpoint"]["installing_envelope_id"], "e1")
        self.assertEqual(result["checkpoint"]["recipient"], B)
        self.assertIsNone(result["checkpoint"]["from_principal"])
        self.assertEqual(self.executed[0][0], TASK)

    def test_mutated_task_or_mutable_reference_cannot_execute(self):
        self.assert_denied("LEGATUS_PROFILE_E_TASK_REVISION", task=TASK + b" and private notes")
        legacy = Runtime()
        legacy.submit(envelope("e1", "delegate", 1, A, {"assignee": B, "task_ref": "mutable://task"}))
        self.assert_denied("LEGATUS_PROFILE_E_TASK_REVISION", runtime=legacy)

    def test_handoff_requires_fresh_recipient_authority(self):
        self.runtime.submit(envelope("e2", "handoff", 2, B, {"to": C}, "e1"))
        self.assert_denied("LEGATUS_PROFILE_E_ACTION_AUTHORITY", now=2)
        self.action_grants.add((GRANT_REF, C, TASK_REF, tuple(EFFECT.items())))
        self.assert_denied("LEGATUS_PROFILE_E_DISCLOSURE_AUTHORIZATION", now=2)
        self.disclosures.add(("bundle-2", GRANT_REF, C, "e2", TASK_REF, tuple(EFFECT.items())))
        result = self.run_effect(disclosure_ref="bundle-2", now=2)
        self.assertEqual(result["checkpoint"]["installing_envelope_id"], "e2")
        self.assertEqual(result["checkpoint"]["from_principal"], B)

    def test_same_recipient_handoff_still_requires_fresh_authority(self):
        self.runtime.submit(envelope("e2", "handoff", 2, B, {"to": B}, "e1"))
        self.assert_denied("LEGATUS_PROFILE_E_DISCLOSURE_AUTHORIZATION", now=2)
        self.disclosures.add(("bundle-2", GRANT_REF, B, "e2", TASK_REF, tuple(EFFECT.items())))
        self.assertEqual(self.run_effect(disclosure_ref="bundle-2", now=2)["result"], "sent")

    def test_gated_handoff_waits_for_approval_and_binds_approval_event(self):
        self.runtime.submit(envelope("e2", "handoff", 2, B, {"to": C, "gate": True, "approver": A}, "e1"))
        self.assert_denied("LEGATUS_PROFILE_E_STATE", now=2)
        self.runtime.submit(envelope("e3", "approve", 3, A, {"of": "e2"}, "e2"))
        self.action_grants.add((GRANT_REF, C, TASK_REF, tuple(EFFECT.items())))
        self.disclosures.add(("bundle-2", GRANT_REF, C, "e2", TASK_REF, tuple(EFFECT.items())))
        self.assert_denied("LEGATUS_PROFILE_E_DISCLOSURE_AUTHORIZATION", disclosure_ref="bundle-2", now=3)
        self.disclosures.add(("bundle-3", GRANT_REF, C, "e3", TASK_REF, tuple(EFFECT.items())))
        checkpoint = self.run_effect(disclosure_ref="bundle-3", now=3)["checkpoint"]
        self.assertEqual(checkpoint["installing_envelope_id"], "e3")
        self.assertEqual(checkpoint["from_principal"], B)

    def test_stale_view_and_stale_writer_cannot_execute(self):
        store = self.runtime.store
        stale_view = Runtime(store)
        self.runtime.submit(envelope("e2", "handoff", 2, B, {"to": C}, "e1"))
        self.assert_denied("LEGATUS_PROFILE_E_STALE_VIEW", runtime=stale_view, now=2)
        store.acquire_writer("writer-2", 2)
        self.assert_denied("LEGATUS_PROFILE_E_STALE_VIEW", now=2)

    def test_pending_pcp_finalization_blocks_effect(self):
        verifier = FixtureVerifier(finalize_available=False)
        runtime = Runtime(verifier=verifier)
        runtime.submit(envelope("e1", "delegate", 1, A, {"assignee": B, "task_ref": TASK_REF}))
        self.assert_denied("LEGATUS_PROFILE_E_PCP_PENDING", runtime=runtime)
        verifier.finalize_available = True
        runtime.reconcile_pcp()
        self.assertEqual(self.run_effect(runtime=runtime)["result"], "sent")

    def test_disclosure_verifier_failure_is_closed(self):
        with self.assertRaises(ProfileDenied) as caught:
            run_authorized(
                self.runtime,
                "thread-1",
                authoritative_now=1,
                task_bytes=TASK,
                grant_ref=GRANT_REF,
                disclosure_ref="bundle-1",
                effect=EFFECT,
                authorize_action=self.authorize_action,
                verify_disclosure=lambda _request: (_ for _ in ()).throw(RuntimeError("offline")),
                execute=self.execute,
            )
        self.assertEqual(caught.exception.code, "LEGATUS_PROFILE_E_DISCLOSURE_AUTHORIZATION")
        self.assertEqual(self.executed, [])

    def test_action_authority_failure_is_closed_before_disclosure(self):
        verified = []
        with self.assertRaises(ProfileDenied) as caught:
            run_authorized(
                self.runtime,
                "thread-1",
                authoritative_now=1,
                task_bytes=TASK,
                grant_ref="urn:pcp:grant:missing",
                disclosure_ref="bundle-1",
                effect=EFFECT,
                authorize_action=self.authorize_action,
                verify_disclosure=lambda _request: verified.append(True),
                execute=self.execute,
            )
        self.assertEqual(caught.exception.code, "LEGATUS_PROFILE_E_ACTION_AUTHORITY")
        self.assertEqual(verified, [])
        self.assertEqual(self.executed, [])

    def test_journal_comparison_quarantines_fork(self):
        left = self.runtime.store.records[:]
        self.runtime.submit(envelope("e2", "handoff", 2, B, {"to": C}, "e1"))
        right = self.runtime.store.records[:]
        other = Runtime()
        other.submit(envelope("e1", "delegate", 1, A, {"assignee": B, "task_ref": TASK_REF}))
        other.submit(envelope("e2", "handoff", 2, B, {"to": A}, "e1"))
        fork = other.store.records[:]
        self.assertEqual(journal_relation(left, left), "same")
        self.assertEqual(journal_relation(left, right), "left_prefix")
        self.assertEqual(journal_relation(right, left), "right_prefix")
        self.assertEqual(journal_relation(right, fork), "fork")
        with self.assertRaises(ProfileDenied):
            journal_relation(left, [{"position": 2}])

    def test_due_timeout_blocks_effect(self):
        runtime = Runtime()
        runtime.submit(envelope("e1", "delegate", 1, A, {
            "assignee": B, "task_ref": TASK_REF, "deadline_now": 1,
        }))
        self.assert_denied("LEGATUS_PROFILE_E_STATE", runtime=runtime, now=2)
        self.assertEqual(runtime.store.records[-1]["kind"], "timeout")

    def test_in_place_journal_tamper_blocks_effect(self):
        self.runtime.store.records[0]["envelope"]["payload"]["task_ref"] = "sha256:" + "0" * 64
        self.assert_denied("LEGATUS_PROFILE_E_STALE_VIEW")


if __name__ == "__main__":
    unittest.main()
