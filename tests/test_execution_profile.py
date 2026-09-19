from hashlib import sha256
import unittest

from conformance.execution_profile import ProfileDenied, journal_relation, run_authorized
from conformance.legatus import FixtureVerifier, JournalStore, Runtime, make_envelope


A = "urn:pcp:principal:a"
B = "urn:pcp:principal:b"
C = "urn:pcp:principal:c"
TASK = b'{"format":"task-manifest-v1","instruction":"send only the approved public summary"}'
TASK_REF = "sha256:" + sha256(TASK).hexdigest()


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
        self.grants = {("context-1", B, "e1", TASK_REF)}
        self.executed = []

    def verify_context(self, request):
        return (
            request["thread"] == "thread-1"
            and request["recipient"] == request["to_principal"]
            and (request["context_ref"], request["recipient"], request["installing_envelope_id"], request["task_ref"])
            in self.grants
        )

    def execute(self, task, checkpoint):
        self.executed.append((task, checkpoint))
        return "sent"

    def run_effect(self, *, runtime=None, task=TASK, context_ref="context-1", now=1):
        return run_authorized(
            runtime or self.runtime,
            "thread-1",
            authoritative_now=now,
            task_bytes=task,
            context_ref=context_ref,
            verify_context=self.verify_context,
            execute=self.execute,
        )

    def assert_denied(self, code, **kwargs):
        with self.assertRaises(ProfileDenied) as caught:
            self.run_effect(**kwargs)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(self.executed, [])

    def test_digest_pinned_task_and_current_context_execute(self):
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
        self.assert_denied("LEGATUS_PROFILE_E_CONTEXT_AUTHORITY", now=2)
        self.grants.add(("context-2", C, "e2", TASK_REF))
        result = self.run_effect(context_ref="context-2", now=2)
        self.assertEqual(result["checkpoint"]["installing_envelope_id"], "e2")
        self.assertEqual(result["checkpoint"]["from_principal"], B)

    def test_same_recipient_handoff_still_requires_fresh_authority(self):
        self.runtime.submit(envelope("e2", "handoff", 2, B, {"to": B}, "e1"))
        self.assert_denied("LEGATUS_PROFILE_E_CONTEXT_AUTHORITY", now=2)
        self.grants.add(("context-2", B, "e2", TASK_REF))
        self.assertEqual(self.run_effect(context_ref="context-2", now=2)["result"], "sent")

    def test_gated_handoff_waits_for_approval_and_binds_approval_event(self):
        self.runtime.submit(envelope("e2", "handoff", 2, B, {"to": C, "gate": True, "approver": A}, "e1"))
        self.assert_denied("LEGATUS_PROFILE_E_STATE", now=2)
        self.runtime.submit(envelope("e3", "approve", 3, A, {"of": "e2"}, "e2"))
        self.grants.add(("context-2", C, "e2", TASK_REF))
        self.assert_denied("LEGATUS_PROFILE_E_CONTEXT_AUTHORITY", context_ref="context-2", now=3)
        self.grants.add(("context-3", C, "e3", TASK_REF))
        checkpoint = self.run_effect(context_ref="context-3", now=3)["checkpoint"]
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

    def test_context_verifier_failure_is_closed(self):
        with self.assertRaises(ProfileDenied) as caught:
            run_authorized(
                self.runtime,
                "thread-1",
                authoritative_now=1,
                task_bytes=TASK,
                context_ref="context-1",
                verify_context=lambda _request: (_ for _ in ()).throw(RuntimeError("offline")),
                execute=self.execute,
            )
        self.assertEqual(caught.exception.code, "LEGATUS_PROFILE_E_CONTEXT_AUTHORITY")
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
