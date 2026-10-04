"""Deterministic PCP grant -> Context Layer disclosure -> Legatus effect trace."""

from __future__ import annotations

from hashlib import sha256
import json

from .execution_profile import run_authorized
from .legatus import Runtime, make_envelope


PRINCIPAL = "urn:pcp:principal:worker"
OWNER = "urn:pcp:principal:owner"
GRANT_REF = "urn:pcp:grant:trace-1"
DISCLOSURE_REF = "urn:cl:bundle:trace-1"
TASK = b'{"format":"task-manifest-v1","instruction":"publish approved summary"}'
TASK_REF = "sha256:" + sha256(TASK).hexdigest()
EFFECT = {
    "action": "publish",
    "destination": "urn:example:approved-summary",
    "purpose": "x.xchat.fulfill",
}


def run_trace() -> dict:
    runtime = Runtime()
    runtime.submit(make_envelope(
        "delegate-1",
        "trace-thread",
        "delegate",
        1,
        1,
        OWNER,
        {"assignee": PRINCIPAL, "task_ref": TASK_REF},
    ))
    events: list[dict] = []

    def authorize_action(request: dict) -> bool:
        allowed = (
            request["grant_ref"] == GRANT_REF
            and request["recipient"] == PRINCIPAL
            and request["task_ref"] == TASK_REF
            and request["effect"] == EFFECT
        )
        events.append({
            "step": "pcp.grant.authorized",
            "authority_source": "principal-signed-grant-fixture",
            "grant_ref": request["grant_ref"],
            "principal": request["recipient"],
            "allowed": allowed,
        })
        return allowed

    def verify_disclosure(request: dict) -> bool:
        allowed = (
            request["disclosure_ref"] == DISCLOSURE_REF
            and request["grant_ref"] == GRANT_REF
            and request["recipient"] == PRINCIPAL
            and request["installing_envelope_id"] == "delegate-1"
            and request["task_digest"] == sha256(TASK).hexdigest()
            and request["effect"] == EFFECT
        )
        events.append({
            "step": "context.disclosure.authorized",
            "authority_source": "none",
            "disclosure_ref": request["disclosure_ref"],
            "recipient": request["recipient"],
            "allowed": allowed,
        })
        return allowed

    def execute(task_bytes: bytes, checkpoint: dict) -> str:
        events.append({
            "step": "legatus.effect.executed",
            "task_digest": sha256(task_bytes).hexdigest(),
            "journal_position": checkpoint["journal_position"],
            "writer_epoch": checkpoint["writer_epoch"],
        })
        return "published"

    result = run_authorized(
        runtime,
        "trace-thread",
        authoritative_now=1,
        task_bytes=TASK,
        grant_ref=GRANT_REF,
        disclosure_ref=DISCLOSURE_REF,
        effect=EFFECT,
        authorize_action=authorize_action,
        verify_disclosure=verify_disclosure,
        execute=execute,
    )
    return {
        "protocol": "legatus/0.1",
        "profile": "grant-disclosure-execution-trace-v1",
        "status": "pass",
        "result": result["result"],
        "events": events,
    }


if __name__ == "__main__":
    print(json.dumps(run_trace(), indent=2, sort_keys=True))
