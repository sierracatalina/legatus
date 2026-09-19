"""Fail-closed reference seam between Legatus coordination and product execution.

This optional profile changes no Legatus envelope or PCP signed object. The
caller supplies the actual task bytes and a Context Layer authority verifier.
The verifier must authenticate issuance and recipient rights; this module does
not issue or validate Context Layer bundles itself.
"""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import re
from typing import Any, Callable

from .legatus import JournalStore, Runtime, Snapshot, _safe_int


TASK_REF = re.compile(r"^sha256:([0-9a-f]{64})$")


class ProfileDenied(ValueError):
    """Execution profile refusal, separate from in-band Legatus errors."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def journal_relation(left: list[dict[str, Any]], right: list[dict[str, Any]]) -> str:
    """Classify two observed journals without choosing or merging a fork.

    A caller must authenticate each journal before using this comparison.
    Equal positions with different records are a fork, including different
    writer epochs or PCP authorization identifiers.
    """

    for history in (left, right):
        try:
            last_epoch = history[-1]["writer_epoch"] if history else 1
            Runtime(JournalStore(history, writer_epoch=last_epoch))
        except Exception as exc:  # malformed journals fail closed at this comparison boundary
            raise ProfileDenied("LEGATUS_PROFILE_E_INVALID_JOURNAL") from exc
    common = min(len(left), len(right))
    if left[:common] != right[:common]:
        return "fork"
    if len(left) == len(right):
        return "same"
    return "left_prefix" if len(left) < len(right) else "right_prefix"


def _floor_event(runtime: Runtime, thread: str) -> tuple[str, int, str | None, str]:
    """Derive the current floor's installation and signed task reference."""

    task_ref: str | None = None
    floor_event: tuple[str, int, str | None] | None = None
    state = Snapshot(thread=thread)
    for record in runtime.store.records[:runtime._known_position]:
        if record["kind"] == "timeout":
            if record["thread"] == thread:
                state = Runtime._apply_timeout(state, record)
            continue
        envelope = record["envelope"]
        if envelope["thread"] != thread:
            continue
        move = envelope["type"]
        prior_floor = state.floor
        pending_move = state.pending["type"] if state.pending else None
        if move == "delegate":
            task_ref = envelope["payload"]["task_ref"]
        state = Runtime._apply_envelope(state, envelope)
        if move in {"delegate", "handoff", "retry"} and not envelope["payload"].get("gate", False):
            floor_event = (envelope["id"], record["position"], prior_floor)
        if move == "approve" and pending_move in {"delegate", "handoff", "retry"}:
            floor_event = (envelope["id"], record["position"], prior_floor)
    if task_ref is None or floor_event is None or state.floor != runtime.threads[thread].floor:
        raise ProfileDenied("LEGATUS_PROFILE_E_STATE")
    return floor_event[0], floor_event[1], floor_event[2], task_ref


def run_authorized(
    runtime: Runtime,
    thread: str,
    *,
    authoritative_now: int,
    task_bytes: bytes,
    context_ref: str,
    verify_context: Callable[[dict[str, Any]], bool],
    execute: Callable[[bytes, dict[str, Any]], Any],
) -> dict[str, Any]:
    """Check current authority and invoke a synchronous fixture action.

    In production, the effect adapter must keep the same writer fence and
    journal-position precondition through its effect dispatch. The in-process
    locks here demonstrate the ordering only; they are not a distributed fence.
    """

    if (
        not _safe_int(authoritative_now)
        or type(task_bytes) is not bytes
        or not isinstance(context_ref, str)
        or not context_ref
    ):
        raise ProfileDenied("LEGATUS_PROFILE_E_INPUT")
    if not callable(verify_context) or not callable(execute):
        raise ProfileDenied("LEGATUS_PROFILE_E_INPUT")

    # Match Runtime.submit's lock order: runtime first, then store.
    with runtime._lock, runtime.store._lock:
        if (
            runtime.writer_id != runtime.store.writer_id
            or runtime.writer_epoch != runtime.store.writer_epoch
            or runtime._known_position != len(runtime.store.records)
        ):
            raise ProfileDenied("LEGATUS_PROFILE_E_STALE_VIEW")
        try:
            replayed = Runtime(
                runtime.store,
                writer_id=runtime.writer_id,
                writer_epoch=runtime.writer_epoch,
                verifier=runtime.verifier,
                finalizer=runtime.finalizer,
            )
        except Exception as exc:  # a malformed or changed journal cannot authorize an effect
            raise ProfileDenied("LEGATUS_PROFILE_E_INVALID_JOURNAL") from exc
        if (
            replayed.fingerprints != runtime.fingerprints
            or replayed.authorization_ids != runtime.authorization_ids
            or {key: value.public() for key, value in replayed.threads.items()}
            != {key: value.public() for key, value in runtime.threads.items()}
        ):
            raise ProfileDenied("LEGATUS_PROFILE_E_STALE_VIEW")
        state = runtime.threads.get(thread)
        if state is None or authoritative_now < state.now:
            raise ProfileDenied("LEGATUS_PROFILE_E_STATE")
        timeout = runtime.advance_now(thread, authoritative_now)
        if timeout is not None and timeout.get("kind") == "error":
            raise ProfileDenied("LEGATUS_PROFILE_E_STALE_VIEW")
        state = runtime.threads.get(thread)
        if state is None or state.state != "running" or state.floor is None:
            raise ProfileDenied("LEGATUS_PROFILE_E_STATE")

        installing_id, installing_position, from_principal, task_ref = _floor_event(runtime, thread)
        pinned = TASK_REF.fullmatch(task_ref)
        if pinned is None or sha256(task_bytes).hexdigest() != pinned.group(1):
            raise ProfileDenied("LEGATUS_PROFILE_E_TASK_REVISION")

        for record in runtime.store.records[:runtime._known_position]:
            if record["kind"] == "envelope" and record["envelope"]["thread"] == thread:
                ack = runtime.acks.get(record["envelope"]["id"])
                if ack is None or ack["authorization_state"] != "committed":
                    raise ProfileDenied("LEGATUS_PROFILE_E_PCP_PENDING")

        checkpoint = {
            "thread": thread,
            "recipient": state.floor,
            "to_principal": state.floor,
            "from_principal": from_principal,
            "task_ref": task_ref,
            "task_digest": pinned.group(1),
            "installing_envelope_id": installing_id,
            "installing_journal_position": installing_position,
            "journal_position": runtime._known_position,
            "writer_epoch": runtime.writer_epoch,
        }
        request = {**checkpoint, "context_ref": context_ref}
        try:
            allowed = verify_context(deepcopy(request))
        except Exception as exc:
            raise ProfileDenied("LEGATUS_PROFILE_E_CONTEXT_AUTHORITY") from exc
        if allowed is not True:
            raise ProfileDenied("LEGATUS_PROFILE_E_CONTEXT_AUTHORITY")
        if (
            runtime.writer_id != runtime.store.writer_id
            or runtime.writer_epoch != runtime.store.writer_epoch
            or runtime._known_position != len(runtime.store.records)
            or runtime._known_position != checkpoint["journal_position"]
        ):
            raise ProfileDenied("LEGATUS_PROFILE_E_STALE_VIEW")
        result = execute(task_bytes, deepcopy(checkpoint))
        return {"checkpoint": checkpoint, "result": result}
