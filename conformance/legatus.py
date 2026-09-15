"""Small deterministic reference model for the Legatus v0.1 fixtures.

The module has no network, key, clock, or storage dependencies. Production
implementations must replace FixtureVerifier and JournalStore with a PCP
verifier and an atomic, consensus-backed journal respectively.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
from hashlib import sha256
import json
import re
from threading import RLock
from typing import Any, Callable, Iterable


MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_BODY_BYTES = 65_536
MOVES = ("delegate", "handoff", "approve", "fail", "retry", "cancel", "resume")
STATES = ("void", "running", "awaiting_approve", "paused", "failed", "cancelled")
PCP_PRINCIPAL = re.compile(r"^urn:pcp:principal:[A-Za-z0-9._~-]{1,220}$")
RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$"
)
INVALID_PROOF_CODES = {
    "invalid_proof",
    "unsigned",
    "unknown_key",
    "unknown_issuer",
    "bad_signature",
    "proof_signer_mismatch",
    "proof_key_mismatch",
    "proof_purpose_mismatch",
    "proof_envelope_mismatch",
    "carrier_is_not_authority",
    "identity_collapse",
}
AUTHORITY_CODES = {
    "grant_not_found",
    "expired",
    "revoked",
    "scope_mismatch",
    "budget_exhausted",
    "unavailable",
}


class JournalCorrupt(ValueError):
    """Raised when durable records cannot deterministically replay."""


class AppendRejected(RuntimeError):
    """Raised when an append loses writer authority or its compare-and-set."""


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON member: {key}")
        value[key] = item
    return value


def parse_candidate(text: str) -> Any:
    """Parse JSON while rejecting duplicate object members."""

    if not isinstance(text, str):
        raise ValueError("candidate body must be UTF-8 text")
    try:
        body_size = len(text.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ValueError("candidate body is not valid UTF-8") from exc
    if body_size > MAX_BODY_BYTES:
        raise ValueError("candidate body exceeds 64 KiB")
    return json.loads(text, object_pairs_hook=_pairs_without_duplicates)


def canonical_json(value: Any) -> str:
    """Stable fixture encoding; live signature canonicalization belongs to PCP."""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def pcp_idempotency_key(thread: str, envelope_id: str) -> str:
    """Derive the PCP key from JCS of the exact two-field identity object."""

    if not _bounded_string(thread) or not _bounded_string(envelope_id):
        raise ValueError("PCP idempotency identity is invalid")
    identity = canonical_json({"envelope_id": envelope_id, "thread": thread})
    return f"legatus:sha256:{sha256(identity.encode('utf-8')).hexdigest()}"


def _safe_int(value: Any, *, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= MAX_SAFE_INTEGER


def _bounded_string(value: Any, maximum: int = 256) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= maximum
        and all(ord(char) >= 32 and ord(char) != 127 for char in value)
    )


def _principal(value: Any) -> bool:
    return isinstance(value, str) and len(value) <= 256 and PCP_PRINCIPAL.fullmatch(value) is not None


def _rfc3339(value: Any) -> bool:
    if not isinstance(value, str) or not 0 < len(value) <= 64 or RFC3339.fullmatch(value) is None:
        return False
    normalized = value.upper().replace("Z", "+00:00")
    try:
        datetime.fromisoformat(normalized)
    except ValueError:
        return False
    return True


def _error(
    code: str,
    *,
    retriable: bool = False,
    envelope_id: str | None = None,
    thread: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "legatus": 0,
        "kind": "error",
        "code": code,
        "retriable": retriable,
    }
    if envelope_id:
        result["envelope_id"] = envelope_id
    if thread:
        result["thread"] = thread
    return result


def _pcp_result(code: str, envelope: dict[str, Any], retriable: bool) -> dict[str, Any]:
    return {
        "legatus": 0,
        "kind": "pcp_result",
        "status": "deny",
        "code": code,
        "retriable": retriable,
        "envelope_id": envelope["id"],
        "thread": envelope["thread"],
    }


def _validate_gate(payload: dict[str, Any]) -> bool:
    gate = payload.get("gate", False)
    if type(gate) is not bool:
        return False
    if gate:
        return _principal(payload.get("approver"))
    return "approver" not in payload


def validate_envelope(value: Any) -> str | None:
    """Return a first structural/type error code, or None."""

    if not isinstance(value, dict):
        return "NOT_A_SUBMIT"
    if "legatus" not in value:
        return "NOT_A_SUBMIT"

    required = {"legatus", "id", "thread", "type", "parents", "clock", "signer", "payload", "sig"}
    if set(value) != required:
        if "sig" not in value and set(value) == required - {"sig"}:
            return "LEGATUS_E_SIG"
        return "LEGATUS_E_SCHEMA"
    if value["legatus"] != 0:
        return "LEGATUS_E_SCHEMA"
    if not _bounded_string(value["id"]) or not _bounded_string(value["thread"]):
        return "LEGATUS_E_SCHEMA"
    if not isinstance(value["type"], str):
        return "LEGATUS_E_SCHEMA"

    parents = value["parents"]
    if (
        not isinstance(parents, list)
        or len(parents) > 32
        or any(not _bounded_string(parent) for parent in parents)
        or len(set(parents)) != len(parents)
    ):
        return "LEGATUS_E_SCHEMA"

    clock = value["clock"]
    if not isinstance(clock, dict) or not {"seq", "now"} <= set(clock) <= {"seq", "now", "ts"}:
        return "LEGATUS_E_SCHEMA"
    if not _safe_int(clock["seq"], minimum=1) or not _safe_int(clock["now"]):
        return "LEGATUS_E_SCHEMA"
    if "ts" in clock and not _rfc3339(clock["ts"]):
        return "LEGATUS_E_SCHEMA"

    payload = value["payload"]
    if not isinstance(payload, dict):
        return "LEGATUS_E_SCHEMA"
    if value["type"] not in MOVES:
        return "LEGATUS_E_UNKNOWN_TYPE"
    if not _principal(value["signer"]):
        return "LEGATUS_E_SIG"
    if not isinstance(value["sig"], str) or not 0 < len(value["sig"]) <= 4096:
        return "LEGATUS_E_SIG"
    move = value["type"]
    allowed: dict[str, set[str]] = {
        "delegate": {"assignee", "task_ref", "gate", "approver", "deadline_now"},
        "handoff": {"to", "gate", "approver", "deadline_now"},
        "approve": {"of"},
        "fail": {"of", "code", "note"},
        "retry": {"of", "assignee", "gate", "approver", "deadline_now"},
        "cancel": {"of", "code", "note"},
        "resume": {"of", "gate", "approver", "deadline_now"},
    }
    if not set(payload) <= allowed[move]:
        return "LEGATUS_E_SCHEMA"

    required_payload: dict[str, set[str]] = {
        "delegate": {"assignee", "task_ref"},
        "handoff": {"to"},
        "approve": {"of"},
        "fail": {"code"},
        "retry": {"of"},
        "cancel": {"code"},
        "resume": set(),
    }
    if not required_payload[move] <= set(payload):
        return "LEGATUS_E_SCHEMA"

    for name in ("assignee", "to", "approver"):
        if name in payload and not _principal(payload[name]):
            return "LEGATUS_E_SCHEMA"
    for name in ("task_ref", "of"):
        if name in payload and not _bounded_string(payload[name]):
            return "LEGATUS_E_SCHEMA"
    if "note" in payload and (
        not isinstance(payload["note"], str)
        or len(payload["note"]) > 1024
        or "\x00" in payload["note"]
    ):
        return "LEGATUS_E_SCHEMA"
    if "deadline_now" in payload and not _safe_int(payload["deadline_now"]):
        return "LEGATUS_E_SCHEMA"
    if move in {"delegate", "handoff", "retry", "resume"} and not _validate_gate(payload):
        return "LEGATUS_E_SCHEMA"
    if move == "fail" and payload["code"] not in {"FAIL_TIMEOUT", "FAIL_REFUSED", "FAIL_FAULT", "FAIL_OTHER"}:
        return "LEGATUS_E_SCHEMA"
    if move == "cancel" and payload["code"] not in {"CANCEL_STOP", "CANCEL_SUPERSEDED", "CANCEL_OTHER"}:
        return "LEGATUS_E_SCHEMA"
    return None


@dataclass
class Snapshot:
    thread: str
    state: str = "void"
    principal: str | None = None
    floor: str | None = None
    pending: dict[str, Any] | None = None
    seq: int = 0
    now: int = 0
    deadline_now: int | None = None
    last_id: str | None = None
    last_assignee: str | None = None
    previous_floors: set[str] = field(default_factory=set)

    def public(self) -> dict[str, Any]:
        return {
            "thread": self.thread,
            "state": self.state,
            "principal": self.principal,
            "floor": self.floor,
            "pending": self.pending["id"] if self.pending else None,
            "seq": self.seq,
            "now": self.now,
            "deadline_now": self.deadline_now,
        }


class JournalStore:
    """In-memory atomic journal used only by tests and examples.

    A production store must place the same compare-and-set behind a durable
    single-writer lease or consensus group.
    """

    def __init__(
        self,
        records: Iterable[dict[str, Any]] = (),
        *,
        writer_id: str = "writer-1",
        writer_epoch: int = 1,
    ) -> None:
        if not _bounded_string(writer_id, 128) or not _safe_int(writer_epoch, minimum=1):
            raise ValueError("invalid writer lease")
        self.records = deepcopy(list(records))
        self.writer_id = writer_id
        self.writer_epoch = writer_epoch
        self._lock = RLock()

    def acquire_writer(self, writer_id: str, writer_epoch: int) -> None:
        with self._lock:
            if not _bounded_string(writer_id, 128) or not _safe_int(writer_epoch, minimum=1):
                raise ValueError("invalid writer lease")
            if writer_epoch <= self.writer_epoch:
                raise AppendRejected("writer epoch must increase")
            self.writer_id = writer_id
            self.writer_epoch = writer_epoch

    def append(
        self,
        record: dict[str, Any],
        *,
        writer_id: str,
        writer_epoch: int,
        expected_position: int,
    ) -> dict[str, Any]:
        with self._lock:
            if writer_id != self.writer_id or writer_epoch != self.writer_epoch:
                raise AppendRejected("writer lease is stale")
            if expected_position != len(self.records) + 1:
                raise AppendRejected("journal compare-and-set failed")
            if not _safe_int(expected_position, minimum=1):
                raise AppendRejected("journal position exhausted")
            if self.records and self.records[-1].get("writer_epoch", 0) > writer_epoch:
                raise AppendRejected("writer epoch precedes the journal")
            stored = deepcopy(record)
            stored["position"] = expected_position
            stored["writer_epoch"] = writer_epoch
            self.records.append(stored)
            return deepcopy(stored)


class FixtureVerifier:
    """Deterministic verifier for synthetic fixtures; it performs no crypto."""

    def __init__(
        self,
        disposition: str = "allow",
        *,
        retriable: bool = False,
        finalize_available: bool = True,
    ) -> None:
        self.disposition = disposition
        self.retriable = retriable
        self.finalize_available = finalize_available
        self.requests: list[dict[str, Any]] = []
        self.finalizations: list[dict[str, Any]] = []
        self.reservations: dict[str, dict[str, Any]] = {}
        self.finalized: dict[str, dict[str, Any]] = {}

    def __call__(self, request: dict[str, Any]) -> dict[str, Any]:
        self.requests.append(deepcopy(request))
        if self.disposition == "allow" and request["proof"] == "SIG_PENDING":
            authorization_id = f"fixture-authorization:{request['envelope']['id']}"
            reservation = {
                "envelope_id": request["envelope"]["id"],
                "thread": request["envelope"]["thread"],
                "idempotency_key": pcp_idempotency_key(
                    request["envelope"]["thread"],
                    request["envelope"]["id"],
                ),
                "request_fingerprint": canonical_json(request),
            }
            if authorization_id in self.reservations and self.reservations[authorization_id] != reservation:
                return {
                    "profile": "pcp-legatus-v1",
                    "status": "deny",
                    "code": "unavailable",
                    "retriable": True,
                }
            self.reservations[authorization_id] = reservation
            return {
                "profile": "pcp-legatus-v1",
                "status": "allow",
                "authorization_id": authorization_id,
            }
        code = self.disposition if self.disposition != "allow" else "invalid_proof"
        return {
            "profile": "pcp-legatus-v1",
            "status": "deny",
            "code": code,
            "retriable": self.retriable,
        }

    def finalize(self, request: dict[str, Any]) -> dict[str, Any]:
        self.finalizations.append(deepcopy(request))
        if not self.finalize_available:
            raise RuntimeError("fixture finalizer unavailable")
        reservation = self.reservations.get(request.get("authorization_id"))
        if reservation is None or (
            request.get("envelope_id") != reservation["envelope_id"]
            or request.get("thread") != reservation["thread"]
            or pcp_idempotency_key(request.get("thread"), request.get("envelope_id"))
            != reservation["idempotency_key"]
            or request.get("outcome") == "commit" and not _safe_int(request.get("journal_position"), minimum=1)
            or request.get("outcome") == "release" and request.get("journal_position") is not None
            or request.get("outcome") not in {"commit", "release"}
        ):
            raise RuntimeError("fixture finalization does not match its reservation")
        prior = self.finalized.get(request["authorization_id"])
        if prior is not None and prior != request:
            raise RuntimeError("fixture authorization has a conflicting final outcome")
        self.finalized[request["authorization_id"]] = deepcopy(request)
        return {
            "profile": "pcp-legatus-v1",
            "status": "finalized",
            "authorization_id": request["authorization_id"],
            "outcome": request["outcome"],
        }


Verifier = Callable[[dict[str, Any]], dict[str, Any]]
Finalizer = Callable[[dict[str, Any]], dict[str, Any]]


def _valid_verifier_result(result: Any) -> bool:
    if not isinstance(result, dict) or result.get("profile") != "pcp-legatus-v1":
        return False
    if result.get("status") == "allow":
        return set(result) == {"profile", "status", "authorization_id"} and _bounded_string(
            result.get("authorization_id")
        )
    if result.get("status") == "deny":
        return (
            set(result) == {"profile", "status", "code", "retriable"}
            and result.get("code") in INVALID_PROOF_CODES | AUTHORITY_CODES
            and type(result.get("retriable")) is bool
            and result["retriable"] is (result["code"] == "unavailable")
        )
    return False


def _valid_finalize_result(result: Any, request: dict[str, Any]) -> bool:
    return (
        isinstance(result, dict)
        and set(result) == {"profile", "status", "authorization_id", "outcome"}
        and result.get("profile") == "pcp-legatus-v1"
        and result.get("status") == "finalized"
        and result.get("authorization_id") == request["authorization_id"]
        and result.get("outcome") == request["outcome"]
    )


class Runtime:
    """Reference state machine with replayable timeout records and fencing."""

    def __init__(
        self,
        store: JournalStore | None = None,
        *,
        writer_id: str = "writer-1",
        writer_epoch: int = 1,
        verifier: Verifier | None = None,
        finalizer: Finalizer | None = None,
    ) -> None:
        self.store = store or JournalStore(writer_id=writer_id, writer_epoch=writer_epoch)
        self.writer_id = writer_id
        self.writer_epoch = writer_epoch
        self.verifier = verifier or FixtureVerifier()
        inherited_finalizer = getattr(self.verifier, "finalize", None)
        self.finalizer = finalizer if finalizer is not None else inherited_finalizer
        self._lock = RLock()
        self.threads: dict[str, Snapshot] = {}
        self.envelopes: dict[str, dict[str, Any]] = {}
        self.envelope_threads: dict[str, str] = {}
        self.fingerprints: dict[str, str] = {}
        self.authorization_ids: dict[str, str] = {}
        self.acks: dict[str, dict[str, Any]] = {}
        self.pending_pcp_handoffs: dict[str, dict[str, Any]] = {}
        self.ambiguous_authorizations: dict[str, dict[str, Any]] = {}
        self._known_position = 0
        self._rebuild()

    def _writer_error(self) -> dict[str, Any] | None:
        if self.writer_id != self.store.writer_id or self.writer_epoch != self.store.writer_epoch:
            return _error("LEGATUS_E_WRITER_UNAVAILABLE", retriable=True)
        return None

    def _snapshot(self, thread: str) -> Snapshot:
        return self.threads.get(thread, Snapshot(thread=thread))

    def _check_causality_and_clock(self, envelope: dict[str, Any], state: Snapshot) -> str | None:
        parents = envelope["parents"]
        for parent in parents:
            if parent in self.envelope_threads and self.envelope_threads[parent] != envelope["thread"]:
                return "LEGATUS_E_THREAD_MISMATCH"
        if state.seq == 0:
            if parents:
                return "LEGATUS_E_CAUSALITY"
        else:
            if not parents:
                return "LEGATUS_E_MISSING_PARENT"
            if any(parent not in self.envelopes for parent in parents) or state.last_id not in parents:
                return "LEGATUS_E_CAUSALITY"
        if envelope["clock"]["seq"] != state.seq + 1 or envelope["clock"]["now"] < state.now:
            return "LEGATUS_E_CLOCK_SKEW"
        deadline = envelope["payload"].get("deadline_now")
        if deadline is not None and deadline < envelope["clock"]["now"]:
            return "LEGATUS_E_CLOCK_SKEW"
        return None

    def _verify(self, envelope: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
        request = {
            "profile": "pcp-legatus-v1",
            "signer_id": envelope["signer"],
            "purpose": f"legatus.{envelope['type']}",
            "envelope": deepcopy(envelope),
            "proof": envelope["sig"],
        }
        try:
            result = self.verifier(request)
        except Exception:
            return None, _pcp_result("unavailable", envelope, True)
        if not _valid_verifier_result(result):
            return None, _pcp_result("unavailable", envelope, True)
        if result["status"] == "allow":
            return result["authorization_id"], None
        code = result.get("code")
        if code in INVALID_PROOF_CODES:
            return None, _error("LEGATUS_E_SIG", envelope_id=envelope["id"], thread=envelope["thread"])
        if code in AUTHORITY_CODES:
            return None, _pcp_result(code, envelope, bool(result.get("retriable", False)))
        return None, _pcp_result("unavailable", envelope, True)

    @staticmethod
    def _finalize_request(
        authorization_id: str,
        envelope: dict[str, Any],
        outcome: str,
        journal_position: int | None,
    ) -> dict[str, Any]:
        return {
            "profile": "pcp-legatus-v1",
            "authorization_id": authorization_id,
            "outcome": outcome,
            "envelope_id": envelope["id"],
            "thread": envelope["thread"],
            "journal_position": journal_position,
        }

    def _send_finalization(
        self,
        authorization_id: str,
        envelope: dict[str, Any],
        outcome: str,
        journal_position: int | None,
    ) -> bool:
        request = self._finalize_request(authorization_id, envelope, outcome, journal_position)
        return self._deliver_finalization(request)

    def _deliver_finalization(self, request: dict[str, Any]) -> bool:
        try:
            result = self.finalizer(request) if self.finalizer is not None else None
        except Exception:
            result = None
        if _valid_finalize_result(result, request):
            self.pending_pcp_handoffs.pop(request["authorization_id"], None)
            return True
        self.pending_pcp_handoffs[request["authorization_id"]] = deepcopy(request)
        return False

    def reconcile_pcp(self) -> list[dict[str, Any]]:
        """Retry idempotent PCP handoffs for this observed journal prefix."""

        with self._lock:
            requests = {
                authorization_id: deepcopy(request)
                for authorization_id, request in self.pending_pcp_handoffs.items()
            }
            for record in self.store.records[:self._known_position]:
                if record["kind"] != "envelope":
                    continue
                envelope = record["envelope"]
                requests[record["authorization_id"]] = self._finalize_request(
                    record["authorization_id"],
                    envelope,
                    "commit",
                    record["position"],
                )

            results: list[dict[str, Any]] = []
            for request in requests.values():
                finalized = self._deliver_finalization(request)
                envelope_id = request["envelope_id"]
                if request["outcome"] == "commit" and envelope_id in self.acks:
                    self.acks[envelope_id]["authorization_state"] = (
                        "committed" if finalized else "reconciliation_required"
                    )
                results.append({
                    "authorization_id": request["authorization_id"],
                    "envelope_id": envelope_id,
                    "outcome": request["outcome"],
                    "finalized": finalized,
                })
            return results

    def reconcile_ambiguous_pcp(self) -> list[dict[str, Any]]:
        """Resolve append ambiguity against a fenced, current journal view.

        An exact journaled envelope commits its reservation. A candidate proven
        absent from the locked journal releases it. Conflicting authorization
        identity remains pending for operator or PCP adapter reconciliation.
        """

        with self._lock:
            if self.writer_id != self.store.writer_id or self.writer_epoch != self.store.writer_epoch:
                return [
                    {
                        "authorization_id": authorization_id,
                        "envelope_id": envelope["id"],
                        "outcome": "unresolved",
                        "finalized": False,
                        "reason": "writer_unavailable",
                    }
                    for authorization_id, envelope in self.ambiguous_authorizations.items()
                ]

            with self.store._lock:
                current = Runtime(
                    self.store,
                    writer_id=self.writer_id,
                    writer_epoch=self.writer_epoch,
                    verifier=self.verifier,
                    finalizer=self.finalizer,
                )
                records_by_envelope = {
                    record["envelope"]["id"]: record
                    for record in self.store.records
                    if record["kind"] == "envelope"
                }
                authorization_owners = {
                    record["authorization_id"]: record["envelope"]["id"]
                    for record in self.store.records
                    if record["kind"] == "envelope"
                }
                results: list[dict[str, Any]] = []
                for authorization_id, envelope in list(self.ambiguous_authorizations.items()):
                    committed = current.envelopes.get(envelope["id"])
                    if committed is not None and canonical_json(committed) == canonical_json(envelope):
                        record = records_by_envelope[envelope["id"]]
                        if record["authorization_id"] != authorization_id:
                            results.append({
                                "authorization_id": authorization_id,
                                "envelope_id": envelope["id"],
                                "outcome": "unresolved",
                                "finalized": False,
                                "reason": "authorization_mismatch",
                            })
                            continue
                        outcome = "commit"
                        journal_position: int | None = record["position"]
                    elif authorization_id in authorization_owners:
                        results.append({
                            "authorization_id": authorization_id,
                            "envelope_id": envelope["id"],
                            "outcome": "unresolved",
                            "finalized": False,
                            "reason": "authorization_collision",
                        })
                        continue
                    else:
                        outcome = "release"
                        journal_position = None

                    finalized = self._send_finalization(
                        authorization_id,
                        envelope,
                        outcome,
                        journal_position,
                    )
                    if finalized:
                        self.ambiguous_authorizations.pop(authorization_id, None)
                    results.append({
                        "authorization_id": authorization_id,
                        "envelope_id": envelope["id"],
                        "outcome": outcome,
                        "finalized": finalized,
                    })
                return results

    def _check_signer_and_transition(self, envelope: dict[str, Any], state: Snapshot) -> str | None:
        move = envelope["type"]
        signer = envelope["signer"]
        payload = envelope["payload"]

        if state.state == "cancelled":
            return "LEGATUS_E_ALREADY_TERMINAL"

        if state.state != "void":
            allowed = False
            if move == "approve":
                allowed = bool(state.pending and signer == state.pending["payload"].get("approver"))
                if not allowed:
                    return "LEGATUS_E_NOT_APPROVER"
            elif move in {"fail", "cancel"}:
                allowed = signer in {state.floor, state.principal}
            elif move == "retry":
                allowed = signer == state.principal
            else:
                allowed = signer == state.floor
            if not allowed:
                if signer in state.previous_floors:
                    return "LEGATUS_E_STALE_FLOOR"
                return "LEGATUS_E_NO_FLOOR"

        current = state.state
        if current == "void":
            return None if move == "delegate" else "LEGATUS_E_ILLEGAL_TRANSITION"
        if current == "running":
            return None if move in {"handoff", "fail", "cancel"} else "LEGATUS_E_ILLEGAL_TRANSITION"
        if current == "awaiting_approve":
            if move not in {"approve", "fail", "cancel"}:
                return "LEGATUS_E_GATE_PENDING"
            if move == "approve" and payload["of"] != state.pending["id"]:
                return "LEGATUS_E_ILLEGAL_TRANSITION"
            return None
        if current == "paused":
            if move not in {"resume", "fail", "cancel"}:
                return "LEGATUS_E_ILLEGAL_TRANSITION"
            if move == "resume" and state.pending and payload.get("gate", False):
                return "LEGATUS_E_GATE_PENDING"
            return None
        if current == "failed":
            if move == "retry":
                return None if payload["of"] == state.last_id else "LEGATUS_E_ILLEGAL_TRANSITION"
            return None if move == "cancel" else "LEGATUS_E_ILLEGAL_TRANSITION"
        raise AssertionError(f"unknown state: {current}")

    @staticmethod
    def _apply_envelope(state: Snapshot, envelope: dict[str, Any]) -> Snapshot:
        result = deepcopy(state)
        move = envelope["type"]
        payload = envelope["payload"]
        old_pending = deepcopy(result.pending)
        result.seq = envelope["clock"]["seq"]
        result.now = max(result.now, envelope["clock"]["now"])
        result.last_id = envelope["id"]

        if move == "delegate":
            result.principal = envelope["signer"]
            result.floor = payload["assignee"] if not payload.get("gate", False) else envelope["signer"]
            result.last_assignee = payload["assignee"]
            result.pending = deepcopy(envelope) if payload.get("gate", False) else None
            result.state = "awaiting_approve" if result.pending else "running"
            result.deadline_now = payload.get("deadline_now")
        elif move == "handoff":
            if payload.get("gate", False):
                result.pending = deepcopy(envelope)
                result.state = "awaiting_approve"
            else:
                if result.floor:
                    result.previous_floors.add(result.floor)
                result.floor = payload["to"]
                result.pending = None
                result.state = "running"
            result.deadline_now = payload.get("deadline_now")
        elif move == "approve":
            pending = old_pending
            pending_move = pending["type"]
            if pending_move == "delegate":
                result.floor = pending["payload"]["assignee"]
            elif pending_move == "handoff":
                if result.floor:
                    result.previous_floors.add(result.floor)
                result.floor = pending["payload"]["to"]
            elif pending_move == "retry":
                result.floor = pending["payload"].get("assignee", result.last_assignee)
            result.pending = None
            result.state = "running"
        elif move == "fail":
            result.pending = None
            result.state = "failed"
            result.deadline_now = None
        elif move == "retry":
            assignee = payload.get("assignee", result.last_assignee)
            result.last_assignee = assignee
            result.pending = deepcopy(envelope) if payload.get("gate", False) else None
            result.floor = assignee if not result.pending else result.floor
            result.state = "awaiting_approve" if result.pending else "running"
            result.deadline_now = payload.get("deadline_now")
        elif move == "cancel":
            result.pending = None
            result.floor = None
            result.state = "cancelled"
            result.deadline_now = None
        elif move == "resume":
            if old_pending:
                result.pending = old_pending
                result.state = "awaiting_approve"
            elif payload.get("gate", False):
                result.pending = deepcopy(envelope)
                result.state = "awaiting_approve"
            else:
                result.pending = None
                result.state = "running"
            result.deadline_now = payload.get("deadline_now")
        return result

    @staticmethod
    def _apply_timeout(state: Snapshot, record: dict[str, Any]) -> Snapshot:
        if state.state not in {"running", "awaiting_approve"}:
            raise JournalCorrupt("timeout record follows a state that cannot time out")
        if state.deadline_now is None or record["deadline_now"] != state.deadline_now:
            raise JournalCorrupt("timeout record does not match the active deadline")
        if record["now"] <= state.deadline_now or record["after_seq"] != state.seq:
            raise JournalCorrupt("timeout record has an invalid clock or sequence")
        pending = state.pending["id"] if state.pending else None
        if record["pending"] != pending:
            raise JournalCorrupt("timeout record does not preserve pending")
        result = deepcopy(state)
        result.state = "paused"
        result.now = max(result.now, record["now"])
        return result

    def _rebuild(self) -> None:
        last_epoch = 0
        for expected_position, record in enumerate(self.store.records, 1):
            if not isinstance(record, dict):
                raise JournalCorrupt("journal record is not an object")
            if record.get("position") != expected_position:
                raise JournalCorrupt("journal positions are not contiguous")
            epoch = record.get("writer_epoch")
            if not _safe_int(epoch, minimum=1) or epoch < last_epoch:
                raise JournalCorrupt("writer epochs are not monotonic")
            last_epoch = epoch
            kind = record.get("kind")
            if kind == "timeout":
                if set(record) != {
                    "legatus", "kind", "position", "writer_epoch", "thread",
                    "after_seq", "now", "deadline_now", "pending",
                }:
                    raise JournalCorrupt("timeout record has an invalid shape")
                if record.get("legatus") != 0 or not _bounded_string(record.get("thread")):
                    raise JournalCorrupt("timeout record has invalid identifiers")
                if not _safe_int(record.get("after_seq"), minimum=1) or not _safe_int(record.get("now")):
                    raise JournalCorrupt("timeout record has invalid clock values")
                if not _safe_int(record.get("deadline_now")):
                    raise JournalCorrupt("timeout record has invalid deadline")
                if record.get("pending") is not None and not _bounded_string(record.get("pending")):
                    raise JournalCorrupt("timeout record has invalid pending identifier")
                thread = record.get("thread")
                state = self.threads.get(thread)
                if state is None:
                    raise JournalCorrupt("timeout record has no thread")
                self.threads[thread] = self._apply_timeout(state, record)
                continue
            if (
                kind != "envelope"
                or set(record) != {
                    "legatus", "kind", "position", "writer_epoch", "authorization_id", "envelope"
                }
                or record.get("legatus") != 0
                or not _bounded_string(record.get("authorization_id"))
                or not isinstance(record.get("envelope"), dict)
            ):
                raise JournalCorrupt("unknown journal record")
            envelope = record["envelope"]
            if validate_envelope(envelope) is not None:
                raise JournalCorrupt("journal contains an invalid envelope")
            if envelope["id"] in self.envelopes:
                raise JournalCorrupt("journal contains a duplicate envelope id")
            if record["authorization_id"] in self.authorization_ids.values():
                raise JournalCorrupt("journal contains a duplicate authorization id")
            state = self._snapshot(envelope["thread"])
            failure = self._check_causality_and_clock(envelope, state) or self._check_signer_and_transition(envelope, state)
            if failure:
                raise JournalCorrupt(f"envelope replay failed: {failure}")
            next_state = self._apply_envelope(state, envelope)
            self.threads[envelope["thread"]] = next_state
            self.envelopes[envelope["id"]] = deepcopy(envelope)
            self.envelope_threads[envelope["id"]] = envelope["thread"]
            self.fingerprints[envelope["id"]] = canonical_json(envelope)
            self.authorization_ids[envelope["id"]] = record["authorization_id"]
            self.acks[envelope["id"]] = self._ack(
                envelope,
                next_state,
                expected_position,
                "committed",
                record["authorization_id"],
                "reconciliation_required",
            )
            self._known_position = expected_position
        if self.store.records:
            self._known_position = len(self.store.records)
        if self.store.writer_epoch < last_epoch:
            raise JournalCorrupt("current writer epoch precedes the journal")

    @staticmethod
    def _ack(
        envelope: dict[str, Any],
        state: Snapshot,
        position: int,
        outcome: str,
        authorization_id: str,
        authorization_state: str,
    ) -> dict[str, Any]:
        return {
            "legatus": 0,
            "kind": "ack",
            "outcome": outcome,
            "envelope_id": envelope["id"],
            "thread": envelope["thread"],
            "seq": state.seq,
            "journal_position": position,
            "authorization_id": authorization_id,
            "authorization_state": authorization_state,
            "state": state.state,
            "floor": state.floor,
            "pending": state.pending["id"] if state.pending else None,
        }

    def advance_now(
        self,
        thread: str,
        now: int,
        *,
        writer_id: str | None = None,
        writer_epoch: int | None = None,
    ) -> dict[str, Any] | None:
        with self._lock:
            writer_id = self.writer_id if writer_id is None else writer_id
            writer_epoch = self.writer_epoch if writer_epoch is None else writer_epoch
            if not _bounded_string(thread):
                return _error("LEGATUS_E_SCHEMA")
            if writer_id != self.store.writer_id or writer_epoch != self.store.writer_epoch:
                return _error("LEGATUS_E_WRITER_UNAVAILABLE", retriable=True, thread=thread)
            if not _safe_int(now):
                return _error("LEGATUS_E_SCHEMA", thread=thread)
            state = self.threads.get(thread)
            if state is None or state.state not in {"running", "awaiting_approve"}:
                return None
            if state.deadline_now is None or now <= state.deadline_now:
                return None
            record = {
                "legatus": 0,
                "kind": "timeout",
                "thread": thread,
                "after_seq": state.seq,
                "now": now,
                "deadline_now": state.deadline_now,
                "pending": state.pending["id"] if state.pending else None,
            }
            try:
                stored = self.store.append(
                    record,
                    writer_id=writer_id,
                    writer_epoch=writer_epoch,
                    expected_position=self._known_position + 1,
                )
            except AppendRejected:
                return _error("LEGATUS_E_WRITER_UNAVAILABLE", retriable=True, thread=thread)
            self.threads[thread] = self._apply_timeout(state, stored)
            self._known_position = stored["position"]
            return deepcopy(stored)

    def submit(
        self,
        envelope: Any,
        *,
        runtime_now: int | None = None,
        writer_id: str | None = None,
        writer_epoch: int | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            writer_id = self.writer_id if writer_id is None else writer_id
            writer_epoch = self.writer_epoch if writer_epoch is None else writer_epoch
            if writer_id != self.store.writer_id or writer_epoch != self.store.writer_epoch:
                return _error("LEGATUS_E_WRITER_UNAVAILABLE", retriable=True)

            failure = validate_envelope(envelope)
            if failure:
                return _error(failure)

            envelope_id = envelope["id"]
            thread = envelope["thread"]
            if envelope_id in self.envelopes:
                if self.fingerprints[envelope_id] == canonical_json(envelope):
                    if runtime_now is not None:
                        if not _safe_int(runtime_now):
                            return _error("LEGATUS_E_SCHEMA", envelope_id=envelope_id, thread=thread)
                        timeout_result = self.advance_now(
                            thread,
                            runtime_now,
                            writer_id=writer_id,
                            writer_epoch=writer_epoch,
                        )
                        if timeout_result and timeout_result.get("kind") == "error":
                            return timeout_result
                    ack = deepcopy(self.acks[envelope_id])
                    ack["outcome"] = "duplicate"
                    authorization_id = ack["authorization_id"]
                    finalized = self._send_finalization(
                        authorization_id,
                        self.envelopes[envelope_id],
                        "commit",
                        ack["journal_position"],
                    )
                    ack["authorization_state"] = (
                        "committed" if finalized else "reconciliation_required"
                    )
                    self.acks[envelope_id]["authorization_state"] = ack["authorization_state"]
                    return ack
                return _error("LEGATUS_E_DUP_ID", envelope_id=envelope_id, thread=thread)

            if runtime_now is not None:
                if not _safe_int(runtime_now):
                    return _error("LEGATUS_E_SCHEMA", envelope_id=envelope_id, thread=thread)
                timeout_result = self.advance_now(
                    thread,
                    runtime_now,
                    writer_id=writer_id,
                    writer_epoch=writer_epoch,
                )
                if timeout_result and timeout_result.get("kind") == "error":
                    return timeout_result

            state = self._snapshot(thread)
            failure = self._check_causality_and_clock(envelope, state)
            if failure:
                return _error(failure, envelope_id=envelope_id, thread=thread)
            deadline = envelope["payload"].get("deadline_now")
            if runtime_now is not None and deadline is not None and deadline < runtime_now:
                return _error("LEGATUS_E_CLOCK_SKEW", envelope_id=envelope_id, thread=thread)
            authorization_id, verification = self._verify(envelope)
            if verification:
                return verification
            assert authorization_id is not None
            authorization_owner = next(
                (
                    committed_id
                    for committed_id, committed_authorization in self.authorization_ids.items()
                    if committed_authorization == authorization_id
                ),
                None,
            )
            ambiguous = self.ambiguous_authorizations.get(authorization_id)
            if (
                authorization_owner not in {None, envelope_id}
                or ambiguous is not None and ambiguous["id"] != envelope_id
            ):
                return _pcp_result("unavailable", envelope, True)
            failure = self._check_signer_and_transition(envelope, state)
            if failure:
                self._send_finalization(authorization_id, envelope, "release", None)
                return _error(failure, envelope_id=envelope_id, thread=thread)

            # A candidate clock becomes authoritative only after proof and floor
            # checks. This prevents a rejected outsider from forcing timeout.
            timeout_result = self.advance_now(
                thread,
                envelope["clock"]["now"],
                writer_id=writer_id,
                writer_epoch=writer_epoch,
            )
            if timeout_result and timeout_result.get("kind") == "error":
                self.ambiguous_authorizations[authorization_id] = deepcopy(envelope)
                return timeout_result
            if timeout_result is not None:
                state = self._snapshot(thread)
                failure = self._check_signer_and_transition(envelope, state)
                if failure:
                    self._send_finalization(authorization_id, envelope, "release", None)
                    return _error(failure, envelope_id=envelope_id, thread=thread)

            next_state = self._apply_envelope(state, envelope)
            record = {
                "legatus": 0,
                "kind": "envelope",
                "authorization_id": authorization_id,
                "envelope": deepcopy(envelope),
            }
            try:
                stored = self.store.append(
                    record,
                    writer_id=writer_id,
                    writer_epoch=writer_epoch,
                    expected_position=self._known_position + 1,
                )
            except AppendRejected:
                self.ambiguous_authorizations[authorization_id] = deepcopy(envelope)
                return _error("LEGATUS_E_WRITER_UNAVAILABLE", retriable=True, envelope_id=envelope_id, thread=thread)

            self.threads[thread] = next_state
            self.envelopes[envelope_id] = deepcopy(envelope)
            self.envelope_threads[envelope_id] = thread
            self.fingerprints[envelope_id] = canonical_json(envelope)
            self.authorization_ids[envelope_id] = authorization_id
            self.ambiguous_authorizations.pop(authorization_id, None)
            self._known_position = stored["position"]
            finalized = self._send_finalization(
                authorization_id,
                envelope,
                "commit",
                stored["position"],
            )
            ack = self._ack(
                envelope,
                next_state,
                stored["position"],
                "committed",
                authorization_id,
                "committed" if finalized else "reconciliation_required",
            )
            self.acks[envelope_id] = deepcopy(ack)
            return ack

    def recover(self, now_by_thread: dict[str, int] | None = None) -> "Runtime":
        recovered = Runtime(
            self.store,
            writer_id=self.writer_id,
            writer_epoch=self.writer_epoch,
            verifier=self.verifier,
            finalizer=self.finalizer,
        )
        for thread, now in sorted((now_by_thread or {}).items()):
            result = recovered.advance_now(thread, now)
            if result and result.get("kind") == "error":
                raise JournalCorrupt(result["code"])
        return recovered

    def export_transcript(
        self,
        thread: str,
        *,
        actions: Iterable[dict[str, Any]] = (),
        receipts: Iterable[dict[str, Any]] = (),
    ) -> dict[str, Any]:
        if thread not in self.threads:
            raise KeyError(thread)
        state = self.threads[thread]
        observed_records = self.store.records[:self._known_position]
        envelope_records = [
            record for record in observed_records
            if record["kind"] == "envelope" and record["envelope"]["thread"] == thread
        ]
        timeout_records = [
            record for record in observed_records
            if record["kind"] == "timeout" and record["thread"] == thread
        ]
        if len(timeout_records) > 4096:
            raise ValueError("transcript timeout-event limit exceeded")
        opening = envelope_records[0]["envelope"]
        links: list[dict[str, Any]] = [
            {"role": "request", "envelope": opening["id"], "task_ref": opening["payload"]["task_ref"]}
        ]
        for record in envelope_records:
            envelope = record["envelope"]
            links.append({
                "role": "move",
                "envelope": envelope["id"],
                "type": envelope["type"],
                "seq": envelope["clock"]["seq"],
                "signer": envelope["signer"],
                "authorization_id": record["authorization_id"],
            })
            if envelope["type"] == "approve":
                links.append({
                    "role": "approval",
                    "envelope": envelope["id"],
                    "of": envelope["payload"]["of"],
                    "approver": envelope["signer"],
                })

        known_envelopes = {record["envelope"]["id"] for record in envelope_records}
        known_actions: set[str] = set()
        for action in actions:
            if set(action) != {"ref", "after"} or action["after"] not in known_envelopes or not _bounded_string(action["ref"]):
                raise ValueError("invalid action reference")
            known_actions.add(action["ref"])
            links.append({"role": "action", **deepcopy(action)})
        for receipt in receipts:
            if (
                set(receipt) != {"ref", "after", "action"}
                or not _bounded_string(receipt.get("ref"))
                or receipt["after"] not in known_envelopes
            ):
                raise ValueError("invalid receipt reference")
            if receipt["action"] is not None and receipt["action"] not in known_actions:
                raise ValueError("receipt action is absent")
            links.append({"role": "receipt", **deepcopy(receipt)})
        if len(links) > 16384:
            raise ValueError("transcript link limit exceeded")

        stop = None
        if state.state == "cancelled":
            cancel = next(record["envelope"] for record in reversed(envelope_records) if record["envelope"]["type"] == "cancel")
            stop = {"envelope": cancel["id"], "code": cancel["payload"]["code"]}
        return {
            "legatus": 0,
            "kind": "transcript",
            "thread": thread,
            "seq_through": state.seq,
            "journal_through": max(record["position"] for record in envelope_records + timeout_records),
            "now": state.now,
            "state": state.state,
            "floor": state.floor,
            "principal": state.principal,
            "pending": state.pending["id"] if state.pending else None,
            "stop": stop,
            "clock_events": [
                {
                    "kind": "timeout",
                    "journal_position": record["position"],
                    "after_seq": record["after_seq"],
                    "now": record["now"],
                    "deadline_now": record["deadline_now"],
                }
                for record in timeout_records
            ],
            "links": links,
            "integrity": {"mode": "unsigned_fixture"},
        }


def make_envelope(
    envelope_id: str,
    thread: str,
    move: str,
    seq: int,
    now: int,
    signer: str,
    payload: dict[str, Any],
    *,
    parents: Iterable[str] = (),
    sig: str = "SIG_PENDING",
) -> dict[str, Any]:
    return {
        "legatus": 0,
        "id": envelope_id,
        "thread": thread,
        "type": move,
        "parents": list(parents),
        "clock": {"seq": seq, "now": now},
        "signer": signer,
        "payload": deepcopy(payload),
        "sig": sig,
    }
