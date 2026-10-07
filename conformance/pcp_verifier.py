"""Ed25519 proof adapter; PCP retains authority and reservation ownership.

Key resolution, grant authorization, and finalization are trusted deployment
callbacks. A verified signature alone never produces an allow decision.
"""

from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import dataclass
import json
from functools import lru_cache
from pathlib import Path
import re
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import rfc8785
from jsonschema import Draft202012Validator, FormatChecker

from .legatus import MOVES, PCP_PRINCIPAL, _valid_verifier_result, validate_envelope


PROFILE = "pcp-legatus-v1"
HEADER_FIELDS = {"context", "signer_id", "key_id", "grant_id", "purpose"}
REQUEST_FIELDS = {"profile", "signer_id", "purpose", "envelope", "proof"}
KEY_ID = re.compile(r"^urn:pcp:key:[A-Za-z0-9._~-]+$")
GRANT_ID = re.compile(r"^urn:pcp:grant:[A-Za-z0-9._~-]+$")


@lru_cache(maxsize=None)
def _validator(name: str) -> Draft202012Validator:
    path = Path(__file__).resolve().parents[1] / "schemas" / name
    return Draft202012Validator(json.loads(path.read_text()), format_checker=FormatChecker())


class InvalidProof(ValueError):
    def __init__(self, code: str = "invalid_proof"):
        self.code = code
        super().__init__(code)


def _deny(code: str) -> dict[str, Any]:
    return {"profile": PROFILE, "status": "deny", "code": code,
            "retriable": code == "unavailable"}


def _decode(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise InvalidProof()
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise InvalidProof()
    return raw


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidProof()
        result[key] = value
    return result


def decode_proof(compact: str) -> tuple[dict[str, Any], bytes]:
    try:
        if not isinstance(compact, str) or len(compact) > 4096:
            raise InvalidProof()
        prefix, encoded_header, encoded_signature = compact.split(".")
        if prefix != "pcp1":
            raise InvalidProof()
        raw_header = _decode(encoded_header)
        header = json.loads(raw_header.decode("utf-8"), object_pairs_hook=_pairs)
        if not isinstance(header, dict) or set(header) != HEADER_FIELDS:
            raise InvalidProof()
        if header["context"] != PROFILE:
            raise InvalidProof()
        if not isinstance(header["signer_id"], str) or not PCP_PRINCIPAL.fullmatch(header["signer_id"]):
            raise InvalidProof("carrier_is_not_authority")
        if not isinstance(header["key_id"], str) or not KEY_ID.fullmatch(header["key_id"]):
            raise InvalidProof()
        if not isinstance(header["grant_id"], str) or not GRANT_ID.fullmatch(header["grant_id"]):
            raise InvalidProof()
        if header["purpose"] not in {f"legatus.{move}" for move in MOVES}:
            raise InvalidProof()
        if rfc8785.dumps(header) != raw_header:
            raise InvalidProof()
        signature = _decode(encoded_signature)
        if len(signature) != 64:
            raise InvalidProof()
        return header, signature
    except InvalidProof:
        raise
    except (ValueError, TypeError, UnicodeError, rfc8785.CanonicalizationError) as exc:
        raise InvalidProof() from exc


def signing_object(header: dict[str, Any], envelope: dict[str, Any]) -> dict[str, Any]:
    """Exactly five protected fields plus the candidate with only sig removed."""
    unsigned = deepcopy(envelope)
    unsigned.pop("sig", None)
    return {**header, "envelope": unsigned}


@dataclass(frozen=True)
class TrustedKey:
    signer_id: str
    key_id: str
    public_key: Ed25519PublicKey


class PCPVerifier:
    """Verify proofs before invoking the trusted PCP authorization callback.

    resolve_key must authenticate key ownership independently of the candidate.
    authorize(request, protected) must validate the principal-signed grant,
    subject, configured audience, purpose, scope, time, revocation and budget,
    returning the strict PCP disposition and a live reservation on allow.
    finalize must use the same authenticated PCP integration and journal evidence.
    Exceptions and malformed callback results fail closed as unavailable.
    """

    def __init__(
        self,
        *,
        resolve_key: Callable[[str, str], TrustedKey | None],
        authorize: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
        finalize: Callable[[dict[str, Any]], dict[str, Any]],
    ):
        if not all(callable(callback) for callback in (resolve_key, authorize, finalize)):
            raise ValueError("trusted key, authority, and finalization callbacks are required")
        self.resolve_key = resolve_key
        self.authorize = authorize
        self._finalize = finalize

    def finalize(self, request: dict[str, Any]) -> dict[str, Any]:
        request = deepcopy(request)
        _validator("pcp-finalize-request.schema.json").validate(request)
        result = deepcopy(self._finalize(deepcopy(request)))
        _validator("pcp-finalize-result.schema.json").validate(result)
        if result["authorization_id"] != request["authorization_id"] or result["outcome"] != request["outcome"]:
            raise ValueError("PCP finalization result does not match its request")
        return result

    def __call__(self, request: dict[str, Any]) -> dict[str, Any]:
        try:
            # Snapshot caller-owned data before passing copies to external callbacks.
            request = deepcopy(request)
            if not isinstance(request, dict) or set(request) != REQUEST_FIELDS or request["profile"] != PROFILE:
                raise InvalidProof()
            if not _validator("pcp-verifier-request.schema.json").is_valid(request):
                raise InvalidProof()
            envelope = request["envelope"]
            if validate_envelope(envelope) is not None:
                raise InvalidProof()
            if request["proof"] != envelope["sig"]:
                raise InvalidProof("proof_envelope_mismatch")
            header, signature = decode_proof(request["proof"])
            if header["signer_id"] != envelope["signer"] or header["signer_id"] != request["signer_id"]:
                raise InvalidProof("proof_signer_mismatch")
            purpose = f"legatus.{envelope['type']}"
            if header["purpose"] != purpose or request["purpose"] != purpose:
                raise InvalidProof("proof_purpose_mismatch")
            key = self.resolve_key(header["signer_id"], header["key_id"])
            if key is None:
                raise InvalidProof("unknown_key")
            if not isinstance(key, TrustedKey) or not isinstance(key.public_key, Ed25519PublicKey):
                return _deny("unavailable")
            if key.signer_id != header["signer_id"]:
                raise InvalidProof("proof_signer_mismatch")
            if key.key_id != header["key_id"]:
                raise InvalidProof("proof_key_mismatch")
            try:
                signed_bytes = rfc8785.dumps(signing_object(header, envelope))
            except (ValueError, TypeError, rfc8785.CanonicalizationError) as exc:
                raise InvalidProof() from exc
            try:
                key.public_key.verify(signature, signed_bytes)
            except InvalidSignature as exc:
                raise InvalidProof("bad_signature") from exc
            result = self.authorize(deepcopy(request), deepcopy(header))
            valid = _valid_verifier_result(result) and _validator("pcp-verifier-result.schema.json").is_valid(result)
            return deepcopy(result) if valid else _deny("unavailable")
        except InvalidProof as exc:
            return _deny(exc.code)
        except Exception:
            return _deny("unavailable")
