import base64
from copy import deepcopy
import json
from pathlib import Path
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import rfc8785

from conformance.legatus import Runtime
from conformance.pcp_verifier import PCPVerifier, TrustedKey, decode_proof, signing_object


FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "pcp-ed25519.json").read_text())


def request(envelope):
    return {"profile": "pcp-legatus-v1", "signer_id": envelope["signer"],
            "purpose": "legatus." + envelope["type"], "envelope": deepcopy(envelope),
            "proof": envelope["sig"]}


def encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.envelope = deepcopy(FIXTURE["envelope"])
        self.header, _ = decode_proof(self.envelope["sig"])
        self.public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(FIXTURE["public_key"]))
        self.key = TrustedKey(self.header["signer_id"], self.header["key_id"], self.public)
        self.calls = []
        self.finalizations = []
        self.decision = {"profile": "pcp-legatus-v1", "status": "allow", "authorization_id": "reservation-1"}

        def authorize(candidate, protected):
            self.calls.append((deepcopy(candidate), deepcopy(protected)))
            return deepcopy(self.decision)

        def finalize(value):
            self.finalizations.append(deepcopy(value))
            return {"profile": "pcp-legatus-v1", "status": "finalized",
                    "authorization_id": value["authorization_id"], "outcome": value["outcome"]}

        self.verifier = PCPVerifier(resolve_key=lambda signer, key_id: self.key,
                                    authorize=authorize, finalize=finalize)

    def test_independent_node_signature_and_exact_unicode_jcs_bytes(self):
        self.assertEqual(rfc8785.dumps(signing_object(self.header, self.envelope)),
                         FIXTURE["canonical_bytes"].encode("utf-8"))
        runtime = Runtime(verifier=self.verifier)
        ack = runtime.submit(self.envelope)
        self.assertEqual(ack["outcome"], "committed")
        self.assertEqual(ack["authorization_state"], "committed")
        self.assertEqual(self.calls, [(request(self.envelope), self.header)])
        self.assertEqual(self.finalizations[0]["outcome"], "commit")
        self.assertEqual(runtime.submit(self.envelope)["outcome"], "duplicate")
        self.assertEqual(len(self.calls), 1)

    def test_runtime_requires_explicit_verifier_or_fixture_mode(self):
        with self.assertRaises(ValueError):
            Runtime()
        self.assertIsNotNone(Runtime(fixture_mode=True))

    def test_tampered_signed_fields_fail_before_authority_or_append(self):
        mutations = [lambda e: e.update(id="other"), lambda e: e.update(thread="other"),
                     lambda e: e["clock"].update(now=101),
                     lambda e: e["payload"].update(task_ref="different 😀"),
                     lambda e: e["payload"].update(assignee="urn:pcp:principal:other")]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                candidate = deepcopy(self.envelope)
                mutate(candidate)
                runtime = Runtime(verifier=self.verifier)
                self.assertEqual(runtime.submit(candidate)["code"], "LEGATUS_E_SIG")
                self.assertEqual(runtime.store.records, [])
        self.assertEqual(self.calls, [])

    def test_wrong_unknown_or_misbound_keys_fail_closed(self):
        choices = [None, TrustedKey(self.key.signer_id, self.key.key_id, Ed25519PrivateKey.generate().public_key()),
                   TrustedKey("urn:pcp:principal:other", self.key.key_id, self.public),
                   TrustedKey(self.key.signer_id, "urn:pcp:key:other", self.public)]
        for key in choices:
            with self.subTest(key=key):
                self.key = key
                self.assertEqual(Runtime(verifier=self.verifier).submit(self.envelope)["code"], "LEGATUS_E_SIG")
        self.assertEqual(self.calls, [])

    def test_proof_copy_signer_and_purpose_bindings(self):
        for field, value, code in [("proof", "other", "proof_envelope_mismatch"),
                                   ("signer_id", "urn:pcp:principal:other", "proof_signer_mismatch"),
                                   ("purpose", "legatus.cancel", "proof_purpose_mismatch")]:
            candidate = request(self.envelope)
            candidate[field] = value
            self.assertEqual(self.verifier(candidate)["code"], code)
        self.assertEqual(self.calls, [])

    def test_malformed_noncanonical_duplicate_and_algorithm_headers(self):
        headers = [json.dumps(self.header).encode(),
                   rfc8785.dumps({**self.header, "alg": "none"}),
                   rfc8785.dumps({**self.header, "context": "another-profile"}),
                   b'{"context":"pcp-legatus-v1","context":"pcp-legatus-v1"}']
        proofs = ["SIG_PENDING", "pcp2.a.b", "pcp1.a.b", "pcp1.."]
        signature = self.envelope["sig"].split(".")[2]
        proofs += ["pcp1." + encode(header) + "." + signature for header in headers]
        proofs += [self.envelope["sig"] + "=", "pcp1." + encode(rfc8785.dumps(self.header)) + "." + encode(b"short")]
        # The last base64url character has two unused bits. An alternate spelling
        # must be rejected even when it decodes to the same signature bytes.
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        last = alphabet[(alphabet.index(signature[-1]) // 16) * 16 + 1]
        proofs.append(self.envelope["sig"][:-1] + last)
        for proof in proofs:
            candidate = deepcopy(self.envelope)
            candidate["sig"] = proof
            self.assertEqual(Runtime(verifier=self.verifier).submit(candidate)["code"], "LEGATUS_E_SIG")
        self.assertEqual(self.calls, [])

    def test_valid_signature_does_not_bypass_authority_denials(self):
        for code in ("grant_not_found", "expired", "revoked", "scope_mismatch", "budget_exhausted", "unavailable"):
            self.decision = {"profile": "pcp-legatus-v1", "status": "deny", "code": code,
                             "retriable": code == "unavailable"}
            runtime = Runtime(verifier=self.verifier)
            result = runtime.submit(self.envelope)
            self.assertEqual(result["code"], code)
            self.assertEqual(result["retriable"], code == "unavailable")
            self.assertEqual(runtime.store.records, [])
        self.assertEqual(self.finalizations, [])

    def test_callback_outage_and_malformed_allow_fail_closed(self):
        self.verifier.resolve_key = lambda *_: (_ for _ in ()).throw(RuntimeError("offline"))
        self.assertEqual(self.verifier(request(self.envelope))["code"], "unavailable")
        self.verifier.resolve_key = lambda *_: self.key
        self.decision = {"profile": "pcp-legatus-v1", "status": "allow"}
        runtime = Runtime(verifier=self.verifier)
        self.assertEqual(runtime.submit(self.envelope)["code"], "unavailable")
        self.assertEqual(runtime.store.records, [])

    def test_signed_illegal_transition_releases_reservation(self):
        private = Ed25519PrivateKey.generate()
        self.key = TrustedKey(self.header["signer_id"], self.header["key_id"], private.public_key())
        candidate = deepcopy(self.envelope)
        candidate.update(type="handoff", payload={"to": "urn:pcp:principal:worker"})
        header = {**self.header, "purpose": "legatus.handoff"}
        candidate["sig"] = "pcp1." + encode(rfc8785.dumps(header)) + "." + encode(
            private.sign(rfc8785.dumps(signing_object(header, candidate))))
        runtime = Runtime(verifier=self.verifier)
        self.assertEqual(runtime.submit(candidate)["code"], "LEGATUS_E_ILLEGAL_TRANSITION")
        self.assertEqual(runtime.store.records, [])
        self.assertEqual(self.finalizations[0]["outcome"], "release")


if __name__ == "__main__":
    unittest.main()
