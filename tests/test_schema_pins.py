import hashlib
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker
from conformance.legatus import make_envelope


ROOT = Path(__file__).resolve().parents[1]


class SchemaPinTests(unittest.TestCase):
    def test_complete_pin_and_hashes_match(self):
        pin = json.loads((ROOT / "schemas" / "pcp-source.json").read_text())
        files = {p.name for p in (ROOT / "schemas").glob("pcp*.schema.json")}
        self.assertEqual(files, set(pin["files"]))
        for name, expected in pin["files"].items():
            with self.subTest(schema=name):
                data = (ROOT / "schemas" / name).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), expected)
                Draft202012Validator.check_schema(json.loads(data))

    def test_local_envelope_contract_remains_stricter_than_pcp_carrier(self):
        candidate = make_envelope("e1", "t1", "delegate", 1, 1,
                                  "urn:pcp:principal:owner",
                                  {"assignee": "urn:pcp:principal:worker", "task_ref": "task-1"})
        carrier = json.loads((ROOT / "schemas" / "pcp-verifier-request.schema.json").read_text())
        validator = Draft202012Validator(carrier, format_checker=FormatChecker())
        req = {"profile": "pcp-legatus-v1", "signer_id": candidate["signer"],
               "purpose": "legatus.delegate", "proof": candidate["sig"], "envelope": candidate}
        validator.validate(req)
        candidate["payload"]["unknown"] = True
        validator.validate(req)  # PCP carries payload; Legatus owns move validation.
        from conformance.legatus import validate_envelope
        self.assertEqual(validate_envelope(candidate), "LEGATUS_E_SCHEMA")


if __name__ == "__main__":
    unittest.main()
