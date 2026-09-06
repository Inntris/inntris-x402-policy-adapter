"""Boundary tests supplementing full real-bridge TypeScript regressions.

Presentation tests here are syntax/interface checks, not signature verification.
The TypeScript suite separately exercises genuinely signed default-bridge inputs.
"""

import base64
import hashlib
import json
import unittest
from types import SimpleNamespace

from presentation import strict_json, validate_presentation
from verify_ap2_structured import _check_time_claims


def encoded(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


def digest(disclosure):
    return base64.urlsafe_b64encode(hashlib.sha256(disclosure.encode()).digest()).decode().rstrip("=")


def presentation(payload, disclosures):
    header = {"alg": "ES256"}
    return SimpleNamespace(issuer_jwt=encoded(header) + "." + encoded(payload) + ".AA",
                           header=header, payload=payload, disclosures=disclosures)


class StrictJsonTests(unittest.TestCase):
    def test_duplicate_members(self):
        for value in ('{"a":1,"a":2}', '{"a":{"x":1,"x":2}}',
                      '{"a":1,"\\u0061":2}'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                strict_json(value)

    def test_unicode(self):
        for value in ('"\\ud800"', '"\\udfff"'):
            with self.subTest(value=value), self.assertRaises(UnicodeError):
                strict_json(value)
        self.assertEqual(strict_json('"café 水 \\ud83d\\ude00"'), "café 水 😀")

    def test_nonfinite(self):
        for value in ("NaN", "Infinity", "1e999"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                strict_json(value)


class TemporalTests(unittest.TestCase):
    def test_missing_optional_times(self):
        _check_time_claims([{}], 100, 0)

    def test_invalid_types(self):
        for claim in ("iat", "nbf", "exp"):
            for value in (None, True, "100", float("nan"), float("inf"), 2**53):
                with self.subTest(claim=claim, value=value), self.assertRaises(ValueError):
                    _check_time_claims([{claim: value}], 100, 0)

    def test_expiry_and_skew(self):
        for skew in (0, 5):
            with self.subTest(skew=skew), self.assertRaises(ValueError):
                _check_time_claims([{"exp": 100 - skew}], 100, skew)
            _check_time_claims([{"exp": 100 - skew + 0.5}], 100, skew)

    def test_nbf_and_skew(self):
        for skew in (0, 5):
            _check_time_claims([{"nbf": 100 + skew}], 100, skew)
            with self.subTest(skew=skew), self.assertRaises(ValueError):
                _check_time_claims([{"nbf": 101 + skew}], 100, skew)


class DisclosureTests(unittest.TestCase):
    def test_nested_object_and_array_disclosures(self):
        child = encoded(["salt-child", "value"])
        parent = encoded(["salt-parent", "nested", [{"...": digest(child)}]])
        validate_presentation(presentation({"_sd": [digest(parent)]}, [parent, child]))

    def test_unreachable_nested_disclosure(self):
        child = encoded(["salt", "value"])
        with self.assertRaises(ValueError):
            validate_presentation(presentation({}, [child]))

    def test_repeated_array_digest(self):
        child = encoded(["salt", "value"])
        with self.assertRaises(ValueError):
            validate_presentation(presentation({"array": [{"...": digest(child)}] * 2}, [child]))

    def test_wrong_object_disclosure_kind(self):
        child = encoded(["salt", "value"])
        with self.assertRaises(ValueError):
            validate_presentation(presentation({"_sd": [digest(child)]}, [child]))

    def test_shadowed_member(self):
        child = encoded(["salt", "name", "value"])
        with self.assertRaises(ValueError):
            validate_presentation(presentation({"name": "original", "_sd": [digest(child)]}, [child]))

    def test_nested_hash_algorithm(self):
        with self.assertRaises(ValueError):
            validate_presentation(presentation({"nested": {"_sd_alg": "sha-256"}}, []))

    def test_duplicate_encoded_payload_members(self):
        token = presentation({}, [])
        payload = base64.urlsafe_b64encode(b'{"exp":0,"exp":100}').decode().rstrip("=")
        token.issuer_jwt = encoded(token.header) + "." + payload + ".AA"
        with self.assertRaises(ValueError):
            validate_presentation(token)

    def test_reserved_disclosed_names(self):
        for name in ("_sd", "...", "_sd_alg"):
            child = encoded(["salt", name, "value"])
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_presentation(presentation({"_sd": [digest(child)]}, [child]))

    def test_decoy_digest_is_not_an_unused_presented_disclosure(self):
        validate_presentation(presentation({"_sd": [digest("absent-decoy")]}, []))


def run_tests():
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromModule(__import__(__name__))
    )
    if not result.wasSuccessful():
        raise AssertionError("Adversarial Python boundary tests failed")


if __name__ == "__main__":
    unittest.main()
