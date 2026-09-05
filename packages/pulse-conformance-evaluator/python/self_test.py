"""Independent positive and negative tests for the structured AP2 bridge."""

from __future__ import annotations

import base64
import json
import time

from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto.jwk import JWK

from ap2.sdk.generated.open_payment_mandate import (
    AllowedPayees,
    AmountRange,
    OpenPaymentMandate,
    PaymentReference,
)
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.jwt_helper import create_jwt
from ap2.sdk.mandate import MandateClient

from verify_ap2_structured import verify_request


def _key(key_id: str) -> JWK:
    private_key = ec.generate_private_key(ec.SECP256R1())
    value = json.loads(JWK.from_pyca(private_key).export())
    value["kid"] = key_id
    value["alg"] = "ES256"
    return JWK(**value)


def _public(key: JWK) -> dict:
    return json.loads(key.export_public())


def _flip_signature(jwt: str) -> str:
    parts = jwt.split(".")
    if len(parts) != 3:
        raise ValueError("test JWT is malformed")
    final = parts[2]
    parts[2] = ("A" if final[0] != "A" else "B") + final[1:]
    return ".".join(parts)


def _decode_base64url_json(value: str) -> object:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return json.loads(base64.urlsafe_b64decode(value + padding))


def _encode_base64url_json(value: object) -> str:
    encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")


def _tamper_disclosure_digest(disclosure: str) -> str:
    value = _decode_base64url_json(disclosure)
    if not isinstance(value, list) or not value or not isinstance(value[0], str):
        raise ValueError("test disclosure is malformed")
    value[0] = value[0] + "tampered"
    return _encode_base64url_json(value)


def _resign_with_bad_sd_hash(token: str, holder_key: JWK) -> str:
    token_parts = token.split("~")
    jwt_parts = token_parts[0].split(".")
    if len(jwt_parts) != 3:
        raise ValueError("test KB SD JWT is malformed")
    header = _decode_base64url_json(jwt_parts[0])
    payload = _decode_base64url_json(jwt_parts[1])
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("test KB SD JWT JSON is malformed")
    current_hash = payload.get("sd_hash")
    if not isinstance(current_hash, str):
        raise ValueError("test KB SD JWT has no sd_hash")
    payload["sd_hash"] = "A" * 43 if current_hash != "A" * 43 else "B" * 43
    token_parts[0] = create_jwt(header, payload, holder_key)
    return "~".join(token_parts)


def _make_request() -> tuple[dict, JWK]:
    now = int(time.time())
    root_key = _key("independent-root")
    holder_key = _key("independent-holder")
    receipt_key = _key("independent-receipt")
    merchant = Merchant(
        id="merchant-independent",
        name="Independent Merchant",
        website="https://merchant.example",
    )
    client = MandateClient()
    instrument = PaymentInstrument(
        id="instrument-independent",
        type="x402",
        description="Independent test instrument",
    )
    open_token = client.create(
        payloads=[
            OpenPaymentMandate(
                constraints=[
                    PaymentReference(
                        conditional_transaction_id="checkout-independent"
                    ),
                    AllowedPayees(allowed=[merchant]),
                    AmountRange(currency="GBP", min=1250, max=1250),
                ],
                cnf={"jwk": _public(holder_key)},
                iat=now - 10,
                exp=now + 300,
            )
        ],
        issuer_key=root_key,
    )
    chain = client.present(
        holder_key=holder_key,
        mandate_token=open_token,
        payloads=[
            PaymentMandate(
                transaction_id="checkout-independent",
                payee=merchant,
                payment_amount=Amount(amount=1250, currency="GBP"),
                payment_instrument=instrument,
                execution_date="2030-01-01T00:00:00Z",
                iat=now - 5,
                exp=now + 300,
            )
        ],
        aud="https://facilitator.example/ap2",
        nonce="independent-nonce",
    )
    receipt = {
        "status": "Success",
        "iss": "facilitator.example",
        "iat": now,
        "reference": "A" * 43,
        "error": None,
        "error_description": None,
        "payment_id": "payment-independent",
        "psp_confirmation_id": "psp-independent",
        "network_confirmation_id": "0x" + "12" * 32,
    }
    receipt_jwt = create_jwt(
        {"alg": "ES256", "kid": receipt_key.get("kid"), "typ": "JWT"},
        receipt,
        receipt_key,
    )
    verification_time = int(time.time())
    return (
        {
            "version": "inntris-pulse-ap2-structured-request/0.1",
            "mandateChain": chain,
            "paymentReceiptJwt": receipt_jwt,
            "trustedRootPublicJwk": _public(root_key),
            "trustedReceiptPublicJwk": _public(receipt_key),
            "expectedAudience": "https://facilitator.example/ap2",
            "expectedNonce": "independent-nonce",
            "currentTimeEpoch": verification_time,
            "clockSkewSeconds": 0,
        },
        holder_key,
    )


def main() -> None:
    request, holder_key = _make_request()
    valid = verify_request(request)
    assert valid["openMandate"]["status"] == "verified"
    assert valid["closedMandate"]["status"] == "verified"
    assert valid["keyBinding"]["status"] == "verified"
    assert valid["mandateTime"]["status"] == "verified"
    assert valid["receipt"]["status"] == "verified"

    root_bad = dict(request)
    root, leaf = request["mandateChain"].split("~~")
    root_jwt, *root_disclosures = root.split("~")
    root_bad["mandateChain"] = "~".join(
        [_flip_signature(root_jwt), *root_disclosures]
    ) + "~~" + leaf
    root_result = verify_request(root_bad)
    assert root_result["openMandate"]["status"] == "invalid"
    assert root_result["closedMandate"]["status"] == "notEvaluated"
    assert root_result["keyBinding"]["status"] == "notEvaluated"
    assert root_result["mandateTime"]["status"] == "notEvaluated"
    assert root_result["receipt"]["status"] == "verified"

    leaf_bad = dict(request)
    leaf_jwt, *leaf_disclosures = leaf.split("~")
    leaf_bad["mandateChain"] = root + "~~" + "~".join(
        [_flip_signature(leaf_jwt), *leaf_disclosures]
    )
    leaf_result = verify_request(leaf_bad)
    assert leaf_result["openMandate"]["status"] == "verified"
    assert leaf_result["closedMandate"]["status"] == "invalid"
    assert leaf_result["keyBinding"]["status"] == "notEvaluated"
    assert leaf_result["mandateTime"]["status"] == "notEvaluated"

    disclosure_bad = dict(request)
    leaf_parts = leaf.split("~")
    if len(leaf_parts) < 2 or not leaf_parts[1]:
        raise AssertionError("test leaf disclosure is unavailable")
    leaf_parts[1] = _tamper_disclosure_digest(leaf_parts[1])
    disclosure_bad["mandateChain"] = root + "~~" + "~".join(leaf_parts)
    disclosure_result = verify_request(disclosure_bad)
    assert disclosure_result["openMandate"]["status"] == "verified"
    assert disclosure_result["closedMandate"]["status"] == "invalid"
    assert disclosure_result["keyBinding"]["status"] == "notEvaluated"

    sd_hash_bad = dict(request)
    sd_hash_bad["mandateChain"] = (
        root + "~~" + _resign_with_bad_sd_hash(leaf, holder_key)
    )
    sd_hash_result = verify_request(sd_hash_bad)
    assert sd_hash_result["openMandate"]["status"] == "verified"
    assert sd_hash_result["closedMandate"]["status"] == "verified"
    assert sd_hash_result["keyBinding"]["status"] == "invalid"
    assert sd_hash_result["mandateTime"]["status"] == "verified"

    binding_bad = dict(request)
    binding_bad["expectedNonce"] = "wrong-nonce"
    binding_result = verify_request(binding_bad)
    assert binding_result["openMandate"]["status"] == "verified"
    assert binding_result["closedMandate"]["status"] == "verified"
    assert binding_result["keyBinding"]["status"] == "invalid"
    assert binding_result["mandateTime"]["status"] == "verified"

    audience_bad = dict(request)
    audience_bad["expectedAudience"] = "https://wrong.example/ap2"
    audience_result = verify_request(audience_bad)
    assert audience_result["closedMandate"]["status"] == "verified"
    assert audience_result["keyBinding"]["status"] == "invalid"

    expired = dict(request)
    expired["currentTimeEpoch"] = request["currentTimeEpoch"] + 1_000
    expired_result = verify_request(expired)
    assert expired_result["openMandate"]["status"] == "verified"
    assert expired_result["closedMandate"]["status"] == "verified"
    assert expired_result["keyBinding"]["status"] == "verified"
    assert expired_result["mandateTime"]["status"] == "invalid"

    receipt_bad = dict(request)
    receipt_bad["paymentReceiptJwt"] = _flip_signature(
        request["paymentReceiptJwt"]
    )
    receipt_result = verify_request(receipt_bad)
    assert receipt_result["receipt"]["status"] == "invalid"

    malformed = dict(request)
    malformed["mandateChain"] = root
    try:
        verify_request(malformed)
    except ValueError:
        pass
    else:
        raise AssertionError("malformed chain must fail the bridge envelope")
    print("PASS independent structured AP2 bridge")


if __name__ == "__main__":
    main()
