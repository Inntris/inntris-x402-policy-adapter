"""Independent positive and negative tests for the structured AP2 bridge."""

from __future__ import annotations

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


def _make_request() -> dict:
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
    return {
        "version": "inntris-pulse-ap2-structured-request/0.1",
        "mandateChain": chain,
        "paymentReceiptJwt": receipt_jwt,
        "trustedRootPublicJwk": _public(root_key),
        "trustedReceiptPublicJwk": _public(receipt_key),
        "expectedAudience": "https://facilitator.example/ap2",
        "expectedNonce": "independent-nonce",
        "currentTimeEpoch": verification_time,
        "clockSkewSeconds": 0,
    }


def main() -> None:
    request = _make_request()
    valid = verify_request(request)
    assert valid["openMandate"]["verified"] is True
    assert valid["closedMandate"]["verified"] is True
    assert valid["keyBinding"]["verified"] is True
    assert valid["receipt"]["verified"] is True

    root_bad = dict(request)
    root, leaf = request["mandateChain"].split("~~")
    root_jwt, *root_disclosures = root.split("~")
    root_bad["mandateChain"] = "~".join(
        [_flip_signature(root_jwt), *root_disclosures]
    ) + "~~" + leaf
    root_result = verify_request(root_bad)
    assert root_result["openMandate"]["verified"] is False
    assert root_result["closedMandate"]["verified"] is False

    binding_bad = dict(request)
    binding_bad["expectedNonce"] = "wrong-nonce"
    binding_result = verify_request(binding_bad)
    assert binding_result["openMandate"]["verified"] is True
    assert binding_result["closedMandate"]["verified"] is False
    assert binding_result["keyBinding"]["verified"] is False

    receipt_bad = dict(request)
    receipt_bad["paymentReceiptJwt"] = _flip_signature(
        request["paymentReceiptJwt"]
    )
    receipt_result = verify_request(receipt_bad)
    assert receipt_result["receipt"]["verified"] is False
    print("PASS independent structured AP2 bridge")


if __name__ == "__main__":
    main()
