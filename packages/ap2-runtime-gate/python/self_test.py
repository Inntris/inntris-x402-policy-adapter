"""End-to-end official AP2 SDK bridge self-test."""

from __future__ import annotations

import json
import subprocess
import sys
import time

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto.jwk import JWK

from ap2.sdk.generated.checkout_mandate import CheckoutMandate
from ap2.sdk.generated.open_checkout_mandate import (
    AllowedMerchants,
    OpenCheckoutMandate,
)
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
from ap2.sdk.utils import compute_sha256_b64url

from verify_ap2 import verify_request


def _jwk_with_kid(raw_key: ec.EllipticCurvePrivateKey, kid: str) -> JWK:
    data = json.loads(JWK.from_pyca(raw_key).export())
    data["kid"] = kid
    return JWK(**data)


def _public(key: JWK) -> dict:
    return json.loads(key.export_public())


def main() -> None:
    now = int(time.time())
    user_key = _jwk_with_kid(
        ec.generate_private_key(ec.SECP256R1()),
        "user-root",
    )
    agent_key = _jwk_with_kid(
        ec.generate_private_key(ec.SECP256R1()),
        "shopping-agent",
    )
    merchant_key = _jwk_with_kid(
        ec.generate_private_key(ec.SECP256R1()),
        "merchant-research-api",
    )
    merchant = Merchant(id="merchant-research-api", name="Research API")
    client = MandateClient()
    cnf = {"jwk": _public(agent_key)}

    open_checkout = client.create(
        payloads=[
            OpenCheckoutMandate(
                constraints=[AllowedMerchants(allowed=[merchant])],
                cnf=cnf,
                iat=now - 5,
                exp=now + 300,
            )
        ],
        issuer_key=user_key,
    )
    checkout_payload = {
        "iss": merchant.id,
        "aud": "merchant-processor",
        "iat": now - 5,
        "exp": now + 300,
        "id": "checkout-1",
        "merchant": merchant.model_dump(),
        "line_items": [
            {
                "id": "line-1",
                "item": {
                    "id": "research-report",
                    "title": "Research report",
                    "price": 4500,
                },
                "quantity": 1,
                "totals": [{"type": "total", "amount": 4500}],
            }
        ],
        "status": "ready_for_complete",
        "currency": "USD",
        "totals": [
            {"type": "subtotal", "amount": 4500},
            {"type": "total", "amount": 4500},
        ],
        "links": [],
    }
    checkout_jwt = create_jwt(
        {"alg": "ES256", "kid": "merchant-research-api"},
        checkout_payload,
        merchant_key,
    )
    checkout_hash = compute_sha256_b64url(checkout_jwt)
    checkout_chain = client.present(
        holder_key=agent_key,
        mandate_token=open_checkout,
        payloads=[
            CheckoutMandate(
                checkout_jwt=checkout_jwt,
                checkout_hash=checkout_hash,
                iat=now - 5,
                exp=now + 300,
            )
        ],
        aud="merchant-processor",
        nonce="checkout-nonce",
    )

    open_checkout_hash = compute_sha256_b64url(
        checkout_chain.split("~~", maxsplit=1)[0]
    )
    open_payment = client.create(
        payloads=[
            OpenPaymentMandate(
                constraints=[
                    PaymentReference(
                        conditional_transaction_id=open_checkout_hash,
                    ),
                    AllowedPayees(allowed=[merchant]),
                    AmountRange(currency="USD", min=0, max=5000),
                ],
                cnf=cnf,
                iat=now - 5,
                exp=now + 300,
            )
        ],
        issuer_key=user_key,
    )
    payment_chain = client.present(
        holder_key=agent_key,
        mandate_token=open_payment,
        payloads=[
            PaymentMandate(
                transaction_id=checkout_hash,
                payee=merchant,
                payment_amount=Amount(amount=4500, currency="USD"),
                payment_instrument=PaymentInstrument(
                    id="credential-stub",
                    type="card",
                    description="Self-test only",
                ),
                iat=now - 5,
                exp=now + 300,
            )
        ],
        aud="credential-provider",
        nonce="payment-nonce",
    )
    request = {
        "version": "inntris-ap2-mandate-presentation-v1",
        "checkout_mandate_token": checkout_chain,
        "payment_mandate_token": payment_chain,
        "checkout_jwt": checkout_jwt,
        "checkout_audience": "merchant-processor",
        "checkout_nonce": "checkout-nonce",
        "checkout_issuer": merchant.id,
        "payment_audience": "credential-provider",
        "payment_nonce": "payment-nonce",
        "issuer_public_jwk": _public(user_key),
        "merchant_public_jwk": _public(merchant_key),
        "expected_merchant_id": merchant.id,
        "current_time_epoch": now,
    }
    result = verify_request(request)
    assert result["intent"]["verified"] is True
    assert result["checkout"]["merchant_id"] == merchant.id
    assert result["payment"]["amount_minor"] == "4500"
    assert result["payment"]["transaction_id"] == result["checkout"]["checkout_hash"]

    process = subprocess.run(
        [sys.executable, str(Path(__file__).with_name("verify_ap2.py"))],
        input=json.dumps(request),
        capture_output=True,
        check=False,
        text=True,
    )
    assert process.returncode == 0
    assert json.loads(process.stdout) == result
    assert process.stderr == ""

    for field, value in [
        ("checkout_audience", "wrong-checkout-audience"),
        ("checkout_nonce", "wrong-checkout-nonce"),
        ("payment_audience", "wrong-payment-audience"),
        ("payment_nonce", "wrong-payment-nonce"),
    ]:
        mismatched_key_binding = dict(request)
        mismatched_key_binding[field] = value
        try:
            verify_request(mismatched_key_binding)
        except ValueError:
            pass
        else:
            raise AssertionError(f"{field} mismatch was not rejected")

    tampered = dict(request)
    tampered["expected_merchant_id"] = "another-merchant"
    try:
        verify_request(tampered)
    except ValueError:
        pass
    else:
        raise AssertionError("merchant substitution was not rejected")

    amount_mismatch_chain = client.present(
        holder_key=agent_key,
        mandate_token=open_payment,
        payloads=[
            PaymentMandate(
                transaction_id=checkout_hash,
                payee=merchant,
                payment_amount=Amount(amount=4400, currency="USD"),
                payment_instrument=PaymentInstrument(
                    id="credential-stub",
                    type="card",
                    description="Self-test only",
                ),
                iat=now - 5,
                exp=now + 300,
            )
        ],
        aud="credential-provider",
        nonce="payment-nonce",
    )
    amount_mismatch = dict(request)
    amount_mismatch["payment_mandate_token"] = amount_mismatch_chain
    try:
        verify_request(amount_mismatch)
    except ValueError:
        pass
    else:
        raise AssertionError("checkout and payment amount mismatch was not rejected")
    print("PASS official AP2 SDK verification bridge")


if __name__ == "__main__":
    main()
