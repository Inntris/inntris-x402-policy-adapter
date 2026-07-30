"""Official AP2 SDK verification bridge for the Inntris TypeScript gate."""

from __future__ import annotations

import json
import sys

from datetime import UTC, datetime
from typing import Any

from ap2.sdk.checkout_mandate_chain import CheckoutMandateChain
from ap2.sdk.generated.types.checkout import Checkout
from ap2.sdk.jwt_helper import verify_jwt
from ap2.sdk.mandate import MandateClient
from ap2.sdk.payment_mandate_chain import PaymentMandateChain
from ap2.sdk.utils import b64url_decode, compute_sha256_b64url
from jwcrypto.jwk import JWK


AP2_REPOSITORY = "https://github.com/google-agentic-commerce/AP2"
AP2_COMMIT = "e1ea56db72a6385bce3e5c1112b3a56ce60acb43"
AP2_PROTOCOL_VERSION = "0.2"


def _require(value: Any, name: str, expected_type: type) -> Any:
    if not isinstance(value, expected_type):
        raise ValueError(f"{name} is invalid")
    return value


def _sha256_hex_via_sdk(value: str) -> str:
    digest = b64url_decode(compute_sha256_b64url(value))
    return f"sha256:{digest.hex()}"


def _iso_timestamp(epoch: int) -> str:
    return (
        datetime.fromtimestamp(epoch, UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _minimum_expiry(payloads: list[dict[str, Any]], label: str) -> int:
    expiries = [payload.get("exp") for payload in payloads]
    if not expiries or any(not isinstance(value, int) for value in expiries):
        raise ValueError(f"{label} mandates must all carry exp")
    return min(expiries)


def _validate_checkout_jwt(
    token: str,
    merchant_key: JWK,
    expected_issuer: str,
    expected_audience: str,
    current_time: int,
) -> Checkout:
    payload = verify_jwt(token, merchant_key)
    if payload.get("iss") != expected_issuer:
        raise ValueError("checkout JWT issuer mismatch")
    audience = payload.get("aud")
    if not (
        audience == expected_audience
        or (isinstance(audience, list) and expected_audience in audience)
    ):
        raise ValueError("checkout JWT audience mismatch")
    issued_at = payload.get("iat")
    expires_at = payload.get("exp")
    if (
        not isinstance(issued_at, int)
        or not isinstance(expires_at, int)
        or issued_at > current_time
        or expires_at <= current_time
    ):
        raise ValueError("checkout JWT time claims are invalid")
    return Checkout.model_validate(payload)


def verify_request(request: dict[str, Any]) -> dict[str, Any]:
    if request.get("version") != "inntris-ap2-mandate-presentation-v1":
        raise ValueError("request version is invalid")
    checkout_token = _require(
        request.get("checkout_mandate_token"),
        "checkout_mandate_token",
        str,
    )
    payment_token = _require(
        request.get("payment_mandate_token"),
        "payment_mandate_token",
        str,
    )
    checkout_jwt = _require(request.get("checkout_jwt"), "checkout_jwt", str)
    if "~~" not in checkout_token or "~~" not in payment_token:
        raise ValueError("autonomous AP2 requires open and closed mandate chains")

    current_time = _require(
        request.get("current_time_epoch"),
        "current_time_epoch",
        int,
    )
    issuer_key = JWK(**_require(request.get("issuer_public_jwk"), "issuer_public_jwk", dict))
    merchant_key = JWK(
        **_require(request.get("merchant_public_jwk"), "merchant_public_jwk", dict)
    )
    expected_merchant_id = _require(
        request.get("expected_merchant_id"),
        "expected_merchant_id",
        str,
    )
    client = MandateClient()

    checkout_payloads = client.verify(
        token=checkout_token,
        key_or_provider=lambda _token: issuer_key,
        expected_aud=_require(
            request.get("checkout_audience"),
            "checkout_audience",
            str,
        ),
        expected_nonce=_require(
            request.get("checkout_nonce"),
            "checkout_nonce",
            str,
        ),
        clock_skew_seconds=0,
        current_time=current_time,
    )
    if not isinstance(checkout_payloads, list):
        raise ValueError("checkout mandate must be an autonomous chain")
    checkout_chain = CheckoutMandateChain.parse(checkout_payloads)
    checkout = _validate_checkout_jwt(
        checkout_jwt,
        merchant_key,
        _require(request.get("checkout_issuer"), "checkout_issuer", str),
        _require(request.get("checkout_audience"), "checkout_audience", str),
        current_time,
    )
    if checkout.merchant is None or checkout.merchant.id != expected_merchant_id:
        raise ValueError("checkout merchant mismatch")
    checkout_hash = compute_sha256_b64url(checkout_jwt)
    checkout_violations = checkout_chain.verify(
        expected_checkout_hash=checkout_hash,
        checkout_jwt=checkout_jwt,
    )
    if checkout_violations:
        raise ValueError("checkout mandate constraints failed")

    open_checkout_token = checkout_token.split("~~", maxsplit=1)[0]
    open_checkout_hash = compute_sha256_b64url(open_checkout_token)
    payment_payloads = client.verify(
        token=payment_token,
        key_or_provider=lambda _token: issuer_key,
        expected_aud=_require(
            request.get("payment_audience"),
            "payment_audience",
            str,
        ),
        expected_nonce=_require(
            request.get("payment_nonce"),
            "payment_nonce",
            str,
        ),
        clock_skew_seconds=0,
        current_time=current_time,
    )
    if not isinstance(payment_payloads, list):
        raise ValueError("payment mandate must be an autonomous chain")
    payment_chain = PaymentMandateChain.parse(payment_payloads)
    payment_violations = payment_chain.verify(
        expected_transaction_id=checkout_hash,
        expected_open_checkout_hash=open_checkout_hash,
    )
    if payment_violations:
        raise ValueError("payment mandate constraints failed")
    payment = payment_chain.closed_mandate
    if payment.payee.id != expected_merchant_id:
        raise ValueError("payment payee mismatch")
    checkout_totals = [
        total.amount for total in checkout.totals if total.type == "total"
    ]
    if len(checkout_totals) != 1 or checkout_totals[0] < 0:
        raise ValueError("checkout must contain one non-negative total")
    if (
        payment.payment_amount.amount != checkout_totals[0]
        or payment.payment_amount.currency != checkout.currency
    ):
        raise ValueError("payment amount does not match checkout total")

    checkout_expiry = _minimum_expiry(checkout_payloads, "checkout")
    payment_expiry = _minimum_expiry(payment_payloads, "payment")
    closed_checkout_jwt = client.get_closed_mandate_jwt(checkout_token)
    closed_payment_jwt = client.get_closed_mandate_jwt(payment_token)
    open_payment_token = payment_token.split("~~", maxsplit=1)[0]
    return {
        "version": "inntris-ap2-official-verification-v1",
        "sdk": {
            "repository": AP2_REPOSITORY,
            "commit": AP2_COMMIT,
            "protocol_version": AP2_PROTOCOL_VERSION,
        },
        "mode": "autonomous",
        "intent": {
            "verified": True,
            "checkout_open_mandate_hash": _sha256_hex_via_sdk(open_checkout_token),
            "payment_open_mandate_hash": _sha256_hex_via_sdk(open_payment_token),
        },
        "checkout": {
            "verified": True,
            "mandate_hash": _sha256_hex_via_sdk(closed_checkout_jwt),
            "expires_at": _iso_timestamp(checkout_expiry),
            "checkout_hash": checkout_hash,
            "checkout_id": checkout.id,
            "merchant_id": checkout.merchant.id,
            "merchant_name": checkout.merchant.name,
        },
        "payment": {
            "verified": True,
            "mandate_hash": _sha256_hex_via_sdk(closed_payment_jwt),
            "expires_at": _iso_timestamp(payment_expiry),
            "transaction_id": payment.transaction_id,
            "payee_id": payment.payee.id,
            "payee_name": payment.payee.name,
            "amount_minor": str(payment.payment_amount.amount),
            "currency": payment.payment_amount.currency,
            "payment_instrument_type": payment.payment_instrument.type,
        },
        "verified_at": _iso_timestamp(current_time),
    }


def main() -> int:
    try:
        raw = sys.stdin.read(1_000_001)
        if len(raw) > 1_000_000:
            raise ValueError("request exceeds limit")
        request = json.loads(raw)
        if not isinstance(request, dict):
            raise ValueError("request must be an object")
        result = verify_request(request)
        sys.stdout.write(json.dumps(result, separators=(",", ":")))
        return 0
    except Exception as error:  # noqa: BLE001 - boundary converts all failures to deny
        sys.stderr.write(f"AP2_VERIFY_FAILED:{type(error).__name__}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
