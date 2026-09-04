"""Structured AP2 verifier for the isolated Inntris Pulse evaluator."""

from __future__ import annotations

import json
import sys
from importlib.metadata import distribution, version
from typing import Any

from ap2.sdk.generated.payment_receipt import PaymentReceipt
from ap2.sdk.jwt_helper import verify_jwt
from ap2.sdk.mandate import MandateClient
from ap2.sdk.sdjwt import sd_jwt
from jwcrypto.jwk import JWK


AP2_REPOSITORY = "https://github.com/google-agentic-commerce/AP2"
AP2_COMMIT = "e1ea56db72a6385bce3e5c1112b3a56ce60acb43"
AP2_PROTOCOL_VERSION = "0.2"
REQUEST_KEYS = {
    "clockSkewSeconds",
    "currentTimeEpoch",
    "expectedAudience",
    "expectedNonce",
    "mandateChain",
    "paymentReceiptJwt",
    "trustedReceiptPublicJwk",
    "trustedRootPublicJwk",
    "version",
}


def _verify_runtime_pins() -> None:
    installed_ap2 = distribution("ap2")
    direct_url_raw = installed_ap2.read_text("direct_url.json")
    if direct_url_raw is None:
        raise ValueError("AP2 installation is not pinned to a source commit")
    direct_url = json.loads(direct_url_raw)
    vcs_info = direct_url.get("vcs_info") if isinstance(direct_url, dict) else None
    if (
        not isinstance(vcs_info, dict)
        or vcs_info.get("commit_id") != AP2_COMMIT
        or vcs_info.get("requested_revision") != AP2_COMMIT
    ):
        raise ValueError("AP2 installation commit does not match the evaluator pin")
    if version("cryptography") != "50.0.0" or version("jwcrypto") != "1.5.7":
        raise ValueError("AP2 cryptographic dependency versions do not match the evaluator pins")


def _require(value: Any, label: str, expected_type: type) -> Any:
    if not isinstance(value, expected_type):
        raise ValueError(f"{label} is invalid")
    return value


def _effective_open_claims(root_payload: dict[str, Any]) -> dict[str, Any]:
    delegate_payload = root_payload.get("delegate_payload")
    if not isinstance(delegate_payload, list) or len(delegate_payload) != 1:
        raise ValueError("root delegate_payload must contain exactly one item")
    claims = delegate_payload[0]
    if not isinstance(claims, dict):
        raise ValueError("root delegate_payload item must be an object")
    return claims


def _jwt_header(token: str) -> dict[str, Any]:
    encoded = token.split(".", maxsplit=1)[0]
    padding = "=" * ((4 - len(encoded) % 4) % 4)
    import base64

    value = json.loads(base64.urlsafe_b64decode(encoded + padding))
    if not isinstance(value, dict):
        raise ValueError("JWT header must be an object")
    return value


def verify_request(request: dict[str, Any]) -> dict[str, Any]:
    _verify_runtime_pins()
    if set(request) != REQUEST_KEYS:
        raise ValueError("request fields are invalid")
    if request.get("version") != "inntris-pulse-ap2-structured-request/0.1":
        raise ValueError("request version is invalid")

    mandate_chain = _require(request.get("mandateChain"), "mandateChain", str)
    receipt_jwt = _require(
        request.get("paymentReceiptJwt"), "paymentReceiptJwt", str
    )
    expected_audience = _require(
        request.get("expectedAudience"), "expectedAudience", str
    )
    expected_nonce = _require(request.get("expectedNonce"), "expectedNonce", str)
    current_time = _require(
        request.get("currentTimeEpoch"), "currentTimeEpoch", int
    )
    clock_skew = _require(
        request.get("clockSkewSeconds"), "clockSkewSeconds", int
    )
    if current_time < 0 or clock_skew < 0 or clock_skew > 300:
        raise ValueError("time input is invalid")

    root_key = JWK(
        **_require(
            request.get("trustedRootPublicJwk"), "trustedRootPublicJwk", dict
        )
    )
    receipt_key = JWK(
        **_require(
            request.get("trustedReceiptPublicJwk"),
            "trustedReceiptPublicJwk",
            dict,
        )
    )
    open_result: dict[str, Any] = {"verified": False}
    closed_result: dict[str, Any] = {"verified": False}
    key_binding_result: dict[str, Any] = {"verified": False}
    receipt_result: dict[str, Any] = {"verified": False}
    client = MandateClient()

    parts = mandate_chain.split("~~")
    if len(parts) == 2 and parts[0] and parts[1]:
        root_token = parts[0] if parts[0].endswith("~") else parts[0] + "~"
        try:
            root_payload = sd_jwt.verify(root_token, root_key)
            open_result = {
                "verified": True,
                "claims": _effective_open_claims(root_payload),
            }
        except Exception:  # noqa: BLE001 - each stage is reported fail closed
            pass

        try:
            payloads = client.verify(
                token=mandate_chain,
                key_or_provider=lambda _token: root_key,
                expected_aud=expected_audience,
                expected_nonce=expected_nonce,
                clock_skew_seconds=clock_skew,
                current_time=current_time,
            )
            if not isinstance(payloads, list) or len(payloads) != 2:
                raise ValueError("payment mandate chain must contain two payloads")
            if not all(isinstance(payload, dict) for payload in payloads):
                raise ValueError("verified AP2 payloads must be objects")
            open_result = {"verified": True, "claims": payloads[0]}
            closed_result = {
                "verified": True,
                "claims": payloads[1],
                "issuerJwt": client.get_closed_mandate_jwt(mandate_chain),
            }
            key_binding_result = {"verified": True}
        except Exception:  # noqa: BLE001 - each stage is reported fail closed
            pass

    try:
        header = _jwt_header(receipt_jwt)
        if header.get("alg") != "ES256":
            raise ValueError("receipt JWT algorithm is invalid")
        if header.get("kid") != receipt_key.get("kid"):
            raise ValueError("receipt JWT key id is invalid")
        receipt_claims = verify_jwt(receipt_jwt, receipt_key)
        PaymentReceipt.model_validate(receipt_claims)
        issued_at = receipt_claims.get("iat")
        if not isinstance(issued_at, int) or issued_at > current_time + clock_skew:
            raise ValueError("receipt JWT time is invalid")
        receipt_result = {"verified": True, "claims": receipt_claims}
    except Exception:  # noqa: BLE001 - each stage is reported fail closed
        pass

    return {
        "version": "inntris-pulse-ap2-structured-verification/0.1",
        "sdk": {
            "repository": AP2_REPOSITORY,
            "commit": AP2_COMMIT,
            "protocolVersion": AP2_PROTOCOL_VERSION,
        },
        "openMandate": open_result,
        "closedMandate": closed_result,
        "keyBinding": key_binding_result,
        "receipt": receipt_result,
    }


def main() -> int:
    try:
        raw = sys.stdin.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError("request exceeds limit")
        request = json.loads(raw)
        if not isinstance(request, dict):
            raise ValueError("request must be an object")
        result = verify_request(request)
        sys.stdout.write(json.dumps(result, separators=(",", ":")))
        return 0
    except Exception as error:  # noqa: BLE001 - process boundary is fail closed
        sys.stderr.write(f"AP2_STRUCTURED_VERIFY_FAILED:{type(error).__name__}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
