"""Structured AP2 verifier for the isolated Inntris Pulse evaluator."""

from __future__ import annotations

import json
import sys
from importlib.metadata import distribution, version
from typing import Any

from ap2.sdk.generated.payment_receipt import PaymentReceipt
from ap2.sdk.jwt_helper import verify_jwt
from ap2.sdk.sdjwt import common, kb_sd_jwt, sd_jwt
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
    if expected_type is int:
        valid = type(value) is int
    else:
        valid = isinstance(value, expected_type)
    if not valid:
        raise ValueError(f"{label} is invalid")
    return value


def _effective_claims(payload: dict[str, Any], label: str) -> dict[str, Any]:
    delegate_payload = payload.get("delegate_payload")
    if not isinstance(delegate_payload, list) or len(delegate_payload) != 1:
        raise ValueError(f"{label} delegate_payload must contain exactly one item")
    claims = delegate_payload[0]
    if not isinstance(claims, dict):
        raise ValueError(f"{label} delegate_payload item must be an object")
    return claims


def _require_es256(header: dict[str, Any], label: str) -> None:
    if header.get("alg") != "ES256":
        raise ValueError(f"{label} JWT algorithm is invalid")


def _check_time_claims(
    payloads: list[dict[str, Any]], current_time: int, clock_skew: int
) -> None:
    for payload in payloads:
        issued_at = payload.get("iat")
        expires_at = payload.get("exp")
        if issued_at is not None:
            if type(issued_at) not in (int, float):
                raise ValueError("mandate iat is invalid")
            if issued_at > current_time + clock_skew:
                raise ValueError("mandate iat is in the future")
        if expires_at is not None:
            if type(expires_at) not in (int, float):
                raise ValueError("mandate exp is invalid")
            if current_time > expires_at + clock_skew:
                raise ValueError("mandate is expired")


def _verify_terminal_binding(
    leaf: common.ParsedToken,
    leaf_payload: dict[str, Any],
    closed_claims: dict[str, Any],
    verified_root: common.ParsedToken,
    expected_audience: str,
    expected_nonce: str,
) -> None:
    if leaf.typ not in kb_sd_jwt.TYP_TERMINAL:
        raise ValueError("closed mandate is not a terminal KB-SD-JWT")
    if leaf.kb_jwt is not None:
        raise ValueError("a trailing key-binding JWT is not supported")
    common.verify_binding(leaf_payload, verified_root)
    common.verify_expected_claims(
        leaf_payload,
        expected_aud=expected_audience,
        expected_nonce=expected_nonce,
        token_label="KB-SD-JWT",
    )
    if isinstance(closed_claims.get("cnf"), dict):
        raise ValueError("terminal closed mandate must not contain cnf")


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

    root_jwk = _require(
        request.get("trustedRootPublicJwk"), "trustedRootPublicJwk", dict
    )
    receipt_jwk = _require(
        request.get("trustedReceiptPublicJwk"),
        "trustedReceiptPublicJwk",
        dict,
    )
    open_result: dict[str, Any] = {"status": "invalid"}
    closed_result: dict[str, Any] = {"status": "notEvaluated"}
    key_binding_result: dict[str, Any] = {"status": "notEvaluated"}
    mandate_time_result: dict[str, Any] = {"status": "notEvaluated"}
    receipt_result: dict[str, Any] = {"status": "invalid"}

    parts = mandate_chain.split("~~")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError("payment mandate chain must contain exactly two tokens")

    root_segment = parts[0]
    if not root_segment.endswith("~"):
        root_segment += "~"
    verified_root: common.ParsedToken | None = None
    root_payload: dict[str, Any] | None = None
    open_claims: dict[str, Any] | None = None
    try:
        root_key = JWK(**root_jwk)
        root = common.parse_token(root_segment)
        _require_es256(root.header, "open mandate")
        root_payload = sd_jwt.verify(root.canonical, root_key)
        open_claims = _effective_claims(root_payload, "open mandate")
        verified_root = root.with_verified_payload(root_payload, [open_claims])
        if verified_root.cnf_jwk() is None:
            raise ValueError("open mandate is missing a verified holder key")
        open_result = {"status": "verified", "claims": open_claims}
    except Exception:  # noqa: BLE001 - each stage is reported fail closed
        pass

    leaf_payload: dict[str, Any] | None = None
    closed_claims: dict[str, Any] | None = None
    if verified_root is not None:
        closed_result = {"status": "invalid"}
        try:
            leaf = common.parse_token(parts[1])
            _require_es256(leaf.header, "closed mandate")
            holder_key = verified_root.cnf_jwk()
            if holder_key is None:
                raise ValueError("open mandate is missing a verified holder key")
            leaf_payload = sd_jwt.verify(leaf.sd_jwt, holder_key)
            closed_claims = _effective_claims(leaf_payload, "closed mandate")
            closed_result = {
                "status": "verified",
                "claims": closed_claims,
                "issuerJwt": leaf.issuer_jwt,
            }

            key_binding_result = {"status": "invalid"}
            try:
                _verify_terminal_binding(
                    leaf,
                    leaf_payload,
                    closed_claims,
                    verified_root,
                    expected_audience,
                    expected_nonce,
                )
                key_binding_result = {"status": "verified"}
            except Exception:  # noqa: BLE001 - stage remains independently invalid
                pass

            mandate_time_result = {"status": "invalid"}
            try:
                if root_payload is None or open_claims is None:
                    raise ValueError("open mandate time prerequisites are unavailable")
                _check_time_claims(
                    [root_payload, open_claims, leaf_payload, closed_claims],
                    current_time,
                    clock_skew,
                )
                mandate_time_result = {"status": "verified"}
            except Exception:  # noqa: BLE001 - stage remains independently invalid
                pass
        except Exception:  # noqa: BLE001 - each stage is reported fail closed
            pass

    try:
        receipt_key = JWK(**receipt_jwk)
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
        receipt_result = {"status": "verified", "claims": receipt_claims}
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
        "mandateTime": mandate_time_result,
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
