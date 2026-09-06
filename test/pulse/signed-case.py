"""Independent deterministic regression signer. No Pulse or AP2 issuance code."""

import base64
import hashlib
import json
import sys
from copy import deepcopy

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def encode(value):
    return b64(json.dumps(value, separators=(",", ":")).encode())


def digest(value):
    return b64(hashlib.sha256(value.encode()).digest())


def key(number, kid):
    private = ec.derive_private_key(number, ec.SECP256R1())
    public = private.public_key().public_numbers()
    jwk = dict(kty="EC", crv="P-256", alg="ES256", kid=kid,
               x=b64(public.x.to_bytes(32)), y=b64(public.y.to_bytes(32)))
    return private, jwk


def jwt(payload, pair, typ):
    private, jwk = pair
    signing = encode(dict(alg="ES256", kid=jwk["kid"], typ=typ)) + "." + encode(payload)
    der = private.sign(signing.encode(), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    return signing + "." + b64(r.to_bytes(32) + s.to_bytes(32))


def present(payload, mode):
    disclosures = []
    if mode in ("valid", "duplicate", "tampered", "concealed", "revealed"):
        if mode in ("concealed", "revealed"):
            value = dict(type="payment.amount_range", currency="GBP", min=0, max=1)
            disclosure = encode(["fixed-restriction-salt", value])
            payload["delegate_payload"][0]["constraints"].append({"...": digest(disclosure)})
            if mode == "revealed":
                disclosures = [disclosure]
        else:
            disclosure = encode(["fixed-regression-salt", payload["delegate_payload"][0]])
            payload["delegate_payload"] = [{"...": digest(disclosure)}]
            disclosures = [disclosure]
        payload["_sd_alg"] = "sha-256"
        if mode == "duplicate":
            disclosures *= 2
        if mode == "tampered":
            disclosures = [encode(["different-salt", {"vct": "tampered"}])]
    if mode == "orphan":
        disclosures = [encode(["fixed-salt", "unsigned", "injected"])]
    if mode == "malformed":
        disclosures = [encode({"not": "a disclosure array"})]
    return disclosures


def main():
    request = json.load(sys.stdin)
    case, options = request["case"], request["options"]
    ap2 = case["ap2"]
    evidence = ap2["verification"]["cryptographicEvidence"]
    root, holder, receipt_key = key(101, "root"), key(102, "holder"), key(103, "receipt")
    ap2["openMandate"]["cnf"]["jwk"] = holder[1]
    root_payload = {"delegate_payload": [deepcopy(ap2["openMandate"])]}
    root_payload.update(options.get("root", {}))
    root_disclosures = present(root_payload, options.get("rootDisclosure"))
    root_token = jwt(root_payload, root, "example+sd-jwt") + "~" + "".join(d + "~" for d in root_disclosures)
    leaf_payload = dict(delegate_payload=[deepcopy(ap2["closedMandate"])],
                        iat=case["nowEpochSeconds"] - 1, aud=evidence["expectedAudience"],
                        nonce=evidence["expectedNonce"], sd_hash=digest(root_token))
    leaf_payload.update(options.get("leaf", {}))
    for name in options.get("omitLeaf", []):
        leaf_payload.pop(name, None)
    leaf_disclosures = present(leaf_payload, options.get("leafDisclosure"))
    leaf_jwt = jwt(leaf_payload, holder, "kb+sd-jwt")
    reference = digest(leaf_jwt)
    if options.get("corruptLeaf"):
        parts = leaf_jwt.split(".")
        signature = bytearray(base64.urlsafe_b64decode(parts[2] + "=="))
        signature[0] ^= 1
        parts[2] = b64(signature)
        leaf_jwt = ".".join(parts)
    evidence["mandateChain"] = root_token + "~" + leaf_jwt + "~" + "".join(d + "~" for d in leaf_disclosures)
    evidence["trustedRootPublicJwk"], evidence["trustedReceiptPublicJwk"] = root[1], receipt_key[1]
    ap2["paymentReceipt"]["reference"] = reference
    receipt_payload = deepcopy(ap2["paymentReceipt"])
    receipt_payload.update(options.get("receipt", {}))
    evidence["paymentReceiptJwt"] = jwt(receipt_payload, receipt_key, "JWT")
    ap2["verification"]["closedMandateReference"] = reference
    for requirements in (case["x402"]["requirements"], case["x402"]["payload"]["accepted"]):
        requirements["extra"]["ap2MandateReference"] = reference
    case["x402"]["payload"]["payload"]["authorization"]["nonce"] = "0x" + base64.urlsafe_b64decode(reference + "=").hex()
    if options.get("rootDisclosure") == "revealed":
        ap2["openMandate"]["constraints"].append(dict(type="payment.amount_range", currency="GBP", min=0, max=1))
    print(json.dumps(case, separators=(",", ":")))


if __name__ == "__main__":
    main()
