"""Strict JSON and complete SD-JWT presentation validation around the pinned SDK.

The SDK authenticates signatures. This module checks syntax and accounts for every
presented disclosure; its output alone never establishes authenticity.
"""

import base64
import hashlib
import json
import math
import re


def strict_json(raw):
    def members(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("Duplicate JSON member")
            result[name] = value
        return result

    def inspect(value, depth=0):
        if depth > 100:
            raise ValueError("JSON nesting exceeds limit")
        if isinstance(value, str):
            value.encode("utf-8", errors="strict")
        elif isinstance(value, float) and not math.isfinite(value):
            raise ValueError("Non-finite JSON number")
        elif isinstance(value, dict):
            for name, child in value.items():
                inspect(name, depth + 1)
                inspect(child, depth + 1)
        elif isinstance(value, list):
            for child in value:
                inspect(child, depth + 1)

    result = json.loads(raw, object_pairs_hook=members)
    inspect(result)
    return result


def decode(segment):
    if not isinstance(segment, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", segment):
        raise ValueError("Invalid base64url")
    raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != segment:
        raise ValueError("Non-canonical base64url")
    return raw


def jwt_json(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid compact JWT")
    header, payload = (strict_json(decode(part)) for part in parts[:2])
    decode(parts[2])
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("JWT header and payload must be objects")
    return header, payload


def validate_presentation(token):
    """RFC 9901 digest reachability, uniqueness and disclosure shape checks.

    Missing disclosures may be decoys or deliberately undisclosed claims. They
    are not equivalent to extra *presented* disclosures, which must all be used.
    Required authority claims are checked by the application schema separately.
    """
    header, payload = jwt_json(token.issuer_jwt)
    if header != token.header or payload != token.payload:
        raise ValueError("Inconsistent parsed JWT")
    if payload.get("_sd_alg", "sha-256") != "sha-256":
        raise ValueError("Unsupported disclosure hash algorithm")
    disclosures = {}
    for encoded in token.disclosures:
        value = strict_json(decode(encoded))
        if not isinstance(value, list) or len(value) not in (2, 3) or not isinstance(value[0], str):
            raise ValueError("Malformed disclosure")
        if len(value) == 3 and (not isinstance(value[1], str) or value[1] in ("_sd", "...", "_sd_alg")):
            raise ValueError("Invalid disclosed member name")
        digest = base64.urlsafe_b64encode(hashlib.sha256(encoded.encode("ascii")).digest()).decode().rstrip("=")
        if digest in disclosures:
            raise ValueError("Duplicate disclosure")
        disclosures[digest] = value

    seen, used = set(), set()

    def consume(digest, length):
        if not isinstance(digest, str) or len(decode(digest)) != 32 or digest in seen:
            raise ValueError("Invalid or repeated signed disclosure digest")
        seen.add(digest)
        disclosure = disclosures.get(digest)
        if disclosure is not None:
            if len(disclosure) != length:
                raise ValueError("Wrong disclosure kind")
            used.add(digest)
        return disclosure

    def walk(value, depth=0):
        if depth > 100:
            raise ValueError("Disclosure nesting exceeds limit")
        if isinstance(value, list):
            for child in value:
                if isinstance(child, dict) and "..." in child:
                    if set(child) != {"..."}:
                        raise ValueError("Invalid array disclosure placeholder")
                    disclosure = consume(child["..."], 2)
                    if disclosure is not None:
                        walk(disclosure[1], depth + 1)
                else:
                    walk(child, depth + 1)
        elif isinstance(value, dict):
            if "..." in value or (depth > 0 and "_sd_alg" in value):
                raise ValueError("Misplaced reserved disclosure member")
            names = set(value) - {"_sd", "_sd_alg"}
            for name in names:
                walk(value[name], depth + 1)
            digests = value.get("_sd", [])
            if not isinstance(digests, list):
                raise ValueError("Invalid object disclosure digests")
            for digest in digests:
                disclosure = consume(digest, 3)
                if disclosure is not None:
                    if disclosure[1] in names:
                        raise ValueError("Disclosure shadows existing member")
                    names.add(disclosure[1])
                    walk(disclosure[2], depth + 1)

    walk(payload)
    if used != set(disclosures):
        raise ValueError("Unauthenticated or unused presented disclosure")
