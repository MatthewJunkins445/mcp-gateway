"""Deterministic pins, bounded schema validation, and response redaction."""

import hashlib
import json
import re

from jsonschema import Draft202012Validator


class GuardError(Exception):
    """A fail-closed gateway decision; messages contain no upstream payloads."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def validate_schema(schema):
    Draft202012Validator.check_schema(schema)

    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"$ref", "$dynamicRef", "$recursiveRef"} and (
                    not isinstance(item, str) or not item.startswith("#")
                ):
                    raise GuardError("External schema references are unsupported")
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(schema)


SECRET_KEY = re.compile(r"(?:password|passwd|secret|token|api[_-]?key|authorization|private[_-]?key)", re.I)
PATTERNS = [
    re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----", re.S),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16})\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]+=*", re.I),
    re.compile(r'''(?i)\b(?:password|passwd|secret|token|api[_-]?key|authorization)\b["']?\s*[:=]\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;}]+)'''),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
]


def redact_text(text, literals=()):
    for secret in sorted(literals, key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    for pattern in PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def redact(value, literals=()):
    if isinstance(value, str):
        return redact_text(value, literals)
    if isinstance(value, list):
        return [redact(item, literals) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if redact_text(key, literals) != key:
                raise GuardError("Response contains sensitive object keys")
            result[key] = "[REDACTED]" if SECRET_KEY.search(key) else redact(item, literals)
        return result
    return value


def permitted(key, policy):
    return key in policy["allow"] and key not in policy["deny"]


def check_pin(key, definition, server_digest, pins, policy):
    if not permitted(key, policy):
        raise GuardError("Tool denied by policy")
    pin = pins.get(key)
    if not pin:
        raise GuardError("Tool has no approved pin")
    if pin["server_digest"] != server_digest or digest(pin["definition"]) != digest(definition):
        raise GuardError("Tool definition or server configuration changed")
