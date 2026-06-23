"""Artifact redaction and Kite finding validation helpers."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

SEVERITIES = {"informational", "low", "medium", "high", "critical"}
CONFIDENCES = {"low", "medium", "high"}
TRACE_KINDS = {"entrypoint", "propagation", "sink"}
CONDITION_KINDS = {
    "authentication_level",
    "authorization_role",
    "user_interaction",
    "system_configuration",
    "network_routing",
    "environmental_dependency",
    "data_state",
    "timing_dependency",
    "third_party_dependency",
}


def _luhn(digits: str) -> bool:
    total = 0
    double = False
    for char in reversed(digits):
        value = int(char)
        if double:
            value *= 2
            if value > 9:
                value -= 9
        total += value
        double = not double
    return total % 10 == 0


def _known_card_network(digits: str) -> bool:
    size = len(digits)
    if not 12 <= size <= 19:
        return False
    prefix1 = digits[0]
    prefix2 = int(digits[:2])
    prefix3 = int(digits[:3]) if size >= 3 else -1
    prefix4 = int(digits[:4]) if size >= 4 else -1
    return bool(
        (size == 15 and prefix2 in {34, 37})
        or (prefix1 == "4" and 13 <= size <= 19)
        or (size == 16 and (51 <= prefix2 <= 55 or 2221 <= prefix4 <= 2720))
        or (16 <= size <= 19 and (prefix4 == 6011 or prefix2 == 65 or 644 <= prefix3 <= 649))
        or (16 <= size <= 19 and 3528 <= prefix4 <= 3589)
        or (16 <= size <= 19 and prefix2 == 62)
        or (14 <= size <= 19 and prefix2 == 36)
        or (12 <= size <= 19 and prefix4 in {5018, 5020, 5038, 5893, 6304, 6759, 6761, 6762, 6763})
        or (size == 16 and (prefix3 == 508 or prefix2 in {81, 82}))
    )


def _valid_ssn(digits: str) -> bool:
    area = int(digits[:3])
    group = int(digits[3:5])
    serial = int(digits[5:])
    return area not in {0, 666} and group != 0 and serial != 0


def _bearer_like(match: re.Match[str]) -> bool:
    value = match.group("value")
    return any(not char.isalpha() for char in value)


_PLACEHOLDER_RE = re.compile(
    r"(?i)\$\{?[A-Z0-9_.]+}?|%[A-Z0-9_]+%|<[^>]+>|\*{3,}|x{3,}|"
    r"\[?redacted]?|\[redacted-[a-z0-9-]+]|null|none|true|false|"
    r"changeme|your[_-]?\w+|placeholder|example"
)
_SECRET_CODE_SHAPE_RE = re.compile(r"^\(|^[A-Za-z_]\w*\(|^[A-Za-z_]\w*\.\w")

_REDACTION_PATTERNS: tuple[
    tuple[str, re.Pattern[str], Any],
    ...,
] = (
    (
        "PAN",
        re.compile(r"(?<![0-9A-Za-z./_-])(?:\d[\s\-]?){12,18}\d(?![0-9A-Za-z./_-])"),
        lambda match: (lambda digits: _known_card_network(digits) and _luhn(digits))(
            re.sub(r"\D", "", match.group(0))
        ),
    ),
    (
        "CVV",
        re.compile(r"(?i)\b(cvv2?|cvc2?|cid|csc)\b\s*[:=]?\s*\"?(\d{3,4})\"?"),
        None,
    ),
    ("TRACK", re.compile(r"%B\d{12,19}\^[^?]{2,90}\?"), None),
    (
        "SSN",
        re.compile(
            r"(?<!\d)(\d{3})[-.\t \u00a0\u2009\u202f\u2007]"
            r"(\d{2})[-.\t \u00a0\u2009\u202f\u2007](\d{4})(?!\d)"
        ),
        lambda match: _valid_ssn(match.group(1) + match.group(2) + match.group(3)),
    ),
    (
        "SSN-CTX",
        re.compile(
            r"(?i)\b(ssn|social[\s_-]*sec(?:urity)?(?:[\s_-]*(?:no|num|number))?"
            r"|itin|tin|taxpayer[\s_-]*id)\b['\"]?\s*[:=#-]?\s*['\"]?"
            r"(?<!\d)(\d{9})(?!\d)"
        ),
        lambda match: _valid_ssn(match.group(2)),
    ),
    ("AWS-KEY", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b"), None),
    (
        "GITHUB-TOKEN",
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9]{59})\b"
        ),
        None,
    ),
    ("SLACK-TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b"), None),
    ("STRIPE-KEY", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,99}\b"), None),
    ("GOOGLE-API-KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), None),
    ("AZURE-SAS", re.compile(r"(?i)\bsig=[0-9A-Za-z%+/=]{20,}\b"), None),
    ("TWILIO-KEY", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), None),
    (
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        None,
    ),
    (
        "BEARER",
        re.compile(r"(?i)\b(?:Bearer|Basic)\s+(?P<value>[A-Za-z0-9+/=._-]{8,})\b"),
        _bearer_like,
    ),
    ("URL-CRED", re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+:)([^\s/@]{1,256})@"), None),
    (
        "PRIVATE-KEY",
        re.compile(r"-{5}BEGIN [A-Z ]*PRIVATE KEY-{5}[\s\S]*?-{5}END [A-Z ]*PRIVATE KEY-{5}"),
        None,
    ),
    (
        "SECRET",
        re.compile(
            r"(?i)(?:\b|(?<=[a-z]))(pass(?:word|wd)?|pwd|secret|api[_-]?key|access[_-]?key"
            r"|client[_-]?secret|auth[_-]?token|token|credential)s?\b"
            r"['\"`]?\s*[:=]\s*(?P<quote>['\"`]?)(?P<value>[^\s'\"`,;\x00]{6,256})(?P=quote)"
        ),
        None,
    ),
)


def redact_counts(text: str) -> tuple[str, dict[str, int]]:
    """Return text with likely secrets/PII masked and per-label hit counts."""
    if not text:
        return text, {}
    if "\x00" in text:
        text = text.replace("\x00", "")

    counts: dict[str, int] = {}
    placeholders: list[str] = []

    def mask(label: str) -> str:
        counts[label] = counts.get(label, 0) + 1
        placeholders.append(f"[REDACTED-{label}]")
        return f"\x00{len(placeholders) - 1}\x00"

    redacted = text
    for label, pattern, validator in _REDACTION_PATTERNS:

        def replace(match: re.Match[str], *, label: str = label, validator: Any = validator) -> str:
            if validator is not None and not validator(match):
                return match.group(0)
            if label == "SECRET":
                return _redact_secret_assignment(match, mask(label))
            if label == "CVV":
                return match.group(0)[: match.start(2) - match.start(0)] + mask(label)
            if label == "SSN-CTX":
                return match.group(0)[: match.start(2) - match.start(0)] + mask("SSN")
            if label == "URL-CRED":
                return match.group(1) + mask(label) + "@"
            return mask(label)

        redacted = pattern.sub(replace, redacted)

    if placeholders:

        def reinsert(match: re.Match[str]) -> str:
            index = int(match.group(1))
            return placeholders[index] if 0 <= index < len(placeholders) else match.group(0)

        redacted = re.sub(r"\x00(\d+)\x00", reinsert, redacted)
    return redacted, counts


def _redact_secret_assignment(match: re.Match[str], replacement: str) -> str:
    value = match.group("value")
    quoted = bool(match.group("quote"))
    value_core = value if quoted else value.rstrip(").}]!?>") or value
    keyword = re.sub(r"[^a-z]", "", match.group(1).lower())
    strong = {"password", "passwd", "pwd", "apikey", "accesskey", "clientsecret", "authtoken"}
    generic_unquoted = keyword not in strong and not quoted
    if generic_unquoted and value_core.isalpha() and value_core.islower() and len(value_core) < 20:
        return match.group(0)
    if generic_unquoted and _SECRET_CODE_SHAPE_RE.match(value_core):
        return match.group(0)
    if _PLACEHOLDER_RE.fullmatch(value_core):
        return match.group(0)
    head = match.group(0)[: match.start("value") - match.start(0)]
    tail = value[len(value_core) :] + match.group(0)[match.end("value") - match.start(0) :]
    return head + replacement + tail


def redact(text: str) -> str:
    """Return text with likely sensitive values masked."""
    return redact_counts(text)[0]


def redact_tree(value: Any) -> Any:
    """Recursively redact string leaves in a JSON-like object."""
    if isinstance(value, dict):
        return {key: redact_tree(child) for key, child in value.items()}
    if isinstance(value, list):
        return [redact_tree(child) for child in value]
    if isinstance(value, str):
        return redact(value)
    return value


def redact_artifact_bytes(name: str, data: bytes) -> tuple[bytes, dict[str, int]]:
    """Redact a canonical text/JSON artifact and return updated bytes/counts."""
    if name.endswith(".json") or name.endswith(".sarif"):
        try:
            parsed = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            text, counts = redact_counts(data.decode("utf-8", errors="replace"))
            return (text + ("\n" if not text.endswith("\n") else "")).encode(), counts
        redacted = redact_tree(parsed)
        rendered = json.dumps(redacted, indent=2, sort_keys=True) + "\n"
        original_text = data.decode("utf-8", errors="replace")
        _, counts = redact_counts(original_text)
        return rendered.encode(), counts
    text, counts = redact_counts(data.decode("utf-8", errors="replace"))
    return (text + ("\n" if not text.endswith("\n") else "")).encode(), counts


def validate_findings_document(document: Any) -> list[str]:
    """Validate Kite's portable findings contract.

    The validator intentionally returns errors instead of raising so callers can
    record non-conforming upstream scanner output without failing artifact upload.
    """
    findings = _findings_list(document)
    if findings is None:
        return ["document must be a findings array or an object with a findings array"]
    errors: list[str] = []
    for index, finding in enumerate(findings):
        path = f"findings[{index}]"
        if not isinstance(finding, Mapping):
            errors.append(f"{path}: expected object")
            continue
        verdict = finding.get("verdict")
        if verdict == "confirmed":
            _validate_confirmed(finding, path, errors)
        elif verdict == "rejected":
            if not isinstance(finding.get("reason"), str) or not finding["reason"].strip():
                errors.append(f"{path}.reason: required non-empty string")
        else:
            errors.append(f"{path}.verdict: expected 'confirmed' or 'rejected'")
    return errors


def _findings_list(document: Any) -> list[Any] | None:
    if isinstance(document, list):
        return document
    if isinstance(document, Mapping) and isinstance(document.get("findings"), list):
        return document["findings"]
    return None


def _validate_confirmed(finding: Mapping[str, Any], path: str, errors: list[str]) -> None:
    for key in ("title", "description", "root_cause", "intended_behavior"):
        _require_non_empty_string(finding, key, f"{path}.{key}", errors)
    _validate_trace(finding.get("trace"), f"{path}.trace", errors)
    _validate_conditions(finding.get("conditions"), f"{path}.conditions", errors)
    _validate_execution(finding.get("execution"), f"{path}.execution", errors)
    _validate_remediation(finding.get("remediation"), f"{path}.remediation", errors)
    _validate_severity(finding.get("severity"), f"{path}.severity", errors)
    _validate_confidence(finding.get("confidence"), f"{path}.confidence", errors)
    if "atlas_mapping" in finding:
        _validate_atlas_mapping(finding["atlas_mapping"], f"{path}.atlas_mapping", errors)


def _require_non_empty_string(
    obj: Mapping[str, Any], key: str, path: str, errors: list[str]
) -> None:
    if not isinstance(obj.get(key), str) or not obj[key].strip():
        errors.append(f"{path}: required non-empty string")


def _validate_trace(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, list) or len(value) < 2:
        errors.append(f"{path}: must contain at least entrypoint and sink steps")
        return
    for index, step in enumerate(value):
        step_path = f"{path}[{index}]"
        if not isinstance(step, Mapping):
            errors.append(f"{step_path}: expected object")
            continue
        if step.get("kind") not in TRACE_KINDS:
            errors.append(f"{step_path}.kind: expected one of {sorted(TRACE_KINDS)}")
        for key in ("file", "scope", "description"):
            _require_non_empty_string(step, key, f"{step_path}.{key}", errors)
        if not isinstance(step.get("line"), int) or step["line"] < 1:
            errors.append(f"{step_path}.line: expected positive integer")
    if isinstance(value[0], Mapping) and value[0].get("kind") != "entrypoint":
        errors.append(f"{path}[0].kind: must be 'entrypoint'")
    if isinstance(value[-1], Mapping) and value[-1].get("kind") != "sink":
        errors.append(f"{path}[-1].kind: must be 'sink'")


def _validate_conditions(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, list):
        errors.append(f"{path}: required array")
        return
    for index, condition in enumerate(value):
        cond_path = f"{path}[{index}]"
        if not isinstance(condition, Mapping):
            errors.append(f"{cond_path}: expected object")
            continue
        if condition.get("kind") not in CONDITION_KINDS:
            errors.append(f"{cond_path}.kind: expected one of {sorted(CONDITION_KINDS)}")
        _require_non_empty_string(condition, "description", f"{cond_path}.description", errors)


def _validate_execution(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, Mapping):
        errors.append(f"{path}: required object")
        return
    _require_non_empty_string(value, "attacker_perspective", f"{path}.attacker_perspective", errors)
    _require_string_list(value.get("payloads"), f"{path}.payloads", errors)
    _require_string_list(value.get("instructions"), f"{path}.instructions", errors)
    _require_non_empty_string(value, "expected_result", f"{path}.expected_result", errors)


def _validate_remediation(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, Mapping):
        errors.append(f"{path}: required object")
        return
    _require_non_empty_string(value, "strategy", f"{path}.strategy", errors)
    changes = value.get("code_changes", [])
    if changes is None:
        return
    if not isinstance(changes, list):
        errors.append(f"{path}.code_changes: expected array")
        return
    for index, change in enumerate(changes):
        change_path = f"{path}.code_changes[{index}]"
        if not isinstance(change, Mapping):
            errors.append(f"{change_path}: expected object")
            continue
        _require_non_empty_string(change, "file_name", f"{change_path}.file_name", errors)
        _require_non_empty_string(change, "fixed_code", f"{change_path}.fixed_code", errors)


def _validate_severity(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, Mapping):
        errors.append(f"{path}: required object")
        return
    for axis in ("likelihood", "impact"):
        axis_value = value.get(axis)
        axis_path = f"{path}.{axis}"
        if not isinstance(axis_value, Mapping):
            errors.append(f"{axis_path}: required object")
            continue
        if axis_value.get("score") not in SEVERITIES:
            errors.append(f"{axis_path}.score: expected one of {sorted(SEVERITIES)}")
        _require_non_empty_string(axis_value, "reason", f"{axis_path}.reason", errors)
    if value.get("overall_severity") not in SEVERITIES:
        errors.append(f"{path}.overall_severity: expected one of {sorted(SEVERITIES)}")


def _validate_confidence(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, Mapping):
        errors.append(f"{path}: required object")
        return
    if value.get("score") not in CONFIDENCES:
        errors.append(f"{path}.score: expected one of {sorted(CONFIDENCES)}")
    _require_non_empty_string(value, "reason", f"{path}.reason", errors)


def _validate_atlas_mapping(value: Any, path: str, errors: list[str]) -> None:
    if value == "not assigned":
        return
    if not isinstance(value, Mapping):
        errors.append(f"{path}: expected object or 'not assigned'")
        return
    ids = value.get("technique_ids", [])
    if not isinstance(ids, list) or not all(isinstance(item, str) for item in ids):
        errors.append(f"{path}.technique_ids: expected string array")
    for technique_id in ids:
        if not re.fullmatch(r"AML\.T\d{4}(?:\.\d{3})?", technique_id):
            errors.append(f"{path}.technique_ids: invalid AML technique id {technique_id!r}")
    tactic_ids = value.get("tactic_ids", [])
    if not isinstance(tactic_ids, list) or not all(isinstance(item, str) for item in tactic_ids):
        errors.append(f"{path}.tactic_ids: expected string array")
    for tactic_id in tactic_ids:
        if not re.fullmatch(r"AML\.TA\d{4}", tactic_id):
            errors.append(f"{path}.tactic_ids: invalid AML tactic id {tactic_id!r}")


def _require_string_list(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        errors.append(f"{path}: expected non-empty string array")
