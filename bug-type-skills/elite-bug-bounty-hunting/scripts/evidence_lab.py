#!/usr/bin/env python3
"""Offline HTTP evidence comparison and finding-packet construction.

This tool never sends requests, renders HTML, or executes supplied content.
Differences are observations and must not be treated as proof of a vulnerability.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus, urlsplit, urlunsplit

SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
}
SENSITIVE_KEY_TOKENS = {
    "accesstoken",
    "apikey",
    "authorization",
    "clientsecret",
    "clientassertion",
    "cookie",
    "credential",
    "credentials",
    "csrftoken",
    "idtoken",
    "jwt",
    "passwd",
    "password",
    "privatekey",
    "refreshtoken",
    "resettoken",
    "secret",
    "session",
    "sessionid",
    "sessiontoken",
    "token",
}
SENSITIVE_HEADER_TOKENS = {
    "apikey",
    "authtoken",
    "clientassertion",
    "clientsecret",
    "credential",
    "credentials",
    "privatekey",
    "secret",
}
SENSITIVE_URL_PARAM_TOKENS = SENSITIVE_KEY_TOKENS | {
    "assertion",
    "code",
    "oauthcode",
    "samlresponse",
    "sessionstate",
    "state",
}
URL_VALUE_HEADERS = {"content-location", "location"}
MAX_CHUNKS = 10_000
MAX_CHUNK_LINE_BYTES = 8_192
MAX_DECODED_ENTITY_BYTES = 32 * 1024 * 1024
DEFAULT_VOLATILE_HEADERS = {
    "age",
    "date",
    "etag",
    "last-modified",
    "server-timing",
    "traceparent",
    "x-amzn-trace-id",
    "x-request-id",
    "x-runtime",
}
REQUIRED_CASE_FIELDS = {
    "schema_version",
    "case_id",
    "target",
    "feature",
    "scope_snapshot",
    "architecture_evidence",
    "hypothesis",
    "expected_secure_behavior",
    "baseline",
    "one_change",
    "negative_control",
    "reproduction_steps",
    "observations",
    "proven_impact",
    "unverified_follow_ons",
    "stop_condition",
    "remediation_invariant",
    "evidence_files",
}
REQUIRED_SCOPE_FIELDS = {
    "program",
    "policy_url",
    "policy_retrieved_at",
    "authorized_asset",
    "authorization_window",
    "controlled_context",
}


class EvidenceError(ValueError):
    pass


@dataclass
class HttpResponse:
    status_line: str
    status: int
    headers: dict[str, list[str]]
    body: bytes
    sequence_statuses: list[int] = field(default_factory=list)
    selected_sequence_index: int = 0


@dataclass
class SecretLabeler:
    """Assign opaque equality labels without emitting a value or value digest."""

    labels: dict[str, str] = field(default_factory=dict)

    def label(self, value: Any) -> str:
        serialized = value if isinstance(value, str) else json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        if serialized not in self.labels:
            self.labels[serialized] = f"secret-{len(self.labels) + 1:03d}"
        return f"[REDACTED:{self.labels[serialized]}]"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


STATUS_RE = re.compile(br"(?m)^HTTP/\d(?:\.\d)?\s+\d{3}(?:\s[^\r\n]*)?\r?$")
REQUEST_RE = re.compile(br"\A(?:\xef\xbb\xbf)?[A-Z]+\s+\S+\s+HTTP/\d(?:\.\d)?\r?$")


def _header_boundary(raw: bytes, start: int) -> tuple[int, int]:
    crlf = raw.find(b"\r\n\r\n", start)
    lf = raw.find(b"\n\n", start)
    candidates = [(position, size) for position, size in ((crlf, 4), (lf, 2)) if position >= 0]
    if not candidates:
        raise EvidenceError("HTTP message has no header/body separator")
    return min(candidates, key=lambda item: item[0])


def _parse_header_block(block: bytes, *, source: Path) -> tuple[str, dict[str, list[str]]]:
    lines = block.decode("iso-8859-1").replace("\r\n", "\n").split("\n")
    start_line = lines[0].lstrip("\ufeff").strip()
    headers: dict[str, list[str]] = {}
    current: str | None = None
    for line in lines[1:]:
        if line.startswith((" ", "\t")) and current:
            headers[current][-1] += " " + line.strip()
            continue
        if not line or ":" not in line:
            raise EvidenceError(f"malformed HTTP header in {source}: {line!r}")
        name, value = line.split(":", 1)
        current = name.strip().lower()
        if not current:
            raise EvidenceError(f"empty HTTP header name in {source}")
        headers.setdefault(current, []).append(value.strip())
    return start_line, headers


def _content_length(headers: dict[str, list[str]], *, source: Path) -> int | None:
    values = headers.get("content-length", [])
    if not values:
        return None
    normalized = {part.strip() for value in values for part in value.split(",")}
    if len(normalized) != 1:
        raise EvidenceError(f"conflicting Content-Length values in {source}")
    value = next(iter(normalized))
    if not value.isdigit():
        raise EvidenceError(f"invalid Content-Length in {source}")
    return int(value)


def _transfer_codings(headers: dict[str, list[str]]) -> list[str]:
    return [
        coding.strip().lower()
        for value in headers.get("transfer-encoding", [])
        for coding in value.split(",")
        if coding.strip()
    ]


def _read_http_line(raw: bytes, cursor: int, *, source: Path) -> tuple[bytes, int]:
    line_end = raw.find(b"\n", cursor)
    if line_end < 0:
        raise EvidenceError(f"unterminated chunk line in {source}")
    if line_end - cursor > MAX_CHUNK_LINE_BYTES:
        raise EvidenceError(f"chunk line exceeds safety bound in {source}")
    line = raw[cursor:line_end]
    if line.endswith(b"\r"):
        line = line[:-1]
    return line, line_end + 1


def _decode_chunked(raw: bytes, start: int, *, source: Path) -> tuple[bytes, int]:
    """Decode one bounded RFC-style chunked entity and return entity plus wire end."""

    cursor = start
    decoded = bytearray()
    for _ in range(MAX_CHUNKS):
        size_line, cursor = _read_http_line(raw, cursor, source=source)
        size_token = size_line.split(b";", 1)[0].strip()
        if not size_token or not re.fullmatch(br"[0-9A-Fa-f]+", size_token):
            raise EvidenceError(f"invalid chunk size in {source}")
        size = int(size_token, 16)
        if size == 0:
            while True:
                trailer, cursor = _read_http_line(raw, cursor, source=source)
                if not trailer:
                    return bytes(decoded), cursor
                if b":" not in trailer:
                    raise EvidenceError(f"malformed chunk trailer in {source}")
        if len(decoded) + size > MAX_DECODED_ENTITY_BYTES:
            raise EvidenceError(f"decoded chunked entity exceeds safety bound in {source}")
        chunk_end = cursor + size
        if chunk_end > len(raw):
            raise EvidenceError(f"chunk exceeds transcript size in {source}")
        decoded.extend(raw[cursor:chunk_end])
        cursor = chunk_end
        if raw[cursor : cursor + 2] == b"\r\n":
            cursor += 2
        elif raw[cursor : cursor + 1] == b"\n":
            cursor += 1
        else:
            raise EvidenceError(f"chunk is missing its line terminator in {source}")
    raise EvidenceError(f"chunk count exceeds safety bound in {source}")


def _framed_entity(
    raw: bytes,
    start: int,
    headers: dict[str, list[str]],
    *,
    source: Path,
    no_body: bool = False,
) -> tuple[bytes, int, bool]:
    """Return decoded entity, wire end, and whether the message was explicitly framed."""

    length = _content_length(headers, source=source)
    codings = _transfer_codings(headers)
    if codings and length is not None:
        raise EvidenceError(f"ambiguous Content-Length and Transfer-Encoding in {source}")
    if no_body:
        return b"", start, True
    if codings:
        if codings != ["chunked"]:
            raise EvidenceError(f"unsupported Transfer-Encoding framing in {source}")
        entity, wire_end = _decode_chunked(raw, start, source=source)
        return entity, wire_end, True
    if length is None:
        return raw[start:], len(raw), False
    end = start + length
    if end > len(raw):
        raise EvidenceError(f"Content-Length exceeds transcript size in {source}")
    return raw[start:end], end, True


def _request_payload_end(raw: bytes, *, source: Path) -> int:
    first_line_end = raw.find(b"\n")
    if first_line_end < 0 or not REQUEST_RE.match(raw[: first_line_end + 1].rstrip(b"\n")):
        return 0
    boundary, separator = _header_boundary(raw, 0)
    _, headers = _parse_header_block(raw[:boundary], source=source)
    body_start = boundary + separator
    codings = _transfer_codings(headers)
    length = _content_length(headers, source=source)
    if codings or length is not None:
        _, body_end, _ = _framed_entity(raw, body_start, headers, source=source)
        return body_end
    return body_start


def _skip_separators(raw: bytes, cursor: int) -> int:
    while cursor < len(raw) and raw[cursor] in b"\r\n \t":
        cursor += 1
    return cursor


def parse_http_transcript(path: Path) -> HttpResponse:
    """Parse a request/response transcript and select the last framed response.

    Interim responses are retained in sequence metadata. Multiple final responses
    are accepted only when earlier messages have explicit framing, preventing a
    response-looking line inside an unframed body from becoming a new response.
    """

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise EvidenceError(f"cannot read {path}: {exc}") from exc

    cursor = _skip_separators(raw, _request_payload_end(raw, source=path))
    parsed: list[HttpResponse] = []
    while cursor < len(raw):
        match = STATUS_RE.search(raw, cursor)
        if not match:
            break
        # Preamble text may precede a response in exported proxy transcripts.
        start = match.start()
        boundary, separator = _header_boundary(raw, start)
        status_line, headers = _parse_header_block(raw[start:boundary], source=path)
        parts = status_line.split(None, 2)
        if len(parts) < 2 or not parts[1].isdigit():
            cursor = match.end()
            continue
        status = int(parts[1])
        body_start = boundary + separator
        no_body = (100 <= status < 200 and status != 101) or status in {204, 304}
        entity, wire_end, framed = _framed_entity(
            raw, body_start, headers, source=path, no_body=no_body
        )
        parsed.append(HttpResponse(status_line, status, headers, entity))
        cursor = _skip_separators(raw, wire_end)
        if not framed:
            break

    if not parsed:
        raise EvidenceError(f"no HTTP response status line found in {path}")
    selectable = [index for index, item in enumerate(parsed) if not (100 <= item.status < 200 and item.status != 101)]
    selected_index = selectable[-1] if selectable else len(parsed) - 1
    selected = parsed[selected_index]
    selected.sequence_statuses = [item.status for item in parsed]
    selected.selected_sequence_index = selected_index
    return selected


def _sensitive_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    return any(normalized == token or normalized.endswith(token) for token in SENSITIVE_KEY_TOKENS)


def _sensitive_header(name: str) -> bool:
    if name in SENSITIVE_HEADERS:
        return True
    normalized = re.sub(r"[^a-z0-9]", "", name.lower())
    return any(
        normalized == token or normalized.endswith(token)
        for token in SENSITIVE_HEADER_TOKENS
    )


def _sensitive_url_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", unquote_plus(key).lower())
    return any(
        normalized == token or normalized.endswith(token)
        for token in SENSITIVE_URL_PARAM_TOKENS
    )


def _redact_url_parameters(component: str, labeler: SecretLabeler) -> str:
    def replace(match: re.Match[str]) -> str:
        if not _sensitive_url_key(match.group("key")):
            return match.group(0)
        return (
            f"{match.group('prefix')}{match.group('key')}="
            f"{labeler.label(match.group('value'))}"
        )

    return re.sub(
        r"(?P<prefix>^|[&;])(?P<key>[^=&;]+)=(?P<value>[^&;]*)",
        replace,
        component,
    )


def _redact_url(value: str, labeler: SecretLabeler) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "[REDACTED:malformed-url]"
    netloc = parsed.netloc
    if "@" in netloc:
        userinfo, hostinfo = netloc.rsplit("@", 1)
        username, separator, password = userinfo.partition(":")
        safe_userinfo = (
            f"{username}:{labeler.label(password)}" if separator else labeler.label(userinfo)
        )
        netloc = f"{safe_userinfo}@{hostinfo}"
    return urlunsplit(
        (
            parsed.scheme,
            netloc,
            parsed.path,
            _redact_url_parameters(parsed.query, labeler),
            _redact_url_parameters(parsed.fragment, labeler),
        )
    )


def _redact_urls_in_text(value: str, labeler: SecretLabeler) -> str:
    pattern = re.compile(r"(?P<url>(?:https?://|/)[^\s\"'<>]*[?#][^\s\"'<>]+)", re.I)
    return pattern.sub(lambda match: _redact_url(match.group("url"), labeler), value)


def _redact_cookie(value: str, labeler: SecretLabeler, *, set_cookie: bool) -> str:
    parts = [part.strip() for part in value.split(";")]
    output: list[str] = []
    for index, part in enumerate(parts):
        if "=" not in part:
            output.append(part)
            continue
        name, secret = part.split("=", 1)
        # Set-Cookie attributes remain useful evidence. Cookie request fields are
        # all credentials and are therefore labelled, not emitted.
        if set_cookie and index > 0:
            output.append(f"{name}={secret}")
        else:
            output.append(f"{name}={labeler.label(secret)}")
    return "; ".join(output)


def _redact_header_value(name: str, value: str, labeler: SecretLabeler) -> str:
    if name == "set-cookie":
        return _redact_cookie(value, labeler, set_cookie=True)
    if name == "cookie":
        return _redact_cookie(value, labeler, set_cookie=False)
    if name in {"authorization", "proxy-authorization"}:
        scheme, separator, credential = value.partition(" ")
        return f"{scheme} {labeler.label(credential)}" if separator else labeler.label(value)
    return labeler.label(value)


def _redact_nonsecret_header(name: str, value: str, labeler: SecretLabeler) -> str:
    if name in URL_VALUE_HEADERS:
        return _redact_url(value, labeler)
    if name == "link":
        return re.sub(
            r"<([^>]*)>",
            lambda match: f"<{_redact_url(match.group(1), labeler)}>",
            value,
        )
    if name == "refresh":
        return re.sub(
            r"(?i)(\burl\s*=\s*)(.+)$",
            lambda match: f"{match.group(1)}{_redact_url(match.group(2).strip(), labeler)}",
            value,
        )
    return value


def _redacted_headers(
    headers: dict[str, list[str]], volatile: set[str], labeler: SecretLabeler
) -> dict[str, list[str]]:
    output: dict[str, list[str]] = {}
    for name in sorted(headers):
        if name in volatile:
            continue
        output[name] = [
            _redact_header_value(name, value, labeler)
            if _sensitive_header(name)
            else _redact_nonsecret_header(name, value, labeler)
            for value in headers[name]
        ]
    return output


def _redact_json(
    value: Any,
    labeler: SecretLabeler,
    *,
    path: str = "$",
    sensitive_fields: list[dict[str, str]] | None = None,
) -> Any:
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in sorted(value.items()):
            child_path = f"{path}.{key}"
            if _sensitive_key(key):
                label = labeler.label(item)
                output[key] = label
                if sensitive_fields is not None:
                    sensitive_fields.append({"path": child_path, "label": label})
            else:
                output[key] = _redact_json(
                    item, labeler, path=child_path, sensitive_fields=sensitive_fields
                )
        return output
    if isinstance(value, list):
        return [
            _redact_json(
                item,
                labeler,
                path=f"{path}[{index}]",
                sensitive_fields=sensitive_fields,
            )
            for index, item in enumerate(value)
        ]
    if isinstance(value, str):
        return redact_text(value, labeler=labeler)
    return value


def _json_summary(response: HttpResponse, labeler: SecretLabeler) -> dict[str, Any] | None:
    content_type = ",".join(response.headers.get("content-type", [])).lower()
    if "json" not in content_type:
        return None
    try:
        value = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"valid": False}
    sensitive_fields: list[dict[str, str]] = []
    redacted = _redact_json(value, labeler, sensitive_fields=sensitive_fields)
    canonical = json.dumps(redacted, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return {
        "valid": True,
        "type": type(redacted).__name__,
        "canonical_sha256": sha256_bytes(canonical.encode("utf-8")),
        "sensitive_fields": sensitive_fields,
    }


def summarize_response(
    response: HttpResponse,
    *,
    marker: bytes | None,
    volatile: set[str],
    labeler: SecretLabeler,
    include_body: bool = False,
    max_body_bytes: int = 512,
) -> dict[str, Any]:
    json_summary = _json_summary(response, labeler)
    summary: dict[str, Any] = {
        "status": response.status,
        "status_line": response.status_line,
        "response_sequence": {
            "statuses": response.sequence_statuses or [response.status],
            "selected_index": response.selected_sequence_index,
        },
        "headers": _redacted_headers(response.headers, volatile, labeler),
        "body_length": len(response.body),
        "body_sha256": sha256_bytes(response.body),
        "json": json_summary,
    }
    if marker:
        positions: list[int] = []
        start = 0
        while True:
            index = response.body.find(marker, start)
            if index < 0:
                break
            positions.append(index)
            start = index + max(1, len(marker))
        summary["marker"] = {"count": len(positions), "positions": positions[:20]}
    if include_body:
        content_type = ",".join(response.headers.get("content-type", [])).lower()
        if "json" in content_type:
            try:
                parsed = json.loads(response.body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                summary["body_excerpt"] = "[OMITTED: invalid JSON cannot be safely redacted]"
                summary["body_excerpt_truncated"] = True
            else:
                safe_body = json.dumps(
                    _redact_json(parsed, labeler),
                    sort_keys=True,
                    ensure_ascii=False,
                )
                summary["body_excerpt"] = safe_body[:max_body_bytes]
                summary["body_excerpt_truncated"] = len(safe_body) > max_body_bytes
        else:
            excerpt = response.body[:max_body_bytes].decode("utf-8", errors="replace")
            summary["body_excerpt"] = redact_text(excerpt, labeler=labeler)
            summary["body_excerpt_truncated"] = len(response.body) > max_body_bytes
    return summary


def _differences(left: dict[str, Any], right: dict[str, Any]) -> list[str]:
    differences: list[str] = []
    for field in ("status", "response_sequence", "headers", "marker"):
        if left.get(field) != right.get(field):
            differences.append(field)
    left_json = left.get("json")
    right_json = right.get("json")
    if left_json != right_json:
        differences.append("json")
    same_valid_json = (
        isinstance(left_json, dict)
        and isinstance(right_json, dict)
        and left_json.get("valid") is True
        and right_json.get("valid") is True
        and left_json.get("canonical_sha256") == right_json.get("canonical_sha256")
    )
    if not same_valid_json:
        for field in ("body_length", "body_sha256"):
            if left.get(field) != right.get(field):
                differences.append(field)
    return differences


def compare_transcripts(
    baseline_path: Path,
    mutation_path: Path,
    negative_path: Path,
    *,
    marker: str | None = None,
    volatile_headers: set[str] | None = None,
    retained_headers: set[str] | None = None,
    include_body: bool = False,
    max_body_bytes: int = 512,
) -> dict[str, Any]:
    volatile = set(DEFAULT_VOLATILE_HEADERS)
    if volatile_headers:
        volatile.update(x.lower() for x in volatile_headers)
    if retained_headers:
        volatile.difference_update(x.lower() for x in retained_headers)
    labeler = SecretLabeler()
    marker_bytes = marker.encode("utf-8") if marker else None
    summaries = {
        "baseline": summarize_response(
            parse_http_transcript(baseline_path),
            marker=marker_bytes,
            volatile=volatile,
            labeler=labeler,
            include_body=include_body,
            max_body_bytes=max_body_bytes,
        ),
        "mutation": summarize_response(
            parse_http_transcript(mutation_path),
            marker=marker_bytes,
            volatile=volatile,
            labeler=labeler,
            include_body=include_body,
            max_body_bytes=max_body_bytes,
        ),
        "negative_control": summarize_response(
            parse_http_transcript(negative_path),
            marker=marker_bytes,
            volatile=volatile,
            labeler=labeler,
            include_body=include_body,
            max_body_bytes=max_body_bytes,
        ),
    }
    return {
        "schema_version": "2",
        "notice": "Differences are observations only; this tool does not prove exploitability.",
        "responses": summaries,
        "differences": {
            "baseline_to_mutation": _differences(summaries["baseline"], summaries["mutation"]),
            "negative_to_mutation": _differences(summaries["negative_control"], summaries["mutation"]),
        },
    }


def redact_text(value: str, *, labeler: SecretLabeler | None = None) -> str:
    """Best-effort text redaction with opaque labels stable for one operation."""

    labels = labeler or SecretLabeler()

    def header_replacement(match: re.Match[str]) -> str:
        name = match.group("name")
        lowered = name.lower()
        if _sensitive_header(lowered):
            safe_value = _redact_header_value(lowered, match.group("value"), labels)
        else:
            safe_value = _redact_nonsecret_header(lowered, match.group("value"), labels)
        return f"{name}{match.group('separator')}{safe_value}"

    value = re.sub(
        r"(?im)^(?P<name>[a-z][a-z0-9-]*)"
        r"(?P<separator>\s*:\s*)(?P<value>[^\r\n]*)$",
        header_replacement,
        value,
    )

    def json_string_replacement(match: re.Match[str]) -> str:
        if not _sensitive_key(match.group("key")):
            return match.group(0)
        return f"{match.group('prefix')}{labels.label(match.group('value'))}\""

    value = re.sub(
        r'(?P<prefix>"(?P<key>[^"\\]+)"\s*:\s*")(?P<value>(?:\\.|[^"\\])*)"',
        json_string_replacement,
        value,
    )

    def assignment_replacement(match: re.Match[str]) -> str:
        if not _sensitive_key(match.group("key")):
            return match.group(0)
        return f"{match.group('key')}{match.group('separator')}{labels.label(match.group('value'))}"

    value = re.sub(
        r"(?i)\b(?P<key>[a-z][a-z0-9_.-]*)(?P<separator>\s*=\s*)(?P<value>[^&\s;,]+)",
        assignment_replacement,
        value,
    )
    value = re.sub(
        r"(?i)\bBearer\s+(?P<value>[A-Za-z0-9._~+\-/]+=*)",
        lambda match: f"Bearer {labels.label(match.group('value'))}",
        value,
    )
    return _redact_urls_in_text(value, labels)


def _safe_evidence_path(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise EvidenceError(f"evidence path must be relative: {relative!r}")
    if ".." in Path(relative).parts:
        raise EvidenceError(f"evidence path contains traversal: {relative!r}")
    resolved_root = root.resolve(strict=True)
    candidate = (resolved_root / relative).resolve(strict=True)
    try:
        candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise EvidenceError(f"evidence path escapes root: {relative!r}") from exc
    if not candidate.is_file():
        raise EvidenceError(f"evidence path is not a file: {relative!r}")
    return candidate


def validate_case(case: Any) -> dict[str, Any]:
    if not isinstance(case, dict):
        raise EvidenceError("case must be a JSON object")
    if case.get("schema_version") == "1":
        raise EvidenceError(
            "case.schema_version '1' is obsolete; migrate to '2' and add "
            "scope_snapshot, architecture_evidence, and reproduction_steps"
        )
    if case.get("schema_version") != "2":
        raise EvidenceError("case.schema_version must be '2'")
    missing = sorted(REQUIRED_CASE_FIELDS - set(case))
    if missing:
        raise EvidenceError("case is missing required fields: " + ", ".join(missing))
    scope = case["scope_snapshot"]
    if not isinstance(scope, dict):
        raise EvidenceError("case.scope_snapshot must be an object")
    missing_scope = sorted(REQUIRED_SCOPE_FIELDS - set(scope))
    if missing_scope:
        raise EvidenceError(
            "case.scope_snapshot is missing required fields: " + ", ".join(missing_scope)
        )
    for field_name in sorted(REQUIRED_SCOPE_FIELDS):
        if not isinstance(scope[field_name], str) or not scope[field_name].strip():
            raise EvidenceError(f"case.scope_snapshot.{field_name} must be a non-empty string")
    for field in (
        "case_id",
        "target",
        "feature",
        "hypothesis",
        "expected_secure_behavior",
        "baseline",
        "one_change",
        "negative_control",
        "stop_condition",
        "remediation_invariant",
    ):
        if not isinstance(case[field], str) or not case[field].strip():
            raise EvidenceError(f"case.{field} must be a non-empty string")
    for field in (
        "architecture_evidence",
        "reproduction_steps",
        "observations",
        "proven_impact",
        "unverified_follow_ons",
        "evidence_files",
    ):
        if not isinstance(case[field], list) or not all(isinstance(x, str) and x.strip() for x in case[field]):
            raise EvidenceError(f"case.{field} must be a string list")
    for field in ("architecture_evidence", "reproduction_steps", "evidence_files"):
        if not case[field]:
            raise EvidenceError(f"case.{field} must not be empty")
    return case


def _md(value: str, labeler: SecretLabeler | None = None) -> str:
    return redact_text(value.strip(), labeler=labeler).replace("\r", " ")


def _bullet_list(
    values: list[str], labeler: SecretLabeler, empty: str = "None recorded."
) -> list[str]:
    return [f"- {_md(value, labeler)}" for value in values] if values else [empty]


def build_packet(case: dict[str, Any], evidence_root: Path) -> str:
    validate_case(case)
    labeler = SecretLabeler()
    evidence: list[tuple[str, str, int]] = []
    for relative in case["evidence_files"]:
        path = _safe_evidence_path(evidence_root, relative)
        data = path.read_bytes()
        evidence.append((relative, sha256_bytes(data), len(data)))
    lines = [
        f"# Finding Evidence Packet: {_md(case['case_id'], labeler)}",
        "",
        "> This packet separates demonstrated evidence from unverified follow-ons. It does not create testing authorization.",
        "",
        "## Target and feature",
        "",
        f"- Target: {_md(case['target'], labeler)}",
        f"- Feature: {_md(case['feature'], labeler)}",
        "",
        "## Scope snapshot",
        "",
        f"- Program: {_md(case['scope_snapshot']['program'], labeler)}",
        f"- Policy: {_md(case['scope_snapshot']['policy_url'], labeler)}",
        f"- Policy retrieved: {_md(case['scope_snapshot']['policy_retrieved_at'], labeler)}",
        f"- Authorized asset: {_md(case['scope_snapshot']['authorized_asset'], labeler)}",
        f"- Authorization window: {_md(case['scope_snapshot']['authorization_window'], labeler)}",
        f"- Controlled context: {_md(case['scope_snapshot']['controlled_context'], labeler)}",
        "",
        "## Architecture evidence",
        "",
        *_bullet_list(case["architecture_evidence"], labeler),
        "",
        "## Falsifiable hypothesis",
        "",
        _md(case["hypothesis"], labeler),
        "",
        "## Expected secure behavior",
        "",
        _md(case["expected_secure_behavior"], labeler),
        "",
        "## Controlled experiment",
        "",
        f"- Baseline: {_md(case['baseline'], labeler)}",
        f"- One change: {_md(case['one_change'], labeler)}",
        f"- Negative control: {_md(case['negative_control'], labeler)}",
        "",
        "## Reproduction steps",
        "",
        *[
            f"{index}. {_md(step, labeler)}"
            for index, step in enumerate(case["reproduction_steps"], start=1)
        ],
        "",
        "## Observations",
        "",
        *_bullet_list(case["observations"], labeler),
        "",
        "## Proven impact",
        "",
        *_bullet_list(case["proven_impact"], labeler),
        "",
        "## Unverified follow-ons",
        "",
        *_bullet_list(case["unverified_follow_ons"], labeler),
        "",
        "## Evidence inventory",
        "",
    ]
    for relative, digest, size in evidence:
        lines.append(f"- `{_md(relative, labeler)}` — {size} bytes — SHA-256 `{digest}`")
    lines.extend(
        [
            "",
            "## Safety stop",
            "",
            _md(case["stop_condition"], labeler),
            "",
            "## Remediation invariant",
            "",
            _md(case["remediation_invariant"], labeler),
            "",
        ]
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version="evidence_lab 2.0")
    sub = parser.add_subparsers(dest="command", required=True)
    diff = sub.add_parser("diff-http", help="compare three saved HTTP transcripts")
    diff.add_argument("--baseline", type=Path, required=True)
    diff.add_argument("--mutation", type=Path, required=True)
    diff.add_argument("--negative-control", type=Path, required=True)
    diff.add_argument("--marker")
    diff.add_argument("--ignore-header", action="append", default=[])
    diff.add_argument(
        "--keep-header",
        action="append",
        default=[],
        help="retain a normally volatile header such as Age, ETag, or X-Request-ID",
    )
    diff.add_argument("--include-body", action="store_true")
    diff.add_argument("--max-body-bytes", type=int, default=512)
    diff.add_argument("--out", type=Path)
    packet = sub.add_parser("packet", help="build a Markdown evidence packet")
    packet.add_argument("case", type=Path)
    packet.add_argument("--evidence-root", type=Path, required=True)
    packet.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "diff-http":
            if args.max_body_bytes < 1 or args.max_body_bytes > 4096:
                raise EvidenceError("max-body-bytes must be between 1 and 4096")
            result = compare_transcripts(
                args.baseline,
                args.mutation,
                args.negative_control,
                marker=args.marker,
                volatile_headers=set(args.ignore_header),
                retained_headers=set(args.keep_header),
                include_body=args.include_body,
                max_body_bytes=args.max_body_bytes,
            )
            rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
            if args.out:
                args.out.write_text(rendered, encoding="utf-8")
            else:
                sys.stdout.write(rendered)
        else:
            with args.case.open("r", encoding="utf-8") as handle:
                case = json.load(handle)
            packet = build_packet(validate_case(case), args.evidence_root)
            args.out.write_text(packet, encoding="utf-8")
        return 0
    except (OSError, json.JSONDecodeError, EvidenceError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
