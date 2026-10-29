#!/usr/bin/env python3
"""Validate a declared bug-bounty scope ledger without performing network I/O.

This tool records and checks authorization supplied by the researcher. It does
not create authorization, discover scope, or contact a target.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import posixpath
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit

SCHEMA_VERSION = "2"
ALLOWED_KINDS = {"host", "url-prefix", "cidr"}
MAX_POLICY_AGE_DAYS = 90
MAX_FUTURE_CLOCK_SKEW = timedelta(minutes=5)
_BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
_DECODED_PATH_DELIMITERS = {"/", "\\", "?", "#"}


class LedgerError(ValueError):
    pass


def _parse_time(value: str, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise LedgerError(f"{field} must be a non-empty ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LedgerError(f"{field} is not valid ISO-8601: {value!r}") from exc
    if parsed.tzinfo is None:
        raise LedgerError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def canonical_host(value: str, *, allow_wildcard: bool = False) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LedgerError("host must be a non-empty string")
    host = value.strip().rstrip(".").lower()
    wildcard = host.startswith("*.")
    if wildcard:
        if not allow_wildcard:
            raise LedgerError("wildcards are allowed only in declared host rules")
        host = host[2:]
    if "*" in host or "/" in host or ":" in host:
        raise LedgerError(f"invalid host rule: {value!r}")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise LedgerError(f"invalid internationalized host: {value!r}") from exc
    if not host or "." not in host:
        raise LedgerError(f"ambiguous host rule: {value!r}")
    return f"*.{host}" if wildcard else host


def _normalized_path(path: str) -> str:
    """Return one unambiguous semantic path or reject it.

    Scope checks should never guess how a CDN, proxy, framework, and origin will
    decode a path. Encoded separators, nested encodings, dot segments, control
    characters, and duplicate separators therefore fail closed.
    """

    path = path or "/"
    if _BAD_PERCENT.search(path):
        raise LedgerError("URL path contains malformed percent encoding")
    if "\\" in path or "//" in path or any(ord(char) < 0x20 or ord(char) == 0x7F for char in path):
        raise LedgerError("URL path contains an ambiguous separator or control character")

    current = path
    for _ in range(5):
        try:
            decoded = unquote(current, errors="strict")
        except UnicodeDecodeError as exc:
            raise LedgerError("URL path contains invalid UTF-8 percent encoding") from exc
        if decoded == current:
            break
        for delimiter in _DECODED_PATH_DELIMITERS:
            if decoded.count(delimiter) != current.count(delimiter):
                raise LedgerError("URL path contains an encoded delimiter")
        current = decoded
        if _BAD_PERCENT.search(current):
            raise LedgerError("URL path contains malformed nested percent encoding")
    else:
        raise LedgerError("URL path contains excessive nested percent encoding")

    segments = current.split("/")
    if any(segment in {".", ".."} or segment.startswith((".;", "..;")) for segment in segments):
        raise LedgerError("URL path contains a dot segment")
    if "\\" in current or "//" in current or any(
        ord(char) < 0x20 or ord(char) == 0x7F for char in current
    ):
        raise LedgerError("decoded URL path is ambiguous")

    trailing = current.endswith("/")
    normalized = posixpath.normpath(current)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    if trailing and normalized != "/":
        normalized += "/"
    return normalized


def canonical_url(value: str, *, declared_prefix: bool = False) -> str:
    if not isinstance(value, str):
        raise LedgerError("URL must be a string")
    try:
        parsed = urlsplit(value.strip())
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise LedgerError(f"invalid URL authority: {value!r}") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        raise LedgerError(f"URL must use http or https with a host: {value!r}")
    if parsed.username or parsed.password:
        raise LedgerError("URL scope rules must not contain userinfo")
    if declared_prefix and (parsed.query or parsed.fragment):
        raise LedgerError("url-prefix rules must not contain a query or fragment")
    host = canonical_host(hostname)
    if port is not None and not (1 <= port <= 65535):
        raise LedgerError("invalid URL port")
    default_port = (parsed.scheme.lower() == "http" and port == 80) or (
        parsed.scheme.lower() == "https" and port == 443
    )
    authority = host if port is None or default_port else f"{host}:{port}"
    return urlunsplit(
        (
            parsed.scheme.lower(),
            authority,
            _normalized_path(parsed.path),
            "" if declared_prefix else parsed.query,
            "",
        )
    )


def _validate_rule(rule: Any, field: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(rule, dict):
        return [f"{field} must be an object"]
    kind = rule.get("kind")
    value = rule.get("value")
    if kind not in ALLOWED_KINDS:
        errors.append(f"{field}.kind must be one of {sorted(ALLOWED_KINDS)}")
        return errors
    try:
        if kind == "host":
            canonical_host(value, allow_wildcard=True)
        elif kind == "url-prefix":
            canonical_url(value, declared_prefix=True)
        else:
            ipaddress.ip_network(value, strict=True)
    except (LedgerError, ValueError, TypeError) as exc:
        errors.append(f"{field}.value: {exc}")
    if "techniques" in rule:
        techniques = rule["techniques"]
        if not isinstance(techniques, list) or not techniques or not all(
            isinstance(item, str) and item.strip() for item in techniques
        ):
            errors.append(f"{field}.techniques must be a non-empty string list")
    return errors


def _is_nonempty_string_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(
        isinstance(item, str) and bool(item.strip()) for item in value
    )


def _is_finite_number(value: Any, *, positive: bool) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    numeric = float(value)
    if not math.isfinite(numeric):
        return False
    return numeric > 0 if positive else numeric >= 0


def validate_ledger(data: Any, *, now: datetime | None = None) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["ledger must be a JSON object"]
    declared_schema = data.get("schema_version")
    if declared_schema == "1":
        errors.append(
            "schema_version '1' is unsupported by scope_guard 2.0; migrate to "
            "schema_version '2' and add the required authorization context, operational "
            "limits, policy freshness, and data-handling fields"
        )
    elif declared_schema != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION!r}")
    for field in ("program", "policy_url", "policy_retrieved_at"):
        if not isinstance(data.get(field), str) or not data[field].strip():
            errors.append(f"{field} is required")
    policy_time: datetime | None = None
    if isinstance(data.get("policy_retrieved_at"), str):
        try:
            policy_time = _parse_time(data["policy_retrieved_at"], "policy_retrieved_at")
        except LedgerError as exc:
            errors.append(str(exc))
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    max_age = data.get("policy_max_age_days")
    if (
        not isinstance(max_age, int)
        or isinstance(max_age, bool)
        or not (1 <= max_age <= MAX_POLICY_AGE_DAYS)
    ):
        errors.append(f"policy_max_age_days is required and must be an integer from 1 to {MAX_POLICY_AGE_DAYS}")
    elif policy_time:
        if policy_time > current + MAX_FUTURE_CLOCK_SKEW:
            errors.append("policy_retrieved_at is in the future")
        elif current - policy_time > timedelta(days=max_age):
            errors.append("policy snapshot is older than policy_max_age_days")

    auth = data.get("authorization")
    if not isinstance(auth, dict):
        errors.append("authorization must be an object")
    else:
        start: datetime | None = None
        end: datetime | None = None
        try:
            start = _parse_time(auth.get("starts_at"), "authorization.starts_at")
        except LedgerError as exc:
            errors.append(str(exc))
        if auth.get("ends_at") is not None:
            try:
                end = _parse_time(auth.get("ends_at"), "authorization.ends_at")
            except LedgerError as exc:
                errors.append(str(exc))
        if start and end and end <= start:
            errors.append("authorization.ends_at must be after starts_at")
        for field in ("basis", "stop_condition"):
            if not isinstance(auth.get(field), str) or not auth[field].strip():
                errors.append(f"authorization.{field} is required")
        for field in ("identities", "tenants", "data_classes"):
            if not _is_nonempty_string_list(auth.get(field)):
                errors.append(f"authorization.{field} must be a non-empty string list")
        callback_assets = auth.get("callback_assets")
        if not isinstance(callback_assets, list):
            errors.append("authorization.callback_assets must be a list, even if empty")
        else:
            for index, rule in enumerate(callback_assets):
                errors.extend(_validate_rule(rule, f"authorization.callback_assets[{index}]"))
                if isinstance(rule, dict) and rule.get("kind") == "cidr":
                    errors.append(
                        f"authorization.callback_assets[{index}] must use host or url-prefix, not cidr"
                    )
        callback_techniques = auth.get("callback_techniques")
        if not isinstance(callback_techniques, list) or not all(
            isinstance(item, str) and item.strip() for item in callback_techniques
        ):
            errors.append("authorization.callback_techniques must be a string list, even if empty")
        elif callback_techniques and not callback_assets:
            errors.append("authorization.callback_assets is required when callback_techniques is non-empty")

    assets = data.get("assets")
    if not isinstance(assets, list) or not assets:
        errors.append("assets must be a non-empty list")
    else:
        for index, rule in enumerate(assets):
            errors.extend(_validate_rule(rule, f"assets[{index}]"))
            if isinstance(rule, dict) and rule.get("active_testing") is not True:
                errors.append(f"assets[{index}].active_testing must explicitly be true")
            if isinstance(rule, dict) and not rule.get("techniques"):
                errors.append(f"assets[{index}].techniques is required")
    excluded = data.get("excluded_assets", [])
    if not isinstance(excluded, list):
        errors.append("excluded_assets must be a list")
    else:
        for index, rule in enumerate(excluded):
            errors.extend(_validate_rule(rule, f"excluded_assets[{index}]"))
    prohibited = data.get("prohibited")
    if not isinstance(prohibited, list) or not all(
        isinstance(x, str) and x.strip() for x in prohibited
    ):
        errors.append("prohibited must be a string list, even if empty")
    limits = data.get("limits")
    if not isinstance(limits, dict):
        errors.append("limits must be an object")
    else:
        if not _is_finite_number(limits.get("requests_per_second"), positive=True):
            errors.append("limits.requests_per_second must be a finite positive number")
        concurrency = limits.get("max_concurrency")
        if not isinstance(concurrency, int) or isinstance(concurrency, bool) or concurrency < 1:
            errors.append("limits.max_concurrency must be a positive integer")
        if not _is_finite_number(limits.get("max_financial_value"), positive=False):
            errors.append("limits.max_financial_value must be a finite non-negative number")
        record_limit = limits.get("max_data_records")
        if not isinstance(record_limit, int) or isinstance(record_limit, bool) or record_limit < 1:
            errors.append("limits.max_data_records must be a positive integer")
        if not isinstance(limits.get("availability_testing"), bool):
            errors.append("limits.availability_testing must explicitly be true or false")
    rules = data.get("data_rules")
    if not isinstance(rules, dict):
        errors.append("data_rules must be an object")
    else:
        for field in (
            "controlled_accounts_only",
            "controlled_tenants_only",
            "controlled_data_only",
            "stop_on_unrelated_data",
            "redact_secrets",
        ):
            if rules.get(field) is not True:
                errors.append(f"data_rules.{field} must explicitly be true")
        retention = rules.get("max_retention_days")
        if not isinstance(retention, int) or isinstance(retention, bool) or retention < 0:
            errors.append("data_rules.max_retention_days must be a non-negative integer")
    return errors


def _rule_matches(rule: dict[str, Any], asset: str) -> bool:
    kind = rule["kind"]
    value = rule["value"]
    if kind == "url-prefix":
        try:
            candidate = canonical_url(asset)
            prefix = canonical_url(value, declared_prefix=True)
        except (LedgerError, ValueError, TypeError):
            return False
        if not candidate.startswith(prefix):
            return False
        if prefix.endswith("/"):
            return True
        remainder = candidate[len(prefix) :]
        return not remainder or remainder.startswith(("/", "?"))
    if kind == "host":
        try:
            parsed = urlsplit(asset) if "://" in asset else None
            if parsed:
                _ = parsed.port
            candidate = canonical_host(parsed.hostname if parsed else asset)
            declared = canonical_host(value, allow_wildcard=True)
        except (LedgerError, TypeError, ValueError):
            return False
        if declared.startswith("*."):
            suffix = declared[1:]  # includes the dot; apex cannot match
            return candidate.endswith(suffix) and candidate != declared[2:]
        return candidate == declared
    try:
        parsed = urlsplit(asset) if "://" in asset else None
        if parsed:
            _ = parsed.port
        raw = parsed.hostname if parsed else asset
        return ipaddress.ip_address(raw) in ipaddress.ip_network(value, strict=True)
    except (TypeError, ValueError):
        return False


def check_authorization(
    data: dict[str, Any],
    *,
    asset: str,
    technique: str,
    mode: str,
    identity: str | None = None,
    tenant: str | None = None,
    data_class: str | None = None,
    callback_asset: str | None = None,
    planned_rps: float | None = None,
    planned_concurrency: float | None = None,
    planned_financial_value: float | None = None,
    planned_data_records: int | None = None,
    availability_impact: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    errors = validate_ledger(data, now=now)
    if errors:
        return {"allowed": False, "reason": "invalid-ledger", "errors": errors}
    if mode not in {"active", "passive"}:
        return {"allowed": False, "reason": "invalid-mode"}
    if mode == "passive":
        return {
            "allowed": False,
            "reason": "passive-mode-does-not-authorize-target-action",
            "notice": (
                "This checker evaluates actions against a target asset. Truly passive or offline "
                "research must not contact the target and does not receive an allow decision here."
            ),
        }
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    auth = data["authorization"]
    start = _parse_time(auth["starts_at"], "authorization.starts_at")
    end = _parse_time(auth["ends_at"], "authorization.ends_at") if auth.get("ends_at") else None
    if current < start or (end and current >= end):
        return {"allowed": False, "reason": "authorization-window"}
    technique = technique.strip().lower()
    if technique in {x.strip().lower() for x in data["prohibited"]}:
        return {"allowed": False, "reason": "prohibited-technique"}
    if any(_rule_matches(rule, asset) for rule in data.get("excluded_assets", [])):
        return {"allowed": False, "reason": "excluded-asset"}
    matching = [rule for rule in data["assets"] if _rule_matches(rule, asset)]
    if not matching:
        return {"allowed": False, "reason": "asset-not-in-scope"}
    eligible = [
        rule
        for rule in matching
        if technique in {x.strip().lower() for x in rule.get("techniques", [])}
        and rule.get("active_testing") is True
    ]
    if not eligible:
        return {"allowed": False, "reason": "technique-or-mode-not-authorized"}

    context_checks = (
        ("identity", identity, auth["identities"]),
        ("tenant", tenant, auth["tenants"]),
        ("data-class", data_class, auth["data_classes"]),
    )
    for label, supplied, allowed_values in context_checks:
        if not isinstance(supplied, str) or not supplied.strip():
            return {"allowed": False, "reason": f"{label}-required"}
        if supplied.strip() not in allowed_values:
            return {"allowed": False, "reason": f"{label}-not-authorized"}

    callback_techniques = {item.strip().lower() for item in auth["callback_techniques"]}
    if technique in callback_techniques and not callback_asset:
        return {"allowed": False, "reason": "callback-asset-required"}
    if callback_asset is not None and not any(
        _rule_matches(rule, callback_asset) for rule in auth["callback_assets"]
    ):
        return {"allowed": False, "reason": "callback-asset-not-authorized"}

    limits = data["limits"]
    if not isinstance(availability_impact, bool):
        return {"allowed": False, "reason": "invalid-availability-impact"}
    if planned_rps is None:
        return {"allowed": False, "reason": "planned-rps-required"}
    if planned_concurrency is None:
        return {"allowed": False, "reason": "planned-concurrency-required"}
    if planned_financial_value is None:
        return {"allowed": False, "reason": "planned-financial-value-required"}
    if planned_data_records is None:
        return {"allowed": False, "reason": "planned-data-records-required"}
    if planned_rps is not None and not _is_finite_number(planned_rps, positive=True):
        return {"allowed": False, "reason": "invalid-planned-rps"}
    if (
        planned_concurrency is not None
        and (
            not _is_finite_number(planned_concurrency, positive=True)
            or not float(planned_concurrency).is_integer()
        )
    ):
        return {"allowed": False, "reason": "invalid-planned-concurrency"}
    if planned_financial_value is not None and not _is_finite_number(
        planned_financial_value, positive=False
    ):
        return {"allowed": False, "reason": "invalid-planned-financial-value"}
    if (
        planned_data_records is not None
        and (
            not isinstance(planned_data_records, int)
            or isinstance(planned_data_records, bool)
            or planned_data_records < 1
        )
    ):
        return {"allowed": False, "reason": "invalid-planned-data-records"}
    if planned_rps is not None and planned_rps > limits["requests_per_second"]:
        return {"allowed": False, "reason": "rps-over-limit"}
    if planned_concurrency is not None and planned_concurrency > limits["max_concurrency"]:
        return {"allowed": False, "reason": "concurrency-over-limit"}
    if (
        planned_financial_value is not None
        and planned_financial_value > limits["max_financial_value"]
    ):
        return {"allowed": False, "reason": "financial-value-over-limit"}
    if planned_data_records is not None and planned_data_records > limits["max_data_records"]:
        return {"allowed": False, "reason": "data-records-over-limit"}
    if availability_impact and not limits["availability_testing"]:
        return {"allowed": False, "reason": "availability-impact-not-authorized"}
    return {
        "allowed": True,
        "reason": "declared-ledger-allows",
        "notice": "This result checks only the supplied ledger; it does not create authorization.",
    }


def _read_json(path: str) -> Any:
    def reject_nonfinite(value: str) -> None:
        raise LedgerError(f"non-standard JSON numeric constant is not allowed: {value}")

    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle, parse_constant=reject_nonfinite)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version="scope_guard 2.0")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate", help="validate a scope ledger")
    validate.add_argument("ledger")
    check = sub.add_parser("check", help="check one declared action against the ledger")
    check.add_argument("ledger")
    check.add_argument("--asset", required=True)
    check.add_argument("--technique", required=True)
    check.add_argument(
        "--mode",
        choices=("passive", "active"),
        required=True,
        help=(
            "active evaluates a target action; passive is deliberately denied because offline "
            "research must not contact a target"
        ),
    )
    check.add_argument("--identity")
    check.add_argument("--tenant")
    check.add_argument("--data-class")
    check.add_argument("--callback-asset")
    check.add_argument("--planned-rps", type=float)
    check.add_argument("--planned-concurrency", type=float)
    check.add_argument("--planned-financial-value", type=float)
    check.add_argument("--planned-data-records", type=int)
    check.add_argument("--availability-impact", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        data = _read_json(args.ledger)
    except (OSError, json.JSONDecodeError, LedgerError) as exc:
        print(json.dumps({"valid": False, "errors": [str(exc)]}), file=sys.stderr)
        return 3
    if args.command == "validate":
        errors = validate_ledger(data)
        print(json.dumps({"valid": not errors, "errors": errors}, indent=2))
        return 0 if not errors else 3
    decision = check_authorization(
        data,
        asset=args.asset,
        technique=args.technique,
        mode=args.mode,
        identity=args.identity,
        tenant=args.tenant,
        data_class=args.data_class,
        callback_asset=args.callback_asset,
        planned_rps=args.planned_rps,
        planned_concurrency=args.planned_concurrency,
        planned_financial_value=args.planned_financial_value,
        planned_data_records=args.planned_data_records,
        availability_impact=args.availability_impact,
    )
    print(json.dumps(decision, indent=2))
    return 0 if decision["allowed"] else (3 if decision["reason"] == "invalid-ledger" else 2)


if __name__ == "__main__":
    raise SystemExit(main())
