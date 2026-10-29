#!/usr/bin/env python3
"""Normalize, deduplicate, and rank already-collected security research.

The script is intentionally network-free. It scores applicability evidence, not
exploitability, and does not infer that a target is vulnerable. Target matching
and recency are computed from explicit evidence rather than author-assigned
ratings.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

TRACKING_KEYS = {"fbclid", "gclid", "mc_cid", "mc_eid", "ref", "source"}
ALLOWED_KINDS = {
    "program-policy",
    "vendor-advisory",
    "cve",
    "original-research",
    "public-report",
    "curated-methodology",
    "standard",
    "product-documentation",
}
MANUAL_RATING_LIMITS = {
    "evidence_quality": 3,
    "actionability": 3,
    "safety_cost": 3,
    "unverified_assumptions": 3,
}
MERGED_LIST_FIELDS = {
    "identifiers",
    "bug_classes",
    "architecture",
    "preconditions",
    "counter_evidence",
    "sibling_surfaces",
}


class ResearchError(ValueError):
    pass


def _one_line(value: str) -> str:
    return " ".join(value.split())


def _term(value: str) -> str:
    return _one_line(value).casefold()


def canonical_url(value: str) -> str:
    if not isinstance(value, str):
        raise ResearchError("URL must be a string")
    parsed = urlsplit(value.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ResearchError(f"invalid HTTP(S) URL: {value!r}")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        port = parsed.port
    except (UnicodeError, ValueError) as exc:
        raise ResearchError(f"invalid HTTP(S) URL: {value!r}") from exc
    default = (parsed.scheme.lower() == "http" and port == 80) or (
        parsed.scheme.lower() == "https" and port == 443
    )
    authority = host if port is None or default else f"{host}:{port}"
    query = []
    for key, val in parse_qsl(parsed.query, keep_blank_values=True):
        lowered = key.lower()
        if lowered.startswith("utm_") or lowered in TRACKING_KEYS:
            continue
        query.append((key, val))
    query.sort()
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    return urlunsplit((parsed.scheme.lower(), authority, path, urlencode(query, doseq=True), ""))


def _string_list(item: dict[str, Any], name: str, *, required: bool = False) -> list[str]:
    value = item.get(name, [])
    if not isinstance(value, list) or not all(isinstance(x, str) and x.strip() for x in value):
        raise ResearchError(f"{name} must be a string list")
    if required and not value:
        raise ResearchError(f"{name} must not be empty")
    return sorted({_term(x) for x in value})


def _parse_timestamp(value: str, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ResearchError(f"{field} is required")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ResearchError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ResearchError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _target_evidence(item: dict[str, Any]) -> list[dict[str, str]]:
    value = item.get("target_evidence", [])
    if not isinstance(value, list):
        raise ResearchError("target_evidence must be a list")
    normalized: dict[tuple[str, str], dict[str, str]] = {}
    for entry in value:
        if not isinstance(entry, dict):
            raise ResearchError("target_evidence entries must be objects")
        target_term = entry.get("target_term")
        evidence = entry.get("evidence")
        if not isinstance(target_term, str) or not target_term.strip():
            raise ResearchError("target_evidence.target_term must be a non-empty string")
        if not isinstance(evidence, str) or not evidence.strip():
            raise ResearchError("target_evidence.evidence must be a non-empty string")
        key = (_term(target_term), _one_line(evidence))
        normalized[key] = {"target_term": key[0], "evidence": key[1]}
    return [normalized[key] for key in sorted(normalized)]


def validate_item(raw: Any, line_number: int | None = None) -> dict[str, Any]:
    prefix = f"line {line_number}: " if line_number else ""
    try:
        return _validate_item(raw)
    except ResearchError as exc:
        raise ResearchError(prefix + str(exc)) from exc


def _validate_item(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ResearchError("research item must be an object")
    item = dict(raw)
    required_strings = (
        "lesson_id", "url", "title", "publisher", "authority", "published_at", "retrieved_at", "kind",
        "affected_component", "boundary", "root_cause", "proof_pattern", "fix_invariant",
    )
    for field in required_strings:
        if not isinstance(item.get(field), str) or not item[field].strip():
            raise ResearchError(f"{field} is required")
    lesson_id = item["lesson_id"].strip().casefold()
    if not re.fullmatch(r"[a-z0-9][a-z0-9._:/#-]{2,127}", lesson_id):
        raise ResearchError(
            "lesson_id must be a stable 3-128 character identifier using letters, numbers, . _ : / # or -"
        )
    item["lesson_id"] = lesson_id
    item["url"] = canonical_url(item["url"])
    try:
        published = date.fromisoformat(item["published_at"].strip())
    except ValueError as exc:
        raise ResearchError("published_at must be an ISO-8601 date") from exc
    retrieved = _parse_timestamp(item["retrieved_at"], "retrieved_at")
    if retrieved.date() < published:
        raise ResearchError("retrieved_at must not precede published_at")
    item["published_at"] = published.isoformat()
    item["retrieved_at"] = retrieved.isoformat().replace("+00:00", "Z")
    if item["kind"] not in ALLOWED_KINDS:
        raise ResearchError(f"kind must be one of {sorted(ALLOWED_KINDS)}")
    if not isinstance(item.get("primary_source"), bool):
        raise ResearchError("primary_source must be boolean")
    for field in MERGED_LIST_FIELDS:
        item[field] = _string_list(
            item, field, required=field in {"bug_classes", "architecture", "preconditions"}
        )
    item["target_evidence"] = _target_evidence(item)
    ratings = item.get("manual_ratings")
    if not isinstance(ratings, dict):
        raise ResearchError("manual_ratings must be an object")
    unknown_ratings = sorted(set(ratings) - set(MANUAL_RATING_LIMITS))
    if unknown_ratings:
        raise ResearchError(
            "manual_ratings contains computed or unknown fields: " + ", ".join(unknown_ratings)
        )
    normalized_ratings: dict[str, int] = {}
    for name, maximum in MANUAL_RATING_LIMITS.items():
        value = ratings.get(name, 0)
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= maximum:
            raise ResearchError(f"manual_ratings.{name} must be an integer from 0 to {maximum}")
        normalized_ratings[name] = value
    item["manual_ratings"] = normalized_ratings
    for field in (
        "title", "publisher", "authority", "affected_component", "boundary", "root_cause",
        "proof_pattern", "fix_invariant",
    ):
        item[field] = _one_line(item[field])
    return item


def _reject_json_constant(value: str) -> None:
    raise ResearchError(f"non-standard JSON constant is not allowed: {value}")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                raw = json.loads(line, parse_constant=_reject_json_constant)
            except json.JSONDecodeError as exc:
                raise ResearchError(f"line {line_number}: invalid JSON: {exc}") from exc
            items.append(validate_item(raw, line_number))
    if not items:
        raise ResearchError("research input contains no items")
    return items


def _source_priority(item: dict[str, Any]) -> tuple[int, int, str, str]:
    return (
        1 if item["primary_source"] else 0,
        item["manual_ratings"]["evidence_quality"],
        item["published_at"],
        item["url"],
    )


def _lesson_groups(items: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Group only records explicitly declared to describe the same lesson.

    A single report or paper may contain several independent root causes. URL,
    CVE, title, or loose semantic similarity therefore cannot establish
    duplicate identity. Producers must reuse a stable lesson_id when separate
    records corroborate the same normalized lesson.
    """

    groups: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        groups.setdefault(item["lesson_id"], []).append(item)
    return [groups[key] for key in sorted(groups)]


def _merge_target_evidence(group: list[dict[str, Any]]) -> list[dict[str, str]]:
    merged: dict[tuple[str, str], dict[str, str]] = {}
    for item in group:
        for entry in item["target_evidence"]:
            key = (entry["target_term"], entry["evidence"])
            merged[key] = dict(entry)
    return [merged[key] for key in sorted(merged)]


def deduplicate(items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    source_items = list(items)
    merged: list[dict[str, Any]] = []
    for group in _lesson_groups(source_items):
        preferred = dict(sorted(group, key=_source_priority, reverse=True)[0])
        preferred_ratings = dict(preferred["manual_ratings"])
        preferred["duplicate_urls"] = sorted(
            {x["url"] for x in group if x["url"] != preferred["url"]}
        )
        for field in MERGED_LIST_FIELDS:
            preferred[field] = sorted({value for entry in group for value in entry[field]})
        preferred["target_evidence"] = _merge_target_evidence(group)
        # Corroborating copies may raise safety cost or uncertainty, but cannot
        # inflate the preferred source's positive evidence/actionability scores.
        preferred["manual_ratings"] = {
            "evidence_quality": preferred_ratings["evidence_quality"],
            "actionability": preferred_ratings["actionability"],
            "safety_cost": max(entry["manual_ratings"]["safety_cost"] for entry in group),
            "unverified_assumptions": max(
                entry["manual_ratings"]["unverified_assumptions"] for entry in group
            ),
        }
        preferred["manual_rating_ranges"] = {
            name: {
                "minimum": min(entry["manual_ratings"][name] for entry in group),
                "maximum": max(entry["manual_ratings"][name] for entry in group),
            }
            for name in MANUAL_RATING_LIMITS
        }
        preferred["corroborating_sources"] = [
            {
                "url": entry["url"], "publisher": entry["publisher"], "kind": entry["kind"],
                "lesson_id": entry["lesson_id"],
                "primary_source": entry["primary_source"],
                "manual_ratings": dict(entry["manual_ratings"]),
            }
            for entry in sorted(group, key=lambda value: value["url"])
        ]
        merged.append(preferred)
    return merged


def _observed_model(target_model: dict[str, Any]) -> dict[str, set[str]]:
    if not isinstance(target_model, dict):
        raise ResearchError("target model must be a JSON object")
    observed: dict[str, set[str]] = {}
    for field in ("architecture", "technologies", "components", "features", "trust_boundaries"):
        value = target_model.get(field, [])
        if not isinstance(value, list) or not all(isinstance(x, str) and x.strip() for x in value):
            raise ResearchError(f"target-model {field} must be a non-empty-string list")
        observed[field] = {_term(x) for x in value}
    return observed


def _recency(published_at: str, retrieved_at: str, as_of: date) -> dict[str, Any]:
    published = date.fromisoformat(published_at)
    retrieved = _parse_timestamp(retrieved_at, "retrieved_at").date()
    publication_age = (as_of - published).days
    retrieval_age = (as_of - retrieved).days
    if publication_age < 0 or retrieval_age < 0:
        raise ResearchError("published_at and retrieved_at must not be in the future relative to --as-of")
    publication_score = 2 if publication_age <= 365 else 1 if publication_age <= 1095 else 0
    retrieval_score = 2 if retrieval_age <= 30 else 1 if retrieval_age <= 180 else 0
    return {
        "publication_age_days": publication_age,
        "retrieval_age_days": retrieval_age,
        "publication_recency_score": publication_score,
        "retrieval_freshness_score": retrieval_score,
    }


def score_item(
    item: dict[str, Any], observed: dict[str, set[str]], *, as_of: date
) -> tuple[int, str, dict[str, Any], dict[str, int]]:
    all_observed = set().union(*observed.values())
    architecture_overlap = sorted(
        set(item["architecture"])
        & (observed["architecture"] | observed["technologies"] | observed["components"])
    )
    affected_component = _term(item["affected_component"])
    component_match = affected_component in (
        observed["components"] | observed["technologies"] | observed["features"]
    )
    boundary = _term(item["boundary"])
    boundary_match = boundary in observed["trust_boundaries"]
    anchored_evidence = [
        dict(entry) for entry in item["target_evidence"] if entry["target_term"] in all_observed
    ]
    recency = _recency(item["published_at"], item["retrieved_at"], as_of)
    structural_count = len(architecture_overlap) + int(component_match) + int(boundary_match)
    computed_score = (
        min(3, structural_count) * 3
        + min(2, len(anchored_evidence)) * 3
        + recency["publication_recency_score"]
        + recency["retrieval_freshness_score"]
    )
    ratings = item["manual_ratings"]
    manual_score = (
        ratings["evidence_quality"] * 3 + ratings["actionability"] * 2
        - ratings["safety_cost"] * 2 - ratings["unverified_assumptions"] * 2
    )
    if structural_count >= 1 and anchored_evidence:
        category = "directly-applicable"
    elif structural_count >= 1 or anchored_evidence:
        category = "architecture-dependent"
    else:
        category = "weak-analogy"
    computed = {
        "as_of": as_of.isoformat(),
        "architecture_overlap": architecture_overlap,
        "affected_component_match": component_match,
        "boundary_match": boundary_match,
        "anchored_target_evidence": anchored_evidence,
        **recency,
    }
    breakdown = {
        "manual": manual_score,
        "computed": computed_score,
        "total": manual_score + computed_score,
    }
    return breakdown["total"], category, computed, breakdown


def build_brief(
    items: list[dict[str, Any]], target_model: dict[str, Any], *, as_of: date | None = None
) -> list[dict[str, Any]]:
    observed = _observed_model(target_model)
    reference_date = as_of or date.today()
    output: list[dict[str, Any]] = []
    for item in deduplicate(items):
        score, category, computed, breakdown = score_item(item, observed, as_of=reference_date)
        copy = dict(item)
        copy["computed_evidence"] = computed
        copy["score_breakdown"] = breakdown
        copy["score"] = score
        copy["category"] = category
        output.append(copy)
    output.sort(key=lambda x: (-x["score"], -int(x["primary_source"]), x["url"]))
    return output


def to_markdown(items: list[dict[str, Any]]) -> str:
    lines = [
        "# Research Triage Brief",
        "",
        "> Ranking indicates research applicability, not that the target is vulnerable. Target matches and dates are computed; manual ratings remain separately labeled.",
        "",
    ]
    categories = ["directly-applicable", "architecture-dependent", "weak-analogy"]
    labels = {
        "directly-applicable": "Directly applicable hypotheses",
        "architecture-dependent": "Architecture-dependent leads",
        "weak-analogy": "Weak analogies and missing evidence",
    }
    for category in categories:
        lines.extend([f"## {labels[category]}", ""])
        subset = [x for x in items if x["category"] == category]
        if not subset:
            lines.extend(["None.", ""])
            continue
        for item in subset:
            computed = item["computed_evidence"]
            anchored = [x["evidence"] for x in computed["anchored_target_evidence"]]
            lines.extend([
                f"### {item['title']}",
                "",
                f"- Lesson ID: {item['lesson_id']}",
                f"- Score: {item['score']} (manual {item['score_breakdown']['manual']}; computed {item['score_breakdown']['computed']})",
                f"- Source: {item['publisher']} ({item['kind']}, published {item['published_at']}, retrieved {item['retrieved_at']})",
                f"- Authority: {item['authority']}",
                f"- Primary source: {'yes' if item['primary_source'] else 'no'}",
                f"- URL: {item['url']}",
                f"- Affected component: {item['affected_component']}",
                f"- Boundary: {item['boundary']}",
                f"- Root cause: {item['root_cause']}",
                f"- Proof pattern: {item['proof_pattern']}",
                f"- Computed architecture overlap: {', '.join(computed['architecture_overlap']) or 'none'}",
                f"- Anchored target evidence: {'; '.join(anchored) or 'none'}",
                f"- Preconditions: {', '.join(item['preconditions'])}",
                f"- Counter-evidence: {', '.join(item['counter_evidence']) or 'not recorded'}",
                f"- Sibling surfaces: {', '.join(item['sibling_surfaces']) or 'not recorded'}",
                f"- Fix invariant: {item['fix_invariant']}",
                "",
            ])
    return "\n".join(lines).rstrip() + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("items", type=Path)
    parser.add_argument("--target-model", type=Path, required=True)
    parser.add_argument("--as-of", type=date.fromisoformat, default=date.today())
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--version", action="version", version="research_triage 3.0")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        items = read_jsonl(args.items)
        with args.target_model.open("r", encoding="utf-8") as handle:
            target_model = json.load(handle, parse_constant=_reject_json_constant)
        brief = build_brief(items, target_model, as_of=args.as_of)
        rendered = (
            json.dumps(
                {"schema_version": "3", "as_of": args.as_of.isoformat(), "items": brief},
                indent=2,
                sort_keys=True,
            ) + "\n"
            if args.format == "json"
            else to_markdown(brief)
        )
        if args.out:
            args.out.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        return 0
    except (OSError, json.JSONDecodeError, ResearchError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
