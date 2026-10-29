import json
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import research_triage


AS_OF = date(2026, 10, 29)


def raw_item(**updates):
    value = {
        "lesson_id": "worker-auth-drift-v1",
        "url": "https://research.example.test/article?utm_source=x&part=1#section",
        "title": "Worker Authorization Drift",
        "publisher": "Original Researcher",
        "authority": "original researcher and vendor reproduction",
        "published_at": "2026-10-01",
        "retrieved_at": "2026-10-29T08:00:00Z",
        "kind": "original-research",
        "primary_source": True,
        "identifiers": [],
        "bug_classes": ["authorization"],
        "architecture": ["async-worker"],
        "affected_component": "export-worker",
        "boundary": "request-to-worker",
        "root_cause": "Worker trusts state prepared by a request handler",
        "preconditions": ["authenticated user"],
        "proof_pattern": "controlled destination receives protected child data",
        "counter_evidence": ["worker reauthorizes at execution"],
        "sibling_surfaces": ["scheduled exports"],
        "fix_invariant": "worker reauthorizes each child object",
        "target_evidence": [
            {
                "target_term": "async-worker",
                "evidence": "Observed an asynchronous export job in controlled traffic",
            }
        ],
        "manual_ratings": {
            "evidence_quality": 3,
            "actionability": 3,
            "safety_cost": 1,
            "unverified_assumptions": 0,
        },
    }
    value.update(updates)
    return value


def item(**updates):
    return research_triage.validate_item(raw_item(**updates))


def target(**updates):
    value = {
        "architecture": ["async-worker"],
        "technologies": ["graphql"],
        "components": ["export-worker"],
        "features": ["exports"],
        "trust_boundaries": ["request-to-worker"],
    }
    value.update(updates)
    return value


class ResearchTriageTests(unittest.TestCase):
    def test_url_normalization_preserves_functional_query(self):
        normalized = research_triage.canonical_url(
            "HTTPS://Research.Example.Test:443//article?utm_source=x&part=1#section"
        )
        self.assertEqual(normalized, "https://research.example.test/article?part=1")

    def test_malformed_port_is_rejected(self):
        with self.assertRaises(research_triage.ResearchError):
            research_triage.canonical_url("https://research.example.test:bad/article")

    def test_required_normalization_fields_are_enforced(self):
        for field in (
            "lesson_id",
            "authority",
            "retrieved_at",
            "affected_component",
            "boundary",
            "fix_invariant",
        ):
            value = raw_item()
            value.pop(field)
            with self.subTest(field=field), self.assertRaises(research_triage.ResearchError):
                research_triage.validate_item(value)

    def test_lesson_id_is_normalized_and_validated(self):
        self.assertEqual(item(lesson_id="Worker-Auth/V1")["lesson_id"], "worker-auth/v1")
        for invalid in ("x", "has spaces", "bad?query", "../escape"):
            with self.subTest(lesson_id=invalid), self.assertRaises(research_triage.ResearchError):
                item(lesson_id=invalid)

    def test_new_source_kinds_are_accepted(self):
        self.assertEqual(item(kind="program-policy")["kind"], "program-policy")
        self.assertEqual(item(kind="curated-methodology")["kind"], "curated-methodology")

    def test_computed_fields_cannot_be_injected_into_manual_ratings(self):
        value = raw_item()
        value["manual_ratings"]["architecture_match"] = 3
        with self.assertRaises(research_triage.ResearchError):
            research_triage.validate_item(value)

    def test_directly_applicable_requires_structural_and_anchored_evidence(self):
        direct = research_triage.build_brief([item()], target(), as_of=AS_OF)[0]
        self.assertEqual(direct["category"], "directly-applicable")
        self.assertEqual(direct["computed_evidence"]["architecture_overlap"], ["async-worker"])
        self.assertEqual(len(direct["computed_evidence"]["anchored_target_evidence"]), 1)
        self.assertIn("manual", direct["score_breakdown"])
        self.assertIn("computed", direct["score_breakdown"])

    def test_self_rated_unrelated_item_cannot_be_directly_applicable(self):
        unrelated = item(
            target_evidence=[
                {"target_term": "async-worker", "evidence": "Unverified author claim"}
            ],
            manual_ratings={
                "evidence_quality": 3,
                "actionability": 3,
                "safety_cost": 0,
                "unverified_assumptions": 0,
            },
        )
        unrelated_target = target(
            architecture=["mainframe"],
            technologies=["cobol"],
            components=["payroll"],
            features=["payroll"],
            trust_boundaries=["batch-to-ledger"],
        )
        result = research_triage.build_brief([unrelated], unrelated_target, as_of=AS_OF)[0]
        self.assertEqual(result["category"], "weak-analogy")
        self.assertEqual(result["computed_evidence"]["anchored_target_evidence"], [])

    def test_match_without_anchored_target_evidence_is_architecture_dependent(self):
        lead = item(target_evidence=[])
        result = research_triage.build_brief([lead], target(), as_of=AS_OF)[0]
        self.assertEqual(result["category"], "architecture-dependent")

    def test_recency_is_derived_from_dates(self):
        old = item(
            published_at="2020-01-01",
            retrieved_at="2025-01-01T00:00:00Z",
        )
        result = research_triage.build_brief([old], target(), as_of=AS_OF)[0]
        computed = result["computed_evidence"]
        self.assertEqual(computed["publication_recency_score"], 0)
        self.assertEqual(computed["retrieval_freshness_score"], 0)

    def test_future_dates_fail_against_explicit_as_of(self):
        future = item(
            published_at="2027-01-01",
            retrieved_at="2027-01-02T00:00:00Z",
        )
        with self.assertRaises(research_triage.ResearchError):
            research_triage.build_brief([future], target(), as_of=AS_OF)

    def test_primary_source_wins_and_duplicate_evidence_is_merged(self):
        primary = item()
        copy = item(
            url="https://copy.example.test/post",
            publisher="Summary Site",
            primary_source=False,
            preconditions=["authenticated user", "export feature enabled"],
            target_evidence=[
                {"target_term": "exports", "evidence": "Observed export feature"}
            ],
            manual_ratings={
                "evidence_quality": 1,
                "actionability": 2,
                "safety_cost": 3,
                "unverified_assumptions": 2,
            },
        )
        merged = research_triage.deduplicate([copy, primary])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["publisher"], "Original Researcher")
        self.assertIn("https://copy.example.test/post", merged[0]["duplicate_urls"])
        self.assertIn("export feature enabled", merged[0]["preconditions"])
        self.assertEqual(len(merged[0]["target_evidence"]), 2)
        self.assertEqual(merged[0]["manual_rating_ranges"]["safety_cost"], {"minimum": 1, "maximum": 3})
        self.assertEqual(len(merged[0]["corroborating_sources"]), 2)

    def test_same_url_does_not_merge_independent_lessons(self):
        shared_url = "https://bridge.example.test/article"
        first = item(
            lesson_id="article-auth-boundary",
            url=shared_url,
            title="First",
            affected_component="identity-mapper",
            boundary="provider-to-local-account",
            root_cause="First root",
        )
        second = item(
            lesson_id="article-cache-boundary",
            url=shared_url,
            title="Second",
            affected_component="cache",
            boundary="cache-to-origin",
            root_cause="Second root",
        )
        merged = research_triage.deduplicate([first, second])
        self.assertEqual(len(merged), 2)
        self.assertEqual(
            {entry["lesson_id"] for entry in merged},
            {"article-auth-boundary", "article-cache-boundary"},
        )

    def test_true_duplicates_merge_transitively_by_stable_lesson_id(self):
        lesson_id = "worker-auth-drift-v1"
        first = item(url="https://one.example.test/article", lesson_id=lesson_id)
        second = item(
            url="https://two.example.test/article",
            lesson_id=lesson_id,
            primary_source=False,
        )
        third = item(
            url="https://three.example.test/article",
            lesson_id=lesson_id,
            primary_source=False,
        )
        merged = research_triage.deduplicate([first, second, third])
        self.assertEqual(len(merged), 1)
        all_urls = {merged[0]["url"], *merged[0]["duplicate_urls"]}
        self.assertEqual(
            all_urls,
            {
                "https://one.example.test/article",
                "https://two.example.test/article",
                "https://three.example.test/article",
            },
        )
        self.assertEqual(len(merged[0]["corroborating_sources"]), 3)

    def test_sorting_is_deterministic(self):
        first = item(
            lesson_id="lesson-a",
            url="https://a.example.test/research",
            title="A",
            root_cause="A root",
        )
        second = item(
            lesson_id="lesson-b",
            url="https://b.example.test/research",
            title="B",
            root_cause="B root",
        )
        one = research_triage.build_brief([second, first], target(), as_of=AS_OF)
        two = research_triage.build_brief([first, second], target(), as_of=AS_OF)
        self.assertEqual([x["url"] for x in one], [x["url"] for x in two])

    def test_read_jsonl_rejects_nonstandard_constants(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "items.jsonl"
            path.write_text(json.dumps(raw_item()).replace('"evidence_quality": 3', '"evidence_quality": NaN'), encoding="utf-8")
            with self.assertRaises(research_triage.ResearchError):
                research_triage.read_jsonl(path)


if __name__ == "__main__":
    unittest.main()
