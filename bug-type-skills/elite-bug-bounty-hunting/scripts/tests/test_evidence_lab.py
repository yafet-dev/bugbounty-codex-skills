import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import evidence_lab


def response(body: bytes, content_type="text/html", extra_headers=b""):
    return (
        b"POST /controlled HTTP/1.1\r\nHost: example.test\r\n\r\n"
        b"HTTP/1.1 200 OK\r\n"
        + f"Content-Type: {content_type}\r\n".encode()
        + b"Date: Tue, 01 Jan 2030 00:00:00 GMT\r\n"
        + b"Set-Cookie: session=secret-value; Path=/; HttpOnly; Secure; SameSite=Lax\r\n"
        + extra_headers
        + b"\r\n"
        + body
    )


class EvidenceLabTests(unittest.TestCase):
    def test_diff_redacts_secret_headers_and_finds_marker(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            baseline = root / "baseline.http"
            mutation = root / "mutation.http"
            negative = root / "negative.http"
            baseline.write_bytes(response(b"clean"))
            negative.write_bytes(response(b"clean"))
            mutation.write_bytes(response(b"marker XSS_TEST_7F92"))
            result = evidence_lab.compare_transcripts(
                baseline, mutation, negative, marker="XSS_TEST_7F92"
            )
            headers = result["responses"]["mutation"]["headers"]
            self.assertNotIn("secret-value", headers["set-cookie"][0])
            self.assertIn("session=[REDACTED:secret-", headers["set-cookie"][0])
            self.assertIn("HttpOnly", headers["set-cookie"][0])
            self.assertIn("SameSite=Lax", headers["set-cookie"][0])
            self.assertNotIn("date", headers)
            self.assertEqual(result["responses"]["mutation"]["marker"]["count"], 1)
            self.assertIn("body_sha256", result["differences"]["baseline_to_mutation"])

    def test_json_key_order_is_not_a_structural_difference(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            a = root / "a.http"
            b = root / "b.http"
            n = root / "n.http"
            a.write_bytes(response(b'{"a":1,"b":2}', "application/json"))
            b.write_bytes(response(b'{"b":2,"a":1}', "application/json"))
            n.write_bytes(response(b'{"a":1,"b":2}', "application/json"))
            result = evidence_lab.compare_transcripts(a, b, n)
            self.assertNotIn("json", result["differences"]["baseline_to_mutation"])
            self.assertNotIn("body_sha256", result["differences"]["baseline_to_mutation"])

    def test_json_secret_changes_are_labelled_detected_and_not_leaked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            baseline = root / "baseline.http"
            mutation = root / "mutation.http"
            negative = root / "negative.http"
            baseline.write_bytes(
                response(b'{"access_token":"AAA","nested":{"accessToken":"SAME"}}', "application/json")
            )
            mutation.write_bytes(
                response(b'{"access_token":"BBB","nested":{"accessToken":"SAME"}}', "application/json")
            )
            negative.write_bytes(
                response(b'{"access_token":"AAA","nested":{"accessToken":"SAME"}}', "application/json")
            )
            result = evidence_lab.compare_transcripts(
                baseline, mutation, negative, include_body=True
            )
            rendered = json.dumps(result)
            for secret in ("AAA", "BBB", "SAME"):
                self.assertNotIn(secret, rendered)
            self.assertIn("[REDACTED:secret-", rendered)
            self.assertIn("json", result["differences"]["baseline_to_mutation"])
            self.assertIn("json", result["differences"]["negative_to_mutation"])
            baseline_fields = result["responses"]["baseline"]["json"]["sensitive_fields"]
            negative_fields = result["responses"]["negative_control"]["json"]["sensitive_fields"]
            mutation_fields = result["responses"]["mutation"]["json"]["sensitive_fields"]
            self.assertEqual(baseline_fields[0]["label"], negative_fields[0]["label"])
            self.assertNotEqual(baseline_fields[0]["label"], mutation_fields[0]["label"])

    def test_invalid_json_body_is_not_echoed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("a.http", "b.http", "n.http"):
                (root / name).write_bytes(response(b'{"accessToken":"LEAK"', "application/json"))
            result = evidence_lab.compare_transcripts(
                root / "a.http", root / "b.http", root / "n.http", include_body=True
            )
            rendered = json.dumps(result)
            self.assertNotIn("LEAK", rendered)
            self.assertIn("invalid JSON cannot be safely redacted", rendered)

    def test_url_headers_custom_credentials_and_key_families_are_redacted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            extra = (
                b"Location: https://client.test/cb?code=OAUTH-CODE&ok=visible"
                b"#access_token=FRAGMENT-TOKEN&id_token=ID-TOKEN\r\n"
                b"X-Credential: CUSTOM-CREDENTIAL\r\n"
            )
            body = (
                b'{"credential":"JSON-CREDENTIAL","private_key":"PRIVATE-KEY",'
                b'"clientAssertion":"CLIENT-ASSERTION",'
                b'"next":"https://client.test/done?refresh_token=BODY-TOKEN"}'
            )
            for name in ("a.http", "b.http", "n.http"):
                (root / name).write_bytes(
                    response(body, "application/json", extra_headers=extra)
                )
            result = evidence_lab.compare_transcripts(
                root / "a.http",
                root / "b.http",
                root / "n.http",
                include_body=True,
            )
            rendered = json.dumps(result)
            for secret in (
                "OAUTH-CODE",
                "FRAGMENT-TOKEN",
                "ID-TOKEN",
                "CUSTOM-CREDENTIAL",
                "JSON-CREDENTIAL",
                "PRIVATE-KEY",
                "CLIENT-ASSERTION",
                "BODY-TOKEN",
            ):
                self.assertNotIn(secret, rendered)
            headers = result["responses"]["baseline"]["headers"]
            self.assertIn("ok=visible", headers["location"][0])
            self.assertIn("[REDACTED:secret-", headers["location"][0])
            self.assertIn("[REDACTED:secret-", headers["x-credential"][0])

    def test_keep_header_restores_cache_and_correlation_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            extra = b"Age: 12\r\nETag: abc\r\nX-Request-ID: controlled-1\r\n"
            for name in ("a.http", "b.http", "n.http"):
                (root / name).write_bytes(response(b"ok", extra_headers=extra))
            default = evidence_lab.compare_transcripts(
                root / "a.http", root / "b.http", root / "n.http"
            )
            kept = evidence_lab.compare_transcripts(
                root / "a.http",
                root / "b.http",
                root / "n.http",
                retained_headers={"age", "etag", "x-request-id"},
            )
            self.assertNotIn("age", default["responses"]["baseline"]["headers"])
            self.assertEqual(kept["responses"]["baseline"]["headers"]["age"], ["12"])
            self.assertEqual(
                kept["responses"]["baseline"]["headers"]["x-request-id"],
                ["controlled-1"],
            )

    def test_parser_selects_final_response_after_interim(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sequence.http"
            path.write_bytes(
                b"POST /controlled HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n"
                b"HTTP/1.1 100 Continue\r\n\r\n"
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok"
            )
            parsed = evidence_lab.parse_http_transcript(path)
            self.assertEqual(parsed.status, 200)
            self.assertEqual(parsed.body, b"ok")
            self.assertEqual(parsed.sequence_statuses, [100, 200])
            self.assertEqual(parsed.selected_sequence_index, 1)

    def test_parser_skips_response_looking_request_body(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "request-body.http"
            request_body = b"HTTP/1.1 418 Fake\r\nX-Fake: yes\r\n\r\n"
            path.write_bytes(
                b"POST /controlled HTTP/1.1\r\nHost: example.test\r\nContent-Length: "
                + str(len(request_body)).encode()
                + b"\r\n\r\n"
                + request_body
                + b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
            )
            parsed = evidence_lab.parse_http_transcript(path)
            self.assertEqual(parsed.status, 200)
            self.assertEqual(parsed.sequence_statuses, [200])

    def test_parser_skips_response_looking_chunked_request_body(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "chunked-request.http"
            request_body = b"HTTP/1.1 418 Fake\r\nX-Fake: yes\r\n\r\n"
            chunked = (
                f"{len(request_body):X}\r\n".encode()
                + request_body
                + b"\r\n0\r\nX-Controlled-Trailer: yes\r\n\r\n"
            )
            path.write_bytes(
                b"POST /controlled HTTP/1.1\r\nHost: example.test\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                + chunked
                + b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
            )
            parsed = evidence_lab.parse_http_transcript(path)
            self.assertEqual(parsed.status, 200)
            self.assertEqual(parsed.body, b"ok")
            self.assertEqual(parsed.sequence_statuses, [200])

    def test_parser_decodes_chunked_response_and_honors_boundary(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "chunked-response.http"
            first_body = b"redirect body HTTP/1.1 418 is data"
            first_chunked = (
                f"{len(first_body):X};controlled=yes\r\n".encode()
                + first_body
                + b"\r\n0\r\nX-Controlled-Trailer: yes\r\n\r\n"
            )
            path.write_bytes(
                b"HTTP/1.1 302 Found\r\nLocation: /next\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                + first_chunked
                + b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                + b"2\r\nfi\r\n3\r\nnal\r\n0\r\n\r\n"
            )
            parsed = evidence_lab.parse_http_transcript(path)
            self.assertEqual(parsed.status, 200)
            self.assertEqual(parsed.body, b"final")
            self.assertEqual(parsed.sequence_statuses, [302, 200])

    def test_parser_rejects_ambiguous_or_malformed_chunking(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ambiguous = root / "ambiguous.http"
            ambiguous.write_bytes(
                b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
            )
            malformed = root / "malformed.http"
            malformed.write_bytes(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n"
            )
            unsupported_chains = []
            for index, coding in enumerate(
                ("gzip, chunked", "chunked, chunked", "gzip", "identity, chunked")
            ):
                path = root / f"unsupported-{index}.http"
                path.write_bytes(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: "
                    + coding.encode()
                    + b"\r\n\r\n0\r\n\r\n"
                )
                unsupported_chains.append(path)
            with self.assertRaises(evidence_lab.EvidenceError):
                evidence_lab.parse_http_transcript(ambiguous)
            with self.assertRaises(evidence_lab.EvidenceError):
                evidence_lab.parse_http_transcript(malformed)
            for path in unsupported_chains:
                with self.subTest(path=path.name):
                    with self.assertRaisesRegex(
                        evidence_lab.EvidenceError,
                        "unsupported Transfer-Encoding framing",
                    ):
                        evidence_lab.parse_http_transcript(path)

    def test_parser_selects_last_framed_final_response(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "redirects.http"
            path.write_bytes(
                b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n"
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfinal"
            )
            parsed = evidence_lab.parse_http_transcript(path)
            self.assertEqual(parsed.status, 200)
            self.assertEqual(parsed.body, b"final")
            self.assertEqual(parsed.sequence_statuses, [302, 200])

    def test_packet_separates_proven_and_unverified_impact(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "evidence.txt").write_text("controlled marker", encoding="utf-8")
            case = {
                "schema_version": "2",
                "case_id": "CASE-001",
                "target": "example.test",
                "feature": "controlled import",
                "scope_snapshot": {
                    "program": "Synthetic Program",
                    "policy_url": "https://example.test/security",
                    "policy_retrieved_at": "2026-10-29T08:00:00Z",
                    "authorized_asset": "example.test",
                    "authorization_window": "2026-01-01 onward",
                    "controlled_context": "two controlled tenants",
                },
                "architecture_evidence": ["Observed import request reaches an asynchronous worker"],
                "hypothesis": "The worker may trust a hidden field",
                "expected_secure_behavior": "Unknown fields are rejected",
                "baseline": "Import without the field",
                "one_change": "Add one harmless field",
                "negative_control": "Repeat the unchanged import",
                "reproduction_steps": [
                    "Create a controlled object",
                    "Run the baseline and one-change experiment",
                ],
                "observations": ["Controlled callback was observed"],
                "proven_impact": ["Worker made a controlled outbound request"],
                "unverified_follow_ons": ["Internal reachability was not tested"],
                "stop_condition": "Stop after controlled callback",
                "remediation_invariant": "Only allowlisted fields reach callbacks",
                "evidence_files": ["evidence.txt"],
            }
            packet = evidence_lab.build_packet(case, root)
            self.assertIn("## Proven impact", packet)
            self.assertIn("## Unverified follow-ons", packet)
            self.assertIn("## Scope snapshot", packet)
            self.assertIn("## Architecture evidence", packet)
            self.assertIn("## Reproduction steps", packet)
            self.assertIn("Internal reachability was not tested", packet)
            self.assertIn("SHA-256", packet)

    def test_schema_one_case_has_migration_diagnostic(self):
        with self.assertRaisesRegex(
            evidence_lab.EvidenceError,
            "schema_version '1' is obsolete.*scope_snapshot",
        ):
            evidence_lab.validate_case({"schema_version": "1"})

    def test_packet_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outside = root.parent / "outside-evidence.txt"
            outside.write_text("outside", encoding="utf-8")
            try:
                with self.assertRaises(evidence_lab.EvidenceError):
                    evidence_lab._safe_evidence_path(root, "../outside-evidence.txt")
            finally:
                outside.unlink(missing_ok=True)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_packet_rejects_escaping_symlink(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as other:
            root = Path(temp)
            external = Path(other) / "external.txt"
            external.write_text("external", encoding="utf-8")
            link = root / "link.txt"
            try:
                os.symlink(external, link)
            except OSError:
                self.skipTest("symlink creation not permitted")
            with self.assertRaises(evidence_lab.EvidenceError):
                evidence_lab._safe_evidence_path(root, "link.txt")

    def test_text_redaction(self):
        redacted = evidence_lab.redact_text(
            'Authorization: Bearer abc.def\npassword=hunter2&access_token=xyz\n{"accessToken":"camel-secret"}'
        )
        self.assertNotIn("abc.def", redacted)
        self.assertNotIn("hunter2", redacted)
        self.assertNotIn("xyz", redacted)
        self.assertNotIn("camel-secret", redacted)
        self.assertIn("[REDACTED:secret-", redacted)


if __name__ == "__main__":
    unittest.main()
