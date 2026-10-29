import math
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import scope_guard


NOW = datetime(2026, 10, 29, tzinfo=timezone.utc)


def ledger():
    return {
        "schema_version": "2",
        "program": "Synthetic Program",
        "policy_url": "https://example.test/policy",
        "policy_retrieved_at": "2026-10-28T00:00:00Z",
        "policy_max_age_days": 7,
        "authorization": {
            "starts_at": "2026-01-01T00:00:00Z",
            "ends_at": None,
            "basis": "Published program policy and researcher account",
            "stop_condition": "Stop on unrelated data or the first sufficient controlled proof",
            "identities": ["researcher-a"],
            "tenants": ["controlled-tenant-a"],
            "data_classes": ["synthetic-controlled"],
            "callback_assets": [{"kind": "host", "value": "callback.researcher.test"}],
            "callback_techniques": ["controlled-callback"],
        },
        "assets": [
            {
                "kind": "url-prefix",
                "value": "https://app.example.test/api/",
                "active_testing": True,
                "techniques": ["manual-http"],
            },
            {
                "kind": "host",
                "value": "*.sandbox.example.test",
                "active_testing": True,
                "techniques": ["controlled-callback"],
            },
        ],
        "excluded_assets": [{"kind": "host", "value": "blocked.sandbox.example.test"}],
        "prohibited": ["availability-testing"],
        "limits": {
            "requests_per_second": 2,
            "max_concurrency": 2,
            "max_financial_value": 0,
            "max_data_records": 3,
            "availability_testing": False,
        },
        "data_rules": {
            "controlled_accounts_only": True,
            "controlled_tenants_only": True,
            "controlled_data_only": True,
            "stop_on_unrelated_data": True,
            "redact_secrets": True,
            "max_retention_days": 14,
        },
    }


def active_check(data=None, **overrides):
    arguments = {
        "asset": "https://app.example.test/api/orders",
        "technique": "manual-http",
        "mode": "active",
        "identity": "researcher-a",
        "tenant": "controlled-tenant-a",
        "data_class": "synthetic-controlled",
        "planned_rps": 1,
        "planned_concurrency": 1,
        "planned_financial_value": 0,
        "planned_data_records": 1,
        "now": NOW,
    }
    arguments.update(overrides)
    return scope_guard.check_authorization(data or ledger(), **arguments)


class ScopeGuardTests(unittest.TestCase):
    def test_valid_ledger_and_exact_prefix(self):
        data = ledger()
        self.assertEqual(scope_guard.validate_ledger(data, now=NOW), [])
        result = active_check(data, asset="https://APP.example.test:443/api/orders?id=1")
        self.assertTrue(result["allowed"])

    def test_schema_one_is_rejected_with_migration_diagnostic(self):
        data = ledger()
        data["schema_version"] = "1"
        result = active_check(data)
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "invalid-ledger")
        diagnostic = " ".join(result["errors"])
        self.assertIn("schema_version '1' is unsupported by scope_guard 2.0", diagnostic)
        self.assertIn("migrate to schema_version '2'", diagnostic)

    def test_adjacent_prefix_is_denied(self):
        result = active_check(asset="https://app.example.test/apiv2/orders")
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "asset-not-in-scope")

    def test_wildcard_does_not_match_apex_and_exclusion_wins(self):
        common = {
            "technique": "controlled-callback",
            "callback_asset": "callback.researcher.test",
        }
        denied = active_check(asset="sandbox.example.test", **common)
        allowed = active_check(asset="one.sandbox.example.test", **common)
        excluded = active_check(asset="blocked.sandbox.example.test", **common)
        self.assertFalse(denied["allowed"])
        self.assertTrue(allowed["allowed"])
        self.assertEqual(excluded["reason"], "excluded-asset")

    def test_invalid_and_passive_modes_cannot_bypass_active_controls(self):
        invalid = scope_guard.check_authorization(
            ledger(),
            asset="https://app.example.test/api/orders",
            technique="manual-http",
            mode="audit",
            now=NOW,
        )
        self.assertEqual(invalid["reason"], "invalid-mode")

        for asset, technique in (
            ("https://app.example.test/api/orders", "manual-http"),
            ("one.sandbox.example.test", "controlled-callback"),
        ):
            with self.subTest(technique=technique):
                result = scope_guard.check_authorization(
                    ledger(),
                    asset=asset,
                    technique=technique,
                    mode="passive",
                    now=NOW,
                )
                self.assertFalse(result["allowed"])
                self.assertEqual(
                    result["reason"], "passive-mode-does-not-authorize-target-action"
                )

    def test_encoded_or_ambiguous_paths_and_malformed_ports_fail_closed(self):
        candidates = [
            "https://app.example.test/api/%2e%2e/admin",
            "https://app.example.test/api/%252e%252e/admin",
            "https://app.example.test/api%2f../admin",
            "https://app.example.test/api//orders",
            "https://app.example.test:bad/api/orders",
        ]
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                result = active_check(asset=candidate)
                self.assertFalse(result["allowed"])
                self.assertEqual(result["reason"], "asset-not-in-scope")

    def test_ambiguous_declared_prefix_and_noncanonical_cidr_are_invalid(self):
        encoded = ledger()
        encoded["assets"][0]["value"] = "https://app.example.test/api/%2e%2e/admin"
        self.assertTrue(scope_guard.validate_ledger(encoded, now=NOW))

        cidr = ledger()
        cidr["assets"].append(
            {
                "kind": "cidr",
                "value": "192.0.2.5/24",
                "active_testing": True,
                "techniques": ["manual-http"],
            }
        )
        errors = " ".join(scope_guard.validate_ledger(cidr, now=NOW))
        self.assertIn("host bits set", errors)

    def test_context_and_callback_allowlists_fail_closed(self):
        for field, reason in (
            ("identity", "identity-not-authorized"),
            ("tenant", "tenant-not-authorized"),
            ("data_class", "data-class-not-authorized"),
        ):
            with self.subTest(field=field):
                self.assertEqual(active_check(**{field: "unknown"})["reason"], reason)
        self.assertEqual(active_check(identity=None)["reason"], "identity-required")

        callback_arguments = {
            "asset": "one.sandbox.example.test",
            "technique": "controlled-callback",
        }
        self.assertEqual(
            active_check(**callback_arguments)["reason"], "callback-asset-required"
        )
        self.assertEqual(
            active_check(**callback_arguments, callback_asset="unowned.example.test")["reason"],
            "callback-asset-not-authorized",
        )
        self.assertTrue(
            active_check(
                **callback_arguments, callback_asset="https://callback.researcher.test/log"
            )["allowed"]
        )

    def test_limits_and_prohibited_techniques_fail_closed(self):
        self.assertEqual(active_check(planned_rps=3)["reason"], "rps-over-limit")
        self.assertEqual(
            active_check(planned_data_records=4)["reason"], "data-records-over-limit"
        )
        self.assertEqual(
            active_check(planned_financial_value=0.01)["reason"],
            "financial-value-over-limit",
        )
        self.assertEqual(
            active_check(availability_impact=True)["reason"],
            "availability-impact-not-authorized",
        )
        prohibited = active_check(technique="availability-testing")
        self.assertEqual(prohibited["reason"], "prohibited-technique")

    def test_nonfinite_nonpositive_and_fractional_plans_are_denied(self):
        cases = (
            ({"planned_rps": -1}, "invalid-planned-rps"),
            ({"planned_rps": math.nan}, "invalid-planned-rps"),
            ({"planned_concurrency": 0}, "invalid-planned-concurrency"),
            ({"planned_concurrency": 1.5}, "invalid-planned-concurrency"),
            ({"planned_financial_value": math.inf}, "invalid-planned-financial-value"),
            ({"planned_data_records": 0}, "invalid-planned-data-records"),
            ({"availability_impact": "yes"}, "invalid-availability-impact"),
        )
        for arguments, reason in cases:
            with self.subTest(arguments=arguments):
                self.assertEqual(active_check(**arguments)["reason"], reason)

    def test_ledger_rejects_nonfinite_and_invalid_limits(self):
        for field, value in (
            ("requests_per_second", math.nan),
            ("requests_per_second", -1),
            ("max_concurrency", 1.5),
            ("max_financial_value", math.inf),
            ("max_data_records", 0),
        ):
            with self.subTest(field=field, value=value):
                data = ledger()
                data["limits"][field] = value
                self.assertTrue(scope_guard.validate_ledger(data, now=NOW))

    def test_expired_authorization_stale_missing_and_future_policy(self):
        expired = ledger()
        expired["authorization"]["ends_at"] = "2026-01-02T00:00:00Z"
        self.assertEqual(active_check(expired)["reason"], "authorization-window")

        stale = ledger()
        stale["policy_retrieved_at"] = "2000-01-01T00:00:00Z"
        self.assertIn(
            "policy snapshot is older", " ".join(scope_guard.validate_ledger(stale, now=NOW))
        )
        missing = ledger()
        del missing["policy_max_age_days"]
        self.assertIn(
            "policy_max_age_days is required",
            " ".join(scope_guard.validate_ledger(missing, now=NOW)),
        )
        future = ledger()
        future["policy_retrieved_at"] = "2026-10-30T00:00:00Z"
        self.assertIn(
            "policy_retrieved_at is in the future",
            " ".join(scope_guard.validate_ledger(future, now=NOW)),
        )

    def test_authorization_contract_fields_are_required(self):
        for field in (
            "basis",
            "stop_condition",
            "identities",
            "tenants",
            "data_classes",
            "callback_assets",
            "callback_techniques",
        ):
            with self.subTest(field=field):
                data = ledger()
                del data["authorization"][field]
                self.assertTrue(scope_guard.validate_ledger(data, now=NOW))

        for field in (
            "controlled_accounts_only",
            "controlled_tenants_only",
            "controlled_data_only",
            "stop_on_unrelated_data",
            "redact_secrets",
            "max_retention_days",
        ):
            with self.subTest(field=field):
                data = ledger()
                del data["data_rules"][field]
                self.assertTrue(scope_guard.validate_ledger(data, now=NOW))

    def test_json_loader_rejects_nan_and_infinity(self):
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(constant=constant), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "ledger.json"
                path.write_text('{"value": ' + constant + "}", encoding="utf-8")
                with self.assertRaises(scope_guard.LedgerError):
                    scope_guard._read_json(str(path))


if __name__ == "__main__":
    unittest.main()
