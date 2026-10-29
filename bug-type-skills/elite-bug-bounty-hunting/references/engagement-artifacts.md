# Engagement Artifacts and Script Schemas

Use these local artifacts to make reasoning reproducible. They record the researcher’s authorization and evidence; they do not create authorization or prove a vulnerability.

All examples use synthetic `.test` domains.

## Scope ledger

Save as `engagement.json`:

```json
{
  "schema_version": "2",
  "program": "Synthetic Program",
  "policy_url": "https://example.test/security",
  "policy_retrieved_at": "2026-10-29T08:00:00Z",
  "policy_max_age_days": 7,
  "authorization": {
    "starts_at": "2026-01-01T00:00:00Z",
    "ends_at": null,
    "basis": "Public bug bounty policy for the listed staging assets",
    "stop_condition": "Stop on unrelated data, scope uncertainty, first sufficient proof, or service degradation",
    "identities": ["controlled-standard-user", "controlled-admin-user"],
    "tenants": ["controlled-tenant-a", "controlled-tenant-b"],
    "data_classes": ["synthetic-profile", "synthetic-project"],
    "callback_assets": [
      {"kind": "host", "value": "callbacks.example.test"}
    ],
    "callback_techniques": ["controlled-callback"]
  },
  "assets": [
    {
      "kind": "url-prefix",
      "value": "https://app.example.test/api/",
      "active_testing": true,
      "techniques": ["manual-http", "controlled-callback"]
    },
    {
      "kind": "host",
      "value": "*.sandbox.example.test",
      "active_testing": true,
      "techniques": ["manual-http"]
    }
  ],
  "excluded_assets": [
    {"kind": "host", "value": "status.sandbox.example.test"}
  ],
  "prohibited": ["availability-testing", "social-engineering"],
  "limits": {
    "requests_per_second": 2,
    "max_concurrency": 2,
    "max_financial_value": 0,
    "max_data_records": 10,
    "availability_testing": false
  },
  "data_rules": {
    "controlled_accounts_only": true,
    "controlled_tenants_only": true,
    "controlled_data_only": true,
    "stop_on_unrelated_data": true,
    "redact_secrets": true,
    "max_retention_days": 30
  }
}
```

This is the `scope_guard 2.0` ledger contract. Supported asset kinds are defined by `scope_guard.py`; use its validation output rather than guessing a shape. A wildcard subdomain does not include the apex. Exclusions override inclusions. A URL prefix remains path-specific and must not be broadened to its host. Ambiguous encodings, non-canonical CIDRs, stale policy snapshots, and non-finite limits fail closed. Callback assets record researcher-controlled infrastructure permitted by policy; they do not add target assets to scope.

Validate and check a planned action:

```text
python scripts/scope_guard.py validate engagement.json
python scripts/scope_guard.py check engagement.json --asset https://app.example.test/api/projects --technique manual-http --mode active --identity controlled-standard-user --tenant controlled-tenant-a --data-class synthetic-project --planned-rps 1 --planned-concurrency 1 --planned-financial-value 0 --planned-data-records 1
```

For a technique listed in `authorization.callback_techniques`, also pass the exact `--callback-asset`. Pass `--availability-impact` only when the planned action can affect availability; the check denies it unless the ledger explicitly permits availability testing. The ledger is a fail-closed record of researcher-supplied authorization, not a substitute for reading the actual policy.

`scope_guard check` authorizes target-touching active actions only. `--mode passive` deliberately returns no allow decision; offline research and planning must not contact the target. Unknown mode strings also fail closed.

Exit `0` allows the action under the supplied ledger, `2` denies it, and `3` means the ledger is malformed or ambiguous.

## Target model

Save only observed evidence, not guesses, in `target-model.json`:

```json
{
  "architecture": ["async-worker", "multi-tenant", "cdn-origin"],
  "technologies": ["graphql", "object-storage"],
  "components": ["project-importer", "export-worker"],
  "features": ["project templates", "scheduled exports"],
  "trust_boundaries": ["tenant", "request-to-worker", "cache-to-origin"]
}
```

Keep the evidence supporting each term in the experiment ledger or architecture notes.

## Research items

Store one JSON object per line in `research-items.jsonl`:

```json
{"lesson_id":"worker-auth-drift-v1","url":"https://research.example.test/worker-auth","title":"Worker Authorization Drift","publisher":"Original Researcher","authority":"original researcher publication","published_at":"2026-10-01","retrieved_at":"2026-10-29T08:00:00Z","kind":"original-research","primary_source":true,"identifiers":[],"bug_classes":["authorization"],"architecture":["async-worker"],"affected_component":"scheduled export worker","boundary":"request-to-worker authorization","root_cause":"Worker trusts state prepared by a request handler","preconditions":["authenticated controlled user","queued export feature"],"proof_pattern":"Controlled destination receives a protected child marker","counter_evidence":["Worker reauthorizes the current actor and each child at execution time"],"sibling_surfaces":["PDF jobs","scheduled reports"],"fix_invariant":"Worker reauthorizes every child object at use time","target_evidence":[{"target_term":"async-worker","evidence":"A controlled export remained queued after the request completed"}],"manual_ratings":{"evidence_quality":3,"actionability":3,"safety_cost":1,"unverified_assumptions":0}}
```

Allowed `kind` values:

- `vendor-advisory`
- `cve`
- `original-research`
- `public-report`
- `program-policy`
- `curated-methodology`
- `standard`
- `product-documentation`

Manual ratings are bounded integers for source quality, actionability, safety cost, and unverified assumptions. Architecture match, target evidence, and date recency are computed rather than accepted as author ratings. A `directly-applicable` result requires both an observed target-model overlap and a `target_evidence` entry anchored to that observed term. A dramatic severity label is intentionally absent.

`lesson_id` names one affected-component, boundary, and root-cause lesson. A multi-technique source may produce several records with different lesson IDs. Reuse an ID only when another source corroborates the same lesson; URL equality alone never means two lessons are duplicates. The normalized JSON output uses schema `3`.

Build a brief:

```text
python scripts/research_triage.py research-items.jsonl --target-model target-model.json --as-of 2026-10-29 --format markdown --out research-brief.md
```

Use `--as-of` to make recency calculations reproducible. Publication dates and timezone-aware retrieval timestamps must not be in the future relative to that date. Duplicate records are merged transitively and preserve corroborating sources and evidence. The output categories are applicability hints, not vulnerability verdicts.

## Hypothesis board

Use a table or JSON document that preserves these fields:

| Field | Requirement |
| --- | --- |
| ID | Stable local identifier |
| Feature | Product action or component |
| Invariant | Expected security or business rule |
| Architecture evidence | Why the feature and boundary exist |
| Hypothesis | Component, trusted property, actor, and boundary |
| Baseline | Normal controlled case |
| One change | Exactly one semantic difference |
| Negative control | Case that should not create the result |
| Oracle | Controlled authoritative evidence |
| Stop point | First sufficient safe proof |
| Status | Backlog, ready, disproved, verified primitive, or stopped |
| Chain dependency | None or a named verified capability |

An experiment is not ready if any of baseline, one change, negative control, oracle, or stop point is missing.

## Saved HTTP transcripts

Store complete synthetic or redacted raw request/response transcripts separately for baseline, mutation, and negative control. `evidence_lab.py` parses them offline and redacts common secret-bearing fields.

```text
python scripts/evidence_lab.py diff-http --baseline evidence/baseline.http --mutation evidence/mutation.http --negative-control evidence/negative.http --marker CONTROLLED_MARKER_7F92 --keep-header Age --keep-header ETag --keep-header X-Request-ID --out evidence/diff.json
```

Use `--keep-header` when a normally volatile cache or correlation header is evidence. Use `--include-body` only for controlled content; excerpts are byte-limited, valid JSON is structurally redacted, and invalid JSON is omitted rather than presented as sanitized. Secret values receive opaque labels that preserve equality across baseline, mutation, and negative control within one run; labels intentionally change across separate runs. URL-valued headers and nested URLs have credential-bearing query and fragment parameters redacted. Bounded chunked request and response bodies are decoded before comparison; ambiguous content-length/transfer-encoding combinations, malformed chunks, unsupported transfer coding, and excessive framing fail closed. Explicitly framed interim/response sequences are followed to the final response, while response-looking body text is not reparsed. Diff output uses schema `2`. A reported marker or difference is an observation, not exploit proof.

## Evidence case

Save as `case.json`:

```json
{
  "schema_version": "2",
  "case_id": "CASE-001",
  "target": "app.example.test",
  "feature": "controlled project import",
  "scope_snapshot": {
    "program": "Synthetic Program",
    "policy_url": "https://example.test/security",
    "policy_retrieved_at": "2026-10-29T08:00:00Z",
    "authorized_asset": "app.example.test",
    "authorization_window": "2026-01-01 onward",
    "controlled_context": "two controlled tenants and synthetic project data"
  },
  "architecture_evidence": [
    "Observed import request returns a job ID and completes in an asynchronous worker"
  ],
  "hypothesis": "The worker may accept a hidden URL-backed model field",
  "expected_secure_behavior": "Unknown fields are rejected before model creation",
  "baseline": "Import the controlled project without the field",
  "one_change": "Add one harmless model field supported by the library",
  "negative_control": "Repeat the unchanged import with a new marker",
  "reproduction_steps": [
    "Create a synthetic project in controlled-tenant-a",
    "Run the baseline import and record the completed job",
    "Repeat with only the hidden field changed",
    "Run the negative control with a new marker"
  ],
  "observations": ["A controlled callback from the worker was recorded"],
  "proven_impact": ["The worker made a controlled outbound request"],
  "unverified_follow_ons": ["Internal reachability was not tested"],
  "stop_condition": "Stop after the worker callback proves the fetch boundary",
  "remediation_invariant": "Only allowlisted fields can reach model callbacks",
  "evidence_files": [
    "baseline.http",
    "mutation.http",
    "callback-log-redacted.txt"
  ]
}
```

Build a sanitized packet:

```text
python scripts/evidence_lab.py packet case.json --evidence-root evidence --out finding-packet.md
```

Evidence paths must remain inside the evidence root. The packet hashes files rather than copying them, keeps proven impact separate from unverified follow-ons, and rejects traversal or escaping links.

## Chain graph

Represent every edge explicitly:

```text
EDGE-01
Input capability: controlled project import
Preconditions: authenticated controlled tenant
Action: add one allowlisted-shaped hidden field
Output capability: worker performs controlled outbound request
Evidence: callback-log-redacted.txt SHA-256 ...
Status: proven
Next edge: none tested
```

Do not use a possible future capability as the input to a proven edge.
