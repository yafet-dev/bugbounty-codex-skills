# SQL Injection Methodology

Use this reference to test database query-control boundaries.

## 1. Input inventory

List path, query, body, JSON, array, GraphQL, sort, filter, search, report, CSV, header, and stored inputs.

## 2. Confirmation methods

Use boolean differences, error messages, time delays, result count changes, and safe out-of-band callbacks where appropriate.

## 3. Application-decoded input checks

When an API, client bundle, or observed request indicates that a parameter is Base64, Base64url, hex, compressed, encrypted, or otherwise wrapped, map decoding as part of the source-to-query path. Encode exact semantic true/false or valid/invalid control pairs and hold the rest of the request constant. A WAF status change is only a filter differential; require the same controlled SQL behavior used for an unwrapped input, such as a repeatable boolean, result-count, error, or bounded timing difference.

Do not add Base64 blindly to every SQLi payload. Verify the application accepts and decodes that format, distinguish transport decoding from database decoding functions, and determine whether validation occurs before or after decoding.

## 4. Impact paths

Assess data access, auth bypass, file read/write, command execution, stacked queries, and privileged database functions.

## 5. Second-order checks

Store payloads in profile, name, comment, import, config, and admin-managed fields; trigger reports/search/exports later.

## 6. Remediation checklist

- Use parameterized queries.
- Decode supported transport formats once before validation, reject malformed or ambiguous values, and keep decoded data parameterized rather than concatenating it into SQL.
- Avoid dynamic SQL for identifiers.
- Validate sort/filter allowlists.
- Limit DB privileges.
- Regression-test query builders and reports.
