# SQL Injection Methodology

Use this reference to test database query-control boundaries.

## Start here: how hunters found this in real reports

1. **Find query-building features.** Search, filters, sorting, reports, exports, analytics, bulk IDs, admin views, and dynamic column or table choices deserve more attention than random form fields.
2. **Include stored and metadata inputs.** Disclosed bugs reached later queries through headers, user agents, imported records, filenames, webhook fields, and values saved for an admin report.
3. **Understand the binder.** Arrays, repeated parameters, JSON collections, and list expansion often take a different code path from scalar values.
4. **Use paired controls.** Compare true/false conditions, short/long delays, valid/invalid syntax, and repeated clean baselines to rule out network noise and generic errors.
5. **Identify the query context.** Value, identifier, list, sort, and stored second-order contexts need different fixes and different evidence.
6. **Prove minimally.** Demonstrate controlled query influence; do not dump unrelated data or modify records.

### Expand the pattern

After one sink is confirmed, test the same filter or report builder through API, exports, scheduled jobs, and staff views. State the unsafe construction step rather than providing a payload catalog.

## 1. Input inventory

List path, query, body, JSON, array, GraphQL, sort, filter, search, report, CSV, header, and stored inputs.

## 2. Confirmation methods

Use boolean differences, error messages, time delays, result count changes, and safe out-of-band callbacks where appropriate.

## 3. Application-decoded input checks

When an API, client bundle, or observed request indicates that a parameter is Base64, Base64url, hex, compressed, encrypted, or otherwise wrapped, map decoding as part of the source-to-query path. Encode exact semantic true/false or valid/invalid control pairs and hold the rest of the request constant. Record WAF status changes and controlled SQL behavior—such as repeatable boolean, result-count, error, or bounded timing differences—as separate capabilities.

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

## 7. What successful reports teach

- The User-Agent SQLi report shows that metadata and logging/analytics inputs can reach later queries; include headers, file metadata, webhook fields, and imported records in source-to-query tracing.
- A report involving a `countryFilter[]` input motivates testing collection binders, array expansion, report filters, and dynamic identifier lists rather than only scalar parameters.
- GraphQL and API reports show that a typed outer protocol can still feed unsafe custom filters, sort expressions, search DSLs, or resolver-built SQL.
- Admin/report/export paths often consume low-privilege stored data in a more powerful query context, creating second-order SQLi.
- SQLi-to-RCE reports require database-specific privileges and features; establish those edges rather than assuming them.

## 8. Context-first method

Trace:

```text
source -> transport/binder -> validation/coercion -> query builder/ORM/raw SQL
-> expression position -> database user/replica -> returned or side-effect channel
```

Classify the input position: value, identifier, sort direction, list, JSON path, full-text expression, limit/offset, stored procedure, or query-language fragment. Parameterization solves values but not necessarily attacker-selected identifiers or prebuilt expressions.

Build paired controls appropriate to the observable:

- same request with true/false predicates and stable result-count difference;
- valid/invalid syntax with database-specific error isolated from application validation;
- bounded delay and non-delay controls repeated enough to separate network noise;
- stored marker triggered and not triggered by a later report/admin path.

Do not begin extraction until the program permits it and a minimal controlled value can prove the boundary. Prefer database version/current user or a researcher-owned row over unrelated data.

## 9. False-positive controls

- Hold cache keys, pagination, sorting, session, and result data stable across pairs.
- Confirm an apparent error is database-originated rather than WAF, JSON parser, or generic server failure.
- For timing, interleave control and candidate requests and account for queueing/rate limits.
- For second-order behavior, use unique stored markers and prove which consumer executed the query.
- Preserve the WAF/parser differential and downstream query behavior independently so either can be assessed under the program's scope and reporting rules.
