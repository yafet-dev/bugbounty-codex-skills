# Denial-of-Service Methodology

Use this reference to assess asymmetric resource exhaustion safely.

## Start here: how hunters found this in real reports

1. **Find amplification.** Look for one request that expands into many resolver calls, conversions, database scans, recursive operations, webhooks, emails, or third-party API calls.
2. **Establish a tiny baseline.** Measure normal response time, job count, downstream calls, or a documented quota using one controlled object.
3. **Increase one dimension slowly.** Add a few aliases, nesting levels, list items, file pages, or repeated operations; stop before service degradation.
4. **Separate client delay from server cost.** A slow response is not enough—look for queue growth, repeated provider calls, timeouts, or work that continues after disconnect.
5. **Test whether limits count requests or actual work.** GraphQL aliases, batches, retries, and background fan-out often multiply work behind one HTTP request.
6. **Report the smallest reproducible ratio.** Explain how little attacker effort creates how much backend work without load testing production.

### Expand the pattern

Use controlled objects and conservative limits. Do not prove availability impact by exhausting resources; demonstrate the missing bound and the measured amplification.

## 1. Surface inventory

List cacheable pages, APIs, GraphQL, exports, uploads, search, renderers, auth endpoints, callbacks, notifications, and background jobs.

## 2. Resource model

Track CPU, memory, disk, database queries, cache entries, queue jobs, emails, third-party quota, and affected users.

## 3. Test families

Test cache poisoning, large payloads, nested payloads, GraphQL aliases, regex complexity, parser bombs, upload processing, recursion, and lockout abuse.

## 4. Rate-limit review

Compare throttles by IP, account, tenant, token, endpoint, device, and operation cost.

## 5. Confirmation rules

Use controlled, reversible evidence: timing, one cache key, one test account, one tenant, bounded query, or local reproduction.

## 6. Remediation checklist

- Bound input size, depth, aliases, page size, export range, and file complexity.
- Add operation cost accounting.
- Fix cache keys and private cache headers.
- Rate-limit by cost and identity.
- Add timeouts and queue limits.

## 7. What successful reports teach

The report corpus broadens DoS beyond “large request” testing:

- Shared cache poisoning can make one small request deny service to many users; public reports include PayPal cache-poisoning DoS and CDN cases.
- A stored oversized field can make a profile, issue, or organization expensive or impossible for every viewer, as in the large profile-picture-name report.
- GraphQL aliases and repeated mutations can multiply downstream SMS, email, verification, or provider work; see the account-recovery aliasing report.
- SSO, recovery, and lockout endpoints can create targeted availability loss for a tenant or victim account without high system load.
- Renderers, diagram engines, recursive parsers, archives, and media processors may amplify a small stored input during every view or background retry.

## 8. Cost and blast-radius model

Estimate rather than stress:

```text
amplification = server_work_or_external_cost / attacker_work
blast_radius = affected_users_or_tenants / attacker_requests
recovery = automatic expiry | cache purge | job drain | manual repair
```

Map independent budgets: request CPU, database fan-out, memory, response size, storage, cache cardinality, worker queue, provider calls, notification volume, and per-victim lockout. A global rate limit does not protect a single expensive query, and a per-IP limit does not protect shared third-party cost.

Use local reproduction, vendor-provided labs, one controlled cache key, one test tenant, or a minimal operation whose cost is visible in response metadata. Do not increase volume merely to prove an obvious linear trend.

## 9. Controls and stop conditions

- Compare the candidate with a same-size cheap input to separate size from algorithmic complexity.
- Measure a sequential baseline before testing bounded parallelism.
- Confirm whether work continues after client disconnect, cancellation, or a failed response.
- Stop immediately on elevated latency for unrelated users, queue growth, provider messages, or program rate-limit warnings.
- Report the amplification mechanism and affected shared resource even when policy forbids demonstrating outage.
