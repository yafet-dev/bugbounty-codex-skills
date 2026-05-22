# Denial-of-Service Methodology

Use this reference to assess asymmetric resource exhaustion safely.

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
