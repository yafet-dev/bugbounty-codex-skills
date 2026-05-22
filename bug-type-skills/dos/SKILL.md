---
name: dos
description: Advanced denial-of-service testing methodology for bug bounty and application security work. Use when testing or reviewing application DoS, web cache poisoning DoS, algorithmic complexity, expensive GraphQL/API queries, large uploads, infinite loops, XMLRPC or brute-force amplification, account lockout abuse, resource exhaustion, cache-key poisoning, decompression or parser bombs, and workflows where small requests can create disproportionate CPU, memory, storage, cache, quota, or availability impact.
---

# Denial-of-Service Testing

## Core Posture

Treat DoS as asymmetry: a small attacker-controlled input causes disproportionate service, user, cache, quota, or workflow disruption.

## Priority Patterns

- Cache poisoning: poisoned CORS, Host, language, path, query, or header variants deny service to many users.
- Expensive APIs: GraphQL aliasing/depth, search, export, rendering, image conversion, reporting, and analytics.
- Upload and parser stress: large payloads, archive bombs, decompression, XML, regex, SVG/PDF/image processing.
- Infinite or near-infinite loops: group names, recursive relationships, callbacks, redirects, and state machines.
- Account or tenant disruption: SSO DoS, account lockout, MFA lockout, organization-wide auth disruption.
- Rate-limit gaps: XMLRPC, basic auth, OTP, login, WebDAV, and old endpoints.

## Assessment Loop

1. Identify attacker-controlled inputs that reach expensive code, cache keys, parsers, or shared state.
2. Estimate amplification: per-request CPU, memory, storage, cache spread, fan-out jobs, third-party quota, or victim count.
3. Prefer low-volume proofs: timing deltas, single-object disruption, controlled cache entry, bounded query cost, or disposable tenant.
4. Test variants: size, depth, alias count, repeated IDs, recursion, malformed values, cache headers, and concurrent requests.
5. Confirm reversible impact without broad disruption.

## High-Value Cues

| Family | Ask |
| --- | --- |
| Cache DoS | Can one poisoned response break many users or origins? |
| Query cost | Can aliases/depth/search create large server work? |
| Parser stress | Can one file/body trigger high CPU, memory, or disk? |
| Workflow loops | Can a state create repeated jobs, emails, or callbacks? |
| Auth lockout | Can A lock out B or an entire org? |
| Quota/cost | Can a public key or API burn paid quota? |

## Variant Playbook

- Increase size, nesting, aliases, repeated fields, page size, export range, and filter complexity gradually.
- Test cache key confusion with Host, Origin, Accept-Language, path, query, cookies, and authorization headers.
- Try compressed payloads, multipart files, archives, SVG/XML/PDF/images, and malformed parser inputs.
- Race or repeat actions that schedule jobs or notifications.
- Compare rate limits by IP, account, token, tenant, endpoint, and client type.

## Confirmation Discipline

Strong evidence shows measurable resource impact, victim impact, shared-cache poisoning, account/org lockout, or expensive quota burn from bounded requests. Avoid broad destructive testing.

## References

Read `references/advanced-methodology.md` only when the task needs deeper cache, GraphQL, parser, upload, lockout, rate-limit, confirmation, or remediation checks.
