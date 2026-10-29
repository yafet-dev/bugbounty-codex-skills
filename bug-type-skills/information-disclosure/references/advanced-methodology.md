# Information Disclosure Methodology

Use this reference to identify unintended audiences for sensitive data.

## Start here: how hunters found this in real reports

1. **Name the sensitive field and intended audience.** Examples: private email visible only to staff, report content visible only to participants, or billing data visible only to an owner.
2. **Build an audience matrix.** Compare anonymous, unrelated user, member, removed member, invited user, owner, and admin.
3. **Search for replicas.** The same field may appear in GraphQL shortcuts, search, autocomplete, exports, emails, notifications, previews, logs, caches, analytics, and mobile responses.
4. **Compare equivalent representations.** Summary versus detail, `edges` versus `nodes`, web versus API, and current versus old endpoints can apply different field filters.
5. **Rule out intentional public data.** Check product behavior and controlled privacy settings rather than inferring sensitivity from a field name.
6. **Prove an audience crossing.** Use controlled records with unmistakable private content and show the unauthorized viewer received that content.

### Expand the pattern

Once one serializer leaks a field, test every object type and delivery channel that reuses it. Report the missing audience rule, not merely the endpoint.

## 1. Data inventory

Classify PII, credentials, tokens, private content, metadata, internal paths, logs, configs, stack traces, source maps, backups, and tenant identifiers.

## 2. Audience matrix

Compare anonymous, user A/B, roles, tenants, mobile/web, API key, removed user, and admin responses.

## 3. Response surfaces

Review JSON, HTML preloads, GraphQL, exports, PDFs, CSVs, emails, notifications, errors, debug pages, Sentry, source maps, and cache.

## 4. Chaining value

Ask whether leaked data enables IDOR, ATO, OAuth abuse, phishing, internal targeting, support impersonation, or tenant enumeration.

## 5. Remediation checklist

- Return only fields needed by the caller.
- Strip debug data from production.
- Protect directories, buckets, logs, and backups.
- Set private cache headers.
- Regression-test field visibility by role and tenant.

## 6. What successful reports teach

- Public RPC and API reports show that knowing a user identifier may be enough to retrieve an over-broad object; see the `userUuid` disclosure. Test field-level audience, not only endpoint authentication.
- The mobile deep-link disclosure shows that sensitive data can cross application boundaries through intents, links, previews, logs, or notifications even when the backend response is authorized.
- Web-cache reports demonstrate that a private response can become public because the cache key or cacheability decision ignores identity.
- Sentry, analytics, status, support, and other third-party products often inherit production data but not production access policy.
- Source maps, backups, build artifacts, and test bundles can reveal secrets or internal routes long after the primary application stopped exposing them.

## 7. Data-lineage method

For each sensitive field trace:

```text
source of truth -> service/API -> serializer -> transport/cache
                -> client storage/rendering -> logs/analytics/export/notification
```

Record the intended audience at every hop. High-value defects occur when a downstream consumer broadens the audience, when an object serializer returns fields the caller did not request, or when a “metadata” field is itself a capability such as a token, signed URL, internal hostname, email, or stable tenant identifier.

Test derived and historical forms: thumbnails, previews, audit entries, deleted-object history, search indexes, exports, webhook payloads, email templates, and cached copies. Deleting or masking the primary field may not remove these replicas.

## 8. Confirmation and classification

- Compare the same object as owner, peer, other tenant, removed member, and unauthenticated client.
- Use unique controlled values to prove which record and pipeline produced the disclosure.
- Distinguish data already public by design from data discoverable only through the candidate path.
- Validate whether a disclosed credential or signed URL is live using the least-privileged, non-mutating request allowed by policy; do not overstate dormant or test-only values.
- Classify impact by sensitivity, audience expansion, scale, lifetime, and capability value rather than response size.
