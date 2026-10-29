# Subdomain Takeover Methodology

Use this reference to test dangling DNS and trusted-origin abuse.

## Start here: how hunters found this in real reports

1. **Resolve the full DNS chain.** Record CNAMEs, aliases, provider hostnames, status responses, and whether the parent organization still references the name.
2. **Prove provider state separately.** A branded error page or dead DNS record is only a clue; determine whether the exact resource type and name are claimable under program rules.
3. **Do not claim a resource unless explicitly allowed.** Prefer provider documentation, a safe ownership check, or program-approved proof.
4. **Map parent-domain trust.** Check cookies, OAuth callbacks, CORS, CSP, postMessage origins, password reset links, email links, mobile deep links, and allowlists.
5. **Use a harmless marker if claim is permitted.** Avoid serving active content to real users or retaining the resource longer than necessary.
6. **State both primitive and consequence.** “Dangling hostname” and “trusted subdomain can receive an OAuth callback” are different levels of evidence.

### Expand the pattern

Review sibling hostnames created by the same deployment process. Real impact usually comes from organizational trust in the hostname, not merely the ability to display a page.

## 1. DNS inventory

Collect CNAME, ALIAS, A/AAAA, NS, MX, TXT, wildcard, staging, regional, and old subdomains.

## 2. Provider checks

Identify cloud/CDN/app-service error fingerprints and whether another account can claim the resource.

## 3. Trust review

Check cookies, CORS, CSP, OAuth redirects, SSO callbacks, static script trust, email links, and production UI links.

## 4. Confirmation rules

Confirm controlled content and a security-relevant trust path.

## 5. Remediation checklist

- Remove dangling DNS.
- Verify cloud resource ownership.
- Narrow cookie domains.
- Restrict OAuth/CORS/CSP allowlists.
- Monitor DNS for drift.

## 6. DNS-to-provider method

Trace the complete delegation and claim chain:

```text
in-scope name -> CNAME/ALIAS/NS/A/AAAA -> provider resource
-> tenant/account claim namespace -> TLS/HTTP routing -> controlled content
```

A provider error fingerprint or NXDOMAIN at one hop is not proof. Determine whether the exact resource identifier can currently be claimed by a different authorized test account, whether provider ownership verification is required, whether the original customer still controls the namespace, and whether wildcard or fallback routing changes the result.

Re-check current provider documentation and behavior. Cloud claim semantics change, and a historically vulnerable fingerprint may now be protected.

## 7. What successful reports teach

- Roblox authentication bypass and Uber auth bypass show that the critical edge is often trust in the parent domain: OAuth callbacks, postMessage origins, cookies, CORS, CSP script allowlists, or login bootstrap.
- CDN and CloudFront reports show that distribution routing and alternate-domain ownership must be tested separately from DNS control.
- Staging, regional, certificate, Storybook, static, and campaign hosts often remain trusted by production after their backing service is removed.
- Email links, password resets, documentation, mobile apps, and old JavaScript bundles can continue directing users to a stale hostname.

## 8. Confirmation and safety

- Confirm the hostname is in scope before any claim attempt.
- Prefer non-invasive provider ownership checks and a harmless unique text file. Do not claim unrelated customer resources or disrupt an active service.
- Record DNS answers, provider response, account used, exact claim step, TLS certificate, and proof that requests for the in-scope hostname reach controlled content.
- Evaluate trust paths individually. Broad cookies may not be readable if `HttpOnly`, OAuth may require exact registered paths, and CSP/CORS may not grant a useful capability.
- Release or transfer the test resource according to program instructions after evidence is preserved; avoid leaving a takeover live.
