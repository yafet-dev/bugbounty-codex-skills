# Web Cache Methodology

Use this reference to test shared cache trust.

## Start here: how hunters found this in real reports

1. **Map the layers.** Identify browser cache, CDN, reverse proxy, application cache, origin, and any authenticated edge behavior.
2. **Learn the cache key empirically.** Use unique path markers and change one header, query value, cookie, method, or path suffix at a time.
3. **Separate cache parsing from origin parsing.** Delimiters, path extensions, normalization, and ignored inputs may cause the cache and origin to believe they are serving different resources.
4. **Create a harmless personalized marker.** Use controlled accounts and content that is safe if another clean session receives it.
5. **Prove cross-session reuse.** Prime with one controlled session, fetch with another, and confirm age, hit behavior, and body all refer to the same cached object.
6. **Avoid shared-path poisoning.** Use unique keys and stop after proof; never test availability by contaminating a popular route.

### Expand the pattern

After one cache-key omission is found, test sibling routes and response variants that share the policy. The finding is the unkeyed security-relevant input plus the cross-user result.

## 1. Cache inventory

Record CDN, reverse proxy, cache headers, cache status headers, TTL, purge, and static/dynamic path rules.

## 2. Poisoning checks

Test unkeyed headers, query parameters, path normalization, Host/Origin reflection, language, scheme, and cookies.

## 3. Deception checks

Test private pages with static suffixes, path confusion, extension tricks, and origin/CDN routing differences.

## 4. Confirmation rules

Use separate sessions and cache busters to prove shared cache impact.

## 5. Remediation checklist

- Key on all response-affecting inputs.
- Set private/no-store on sensitive pages.
- Use correct `Vary` headers.
- Normalize paths consistently.
- Avoid reflecting untrusted headers.

## 6. How hunters reason about cache bugs

Use Practical Web Cache Poisoning to reason from unkeyed inputs to a cacheable harmful response, and Gotta cache 'em all to model path and delimiter discrepancies across proprietary cache and origin parsers.

Keep poisoning and deception separate:

- **Poisoning:** attacker input changes a response but is absent or normalized differently in the cache key, so victims receive attacker-influenced content.
- **Deception:** a victim-specific dynamic response is stored under a URL the cache considers static, so another requester can retrieve it.

## 7. Cache-key and layer ledger

For each cache layer record:

| Property | Evidence |
| --- | --- |
| Key | Scheme, host, path normalization, query handling, headers, cookies, method |
| Cacheability | Status, extension, content type, response headers, auth/cookie exceptions |
| Oracle | Age, hit/miss header, stable replay, timing, generated request ID |
| Scope | Browser, POP, region, tenant, host, shared upstream, internal cache |
| Lifetime | TTL, stale behavior, purge, revalidation, error caching |

Use a unique cache buster to isolate your entries while discovering response-affecting inputs. Remove or control the buster only when the program allows shared-cache confirmation and impact cannot be proven otherwise.

For path confusion, separately fingerprint cache and origin interpretation using a known dynamic endpoint, random suffixes, candidate delimiters, and static extensions. Change one path property at a time.

## 8. Report-derived hypotheses

- PayPal cache-poisoning DoS: one poisoned shared response can deny a high-traffic route.
- Postmates information disclosure: cache behavior can expose personalized responses or combine poisoning with data leakage.
- Stored-XSS reports show that a modest reflection becomes high impact when the cache delivers it broadly.
- Web-cache-deception reports exposing CSRF tokens, user IDs, or session-related data show why `Cache-Control` and path mapping must agree at every layer.

## 9. Confirmation and safety

- Use separate controlled sessions and verify a cache hit with an explicit oracle.
- Rule out browser cache, service worker, application-level storage, and ordinary persistence.
- Do not poison shared production keys when a unique keyed path proves the flaw.
- Confirm which input is unkeyed and which response component it changes; a hit/miss difference alone is not a vulnerability.
- Record the exact layer and parser discrepancy so remediation does not merely block one payload.
