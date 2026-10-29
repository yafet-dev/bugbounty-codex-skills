# Request Smuggling Methodology

Use this reference to test HTTP parser desynchronization.

## Start here: how hunters found this in real reports

1. **Confirm the architecture.** Identify a front end and back end that may parse request boundaries differently; avoid testing when program rules prohibit desynchronization work.
2. **Use a harmless canary.** Demonstrate a stable queue or connection desync against your own follow-up request before involving any victim-like behavior.
3. **Reduce the disagreement.** Change one header spelling, whitespace rule, length, transfer rule, protocol hop, or connection behavior at a time.
4. **Search for the second bug.** One critical report became exploitable because a smuggled request reached a backend redirect behavior that forwarded a later user to a controlled host.
5. **Model the victim boundary safely.** Use controlled clients and distinct markers to show cross-request influence without collecting another person’s data.
6. **Retest the exact parser gap after fixes.** Also test whether the dangerous secondary behavior remains useful if another desync variant appears.

### Expand the pattern

A parser mismatch alone may be weak or unsafe to assess. The valuable methodology is: prove the mismatch minimally, then look for a concrete cache, routing, redirect, or authorization consequence.

## 1. Stack inventory

Record CDN, WAF, reverse proxy, load balancer, origin, protocol versions, keep-alive, and cache behavior.

## 2. Variant families

Test CL.TE, TE.CL, TE.TE, duplicate CL, malformed TE, whitespace, casing, HTTP/2 downgrade, and pseudoheader ambiguity.

## 3. Impact checks

Review response queue poisoning, cache poisoning, auth bypass, internal path tunneling, credential capture, and request prefix injection.

## 4. Confirmation rules

Use controlled canaries and isolated accounts. Show parser disagreement plus a security boundary crossed.

## 5. Remediation checklist

- Normalize/reject ambiguous framing at the edge.
- Keep proxy/origin parser behavior consistent.
- Disable risky downgrade behavior.
- Close connections on malformed requests.
- Add desync regression tests.

## 6. Current variant model

Use PortSwigger's request-smuggling research to keep the model current. Classic CL.TE and TE.CL are only part of the surface. Include HTTP/2 downgrade and pseudo-header handling, request splitting, CL.0/0.CL conditions, browser-powered client-side desynchronization, connection-state attacks, and request tunneling where the target topology supports them.

Do not spray ambiguous requests. First identify the exact hop pair, protocol on each leg, connection reuse, normalization, and whether the program permits desync testing.

## 7. Topology and differential method

Record:

| Hop | Protocol | Framing/normalization | Connection reuse | Security role |
| --- | --- | --- | --- | --- |
| Client to edge | H1/H2/H3 | Header and pseudo-header rules | Client-specific | Browser/API input |
| Edge to proxy | H1/H2 | Downgrade, rewriting, coalescing | Pool scope | WAF/cache/routing |
| Proxy to origin | H1/H2 | CL/TE interpretation | Shared or dedicated | Application boundary |

Use a baseline request, a harmless malformed control, and one candidate ambiguity. Observe timeouts, connection reuse, response ordering, and a unique canary on an isolated connection. Reproduce across fresh connections and rule out ordinary pipelining, retry, multiplexing, and cache behavior.

## 8. Report-derived impact paths

- Slack mass account takeover, password theft, and token-capture reports show that queue poisoning becomes critical only when the desynchronized prefix can capture or alter another request.
- HTTP/2 smuggling shows that secure H2 at the client side does not eliminate downgrade disagreement downstream.
- Parser-bug reports involving malformed transfer coding, carriage-return normalization, hop-by-hop headers, or host rewrite show why a specific differential matters more than a generic variant name.
- Cache poisoning, front-end access-control bypass, internal routing, and request tunneling each require a different target capability; verify the edge before claiming it.

## 9. Safety and false-positive controls

- Use dedicated test accounts, unique paths, cache busters, and low-traffic windows if the program explicitly allows the technique.
- Prefer single-connection/self-impact confirmation. Do not target or wait for unrelated-user requests.
- Follow the current false-positive guidance for distinguishing pipelining and retry artifacts from a poisoned shared connection.
- Stop when a parser disagreement and a controlled boundary crossing are proven; do not pursue credential capture from real users.
- Report the hop pair, parsing discrepancy, connection prerequisite, and minimal security effect separately.
