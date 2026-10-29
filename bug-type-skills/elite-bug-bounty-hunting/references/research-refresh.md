# Research Refresh

Use this reference when a stack, standard, framework behavior, public technique, CVE, or program policy may have changed. The purpose is to change the test plan with current evidence, not to accumulate links.

## Refresh order

1. **Program policy:** scope, exclusions, rate limits, prohibited actions, duplicate rules, and policy timestamp.
2. **Observed product evidence:** response headers, client bundles, SDKs, mobile code, error signatures, public repositories, product documentation, and changelogs.
3. **Vendor and standards sources:** framework advisories, release notes, official security documentation, RFCs, and protocol errata.
4. **Original research:** the researcher’s paper, conference material, repository, or technical writeup.
5. **Disclosed platform reports:** reports with enough detail to recover the precondition, broken invariant, proof method, and fix.
6. **Curated methodology:** OWASP, platform research blogs, and annual research roundups for coverage gaps.

Prefer the original source over a copied summary. Search for documented safe behavior and patches as aggressively as for bypasses.

## Canonical discovery surfaces

These are discovery starting points, not embedded truth:

- PortSwigger Research and its annual Top 10 Web Hacking Techniques: `https://portswigger.net/research/`
- HackerOne Hacktivity and disclosed reports: `https://hackerone.com/hacktivity/overview`
- HackerOne researcher and report-quality guidance: `https://docs.hackerone.com/`
- Intigriti researcher research and triage standards: `https://www.intigriti.com/researchers/blog/` and `https://kb.intigriti.com/`
- YesWeHack researcher hub and detailed hunter writeups: `https://www.yeswehack.com/researchers/start-hunting` and the individual `/learn-bug-bounty/...` articles indexed from it
- GitHub Security Advisories and vendor advisory repositories: `https://github.com/advisories`
- NVD CVE API 2.0 documentation: `https://nvd.nist.gov/developers/vulnerabilities`
- CISA Known Exploited Vulnerabilities catalog: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`
- IETF RFC and working-group documents: `https://datatracker.ietf.org/`
- OWASP WSTG and ASVS: `https://wstg.owasp.org/` and `https://asvs.owasp.org/`

When a platform article points to an external researcher, vendor advisory, or patch, follow the primary source before using the lesson.

## Search from architecture, not only bug names

Combine observed nouns with trust boundaries:

```text
<framework version> security advisory middleware authorization
<feature> importer hidden field model callback security
<proxy/CDN> path normalization cache key parser discrepancy
<identity provider> issuer subject email account linking advisory
<ORM/filter language> authorization data leak advisory
<worker/converter> pre-auth deserialization template command injection
site:hackerone.com/reports <feature noun> <boundary>
site:intigriti.com/researchers/blog <framework> <primitive>
site:yeswehack.com/learn-bug-bounty <architecture> <bug class>
```

Search product nouns such as “project template,” “saved report,” “preview worker,” or “remote attachment.” They generalize better than a payload string.

## Normalize every useful source

Record:

| Field | Question |
| --- | --- |
| Retrieval | When was the source checked? |
| Authority | Is it policy, vendor, standard, original research, or a disclosed report? |
| Affected component | Which exact product, version, feature, library, or protocol state is involved? |
| Preconditions | Which role, configuration, object state, or architecture is required? |
| Broken invariant | What did one component trust that another did not guarantee? |
| Boundary | Identity, tenant, namespace, parser, cache, state, network, service identity, or time? |
| Proof pattern | What controlled observable established the issue? |
| Counter-evidence | What safe behavior, patch, or absent precondition would disprove applicability? |
| Sibling surfaces | Which features share the same helper, worker, library, or trust decision? |
| Fix invariant | What property must hold across every equivalent route? |

Feed normalized JSONL items to `scripts/research_triage.py`. Do not feed raw article text or treat script ranking as a vulnerability verdict.

## Dated research cards

The cards below are a seed set checked on 2026-10-29. They are not a static payload library and must not be described as “latest” after that date without refreshing the sources. Use a card only when observed target evidence satisfies its applicability gate.

### Parser and normalization disagreement

- **Source:** YesWeHack, [“The minefield between syntaxes”](https://www.yeswehack.com/learn-bug-bounty/syntax-confusion-ambiguous-parsing-exploits), 2025-10-17.
- **Transferable method:** Write the exact byte or character sequence seen by every parser. Compare alternate but standards-recognized forms such as extended multipart parameters, duplicate fields, Unicode forms, and parser-specific delimiters. Preserve the filter differential and any downstream boundary crossing as distinct capabilities for program-specific assessment.
- **Applicability gate:** At least two observed components parse or normalize the same attacker-controlled value.
- **Counter-evidence:** The guard and final consumer use one canonical representation or reject ambiguous forms before the trust decision.

### Signed structure parsed twice

- **Source:** PortSwigger Research, [“SAML roulette: the hacker always wins”](https://portswigger.net/research/saml-roulette-the-hacker-always-wins), 2025.
- **Transferable method:** For signed XML or another structured token, distinguish the tree that was verified from the tree or attributes later consumed. Review parse-serialize-reparse, namespace handling, comments, CDATA, duplicate identifiers, and library handoffs.
- **Applicability gate:** The target or its identified library verifies one representation and later consumes another.
- **Counter-evidence:** One immutable parsed representation is both verified and consumed, with strict identifier and namespace rules.

### Internal framework cache and layered cache keys

- **Sources:** PortSwigger Research, [“Gotta cache ’em all”](https://portswigger.net/research/gotta-cache-em-all), updated 2026-01-08; Intigriti, [“Exploiting web cache poisoning vulnerabilities”](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-web-cache-poisoning-vulnerabilities), updated 2026-10-15; and the [2025 web-hacking research roundup](https://portswigger.net/research/top-10-web-hacking-techniques-of-2025), published 2026-02-05.
- **Transferable method:** Model browser, CDN, reverse-proxy, framework, and data caches separately. Discover what each layer stores, normalizes, and keys before changing one unkeyed input. Confirm cross-request or cross-user reuse with unique safe routes and two controlled sessions.
- **Applicability gate:** Repeated controlled requests show a cache layer or framework cache whose key and stored response can be observed safely.
- **Counter-evidence:** The candidate response is private/non-stored, the changed input is keyed, or no second controlled client receives the object.

### Middleware provenance and internal sentinel headers

- **Source:** Vercel’s [Next.js middleware authorization-bypass advisory](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw), published 2025-03-21.
- **Transferable method:** Inventory headers, cookies, flags, and route metadata intended to be set only by an internal hop. Trace where they originate, which edge strips them, and whether authorization middleware trusts externally supplied provenance. Search sibling routes that reuse the same internal marker.
- **Applicability gate:** The observed deployment uses the relevant middleware or an analogous internal marker at an authorization boundary.
- **Counter-evidence:** The deployment is patched or protected, the edge removes the value, or the application reauthorizes at the destination.

### Protocol translation and request boundaries

- **Source:** PortSwigger Research, [“HTTP/1.1 must die: the desync endgame”](https://portswigger.net/research/http1-must-die), updated 2025-10-17.
- **Transferable method:** Map every protocol hop and which component chooses message length, routing, and connection reuse. Test only a low-volume, program-permitted differential with controlled canaries; a parsing discrepancy is not impact until a downstream security consequence is demonstrated.
- **Applicability gate:** An observed front end translates to or reuses upstream HTTP/1.1 connections and the program permits this class of testing.
- **Counter-evidence:** End-to-end protocol handling removes the ambiguous hop, connections are not shared, or paired probes do not produce a downstream discrepancy.

### OAuth transaction and issuer binding

- **Source:** IETF [RFC 9700, Best Current Practice for OAuth 2.0 Security](https://datatracker.ietf.org/doc/html/rfc9700), January 2025.
- **Transferable method:** Bind the browser transaction, issuer, exact redirect URI, client, PKCE verifier, state, and OIDC nonce. When several authorization servers exist, test issuer mix-up and account-linking state as separate invariants using controlled providers and accounts.
- **Applicability gate:** The product is an OAuth client, authorization server, broker, or account-linking consumer and the relevant flow is observed.
- **Counter-evidence:** Exact redirects, one-time browser-bound state, PKCE/nonce, issuer validation, and local-account binding all hold in clean sessions.

### Systemic query construction, not only quote parameters

- **Source:** GitHub’s reviewed [CVE-2025-58450 / pREST systemic SQL injection advisory](https://github.com/advisories/GHSA-p46v-f2x8-qp98), published 2025-09-06.
- **Transferable method:** Trace repeated query builders across read, create, update, and delete routes. Separate dynamic identifiers, selected fields, ordering, relations, arrays, filter DSLs, and authorization predicates from safely bound data values. Search shared builders after one primitive is proven.
- **Applicability gate:** Code, error behavior, schema, or product features show a query-building abstraction reachable from controlled input.
- **Counter-evidence:** Every structural choice comes from an allowlist and user data remains parameterized without authority-predicate influence.

### Pre-authentication protocol states

- **Source:** Erlang/OTP’s [unauthenticated SSH RCE advisory](https://github.com/erlang/otp/security/advisories/GHSA-37cp-fgq5-7wc2), published 2025-04-16.
- **Transferable method:** Draw the message/state transition graph and enumerate handlers reachable before authentication, not just routes labelled “login.” Trace whether an out-of-state message can reach a privileged interpreter or command handler.
- **Applicability gate:** The exact exposed protocol, component, version/configuration, and pre-auth handler are evidenced.
- **Counter-evidence:** The target does not expose the component, is patched, or rejects the message before the privileged handler.

### Human-led architecture and impact discipline

- **Sources:** HackerOne, [2025 researcher signals](https://www.hackerone.com/blog/2025-hpsr-researcher-signals), published 2026-01-06; [Quality Reports](https://docs.hackerone.com/en/articles/8475116-quality-reports), updated 2025-02-05; Intigriti [Triage Standards](https://kb.intigriti.com/en/articles/10335710-intigriti-triage-standards), effective 2025.
- **Transferable method:** Use automation for baseline coverage, then apply human architecture and logic analysis. Preserve concise numbered reproduction, expected versus actual behavior, demonstrated impact, and the simplest PoC that proves exploitability. A technical primitive without tangible attacker gain remains a lead.
- **Applicability gate:** Always applicable to research prioritization and report construction, subject to the program’s own rules taking precedence.

Across all cards, transfer the invariant and experiment design—not a payload or severity label. Record the source date, retrieval time, affected component, preconditions, counter-evidence, and target evidence in the research ledger.

## CVE and advisory discipline

A CVE is a code-review lead, not a finding. Before testing or reporting, establish:

1. exact product and version or commit evidence;
2. affected configuration and feature use;
3. vulnerable code path deployed and reachable;
4. patch or mitigation state;
5. attacker preconditions and boundary;
6. controlled runtime confirmation permitted by policy.

Do not report banner matches, dependency presence, or theoretical reachability. Use CISA KEV to understand real-world exploitation priority, not to infer that the target is exploitable.

## Research stopping rule

Stop broad reading when scope is clear and one hypothesis has:

- observed target architecture;
- a named invariant and boundary;
- a baseline and one mutation;
- a negative control;
- a safe proof oracle;
- a stop point.

Return to research when behavior contradicts the model, a component remains unidentified, the technique is version-sensitive, or safe confirmation depends on an unknown protocol guarantee.
