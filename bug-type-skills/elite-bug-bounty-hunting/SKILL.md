---
name: elite-bug-bounty-hunting
description: Architecture-driven, research-led methodology for authorized bug-bounty and vulnerability-disclosure work where the goal is a reproducible high-impact finding rather than scanner output. Use for deep attack-surface mapping, code-assisted analysis, manual testing, critical server-side or identity flaws, complex exploit chains, and rigorous candidate validation. Do not use to test assets without current authorization, spray payloads, or turn unverified CVE/version matches into findings.
---

# Elite Bug Bounty Hunting

## Outcome

Find a small number of genuine, high-impact security boundary failures. Learn the target's architecture, derive hypotheses from observed behavior and current research, test one assumption at a time, and promote a candidate only when controlled evidence proves exploitability and impact.

Automation may inventory and compare. It must not replace architecture analysis, product understanding, manual reasoning, or proof.

## Authorization Contract

Before active testing, record:

- the current program policy and retrieval time;
- exact included and excluded assets;
- permitted account types, tenants, data, callback infrastructure, and test identities;
- prohibited techniques and classes;
- automation, rate, concurrency, availability, financial, and data-handling limits;
- the stop condition for the planned test.

If ownership, scope, or a limit is ambiguous, perform passive research only. A related domain, shared vendor, leaked credential, public source repository, or matching technology does not create authorization.

Use [`scripts/scope_guard.py`](scripts/scope_guard.py) to check a researcher-authored scope ledger before active work. The script fails closed on stale policy, ambiguous scope, missing controlled identities/data, and undeclared operational limits; it cannot grant authorization.

## Research Freshness Gate

At the start of every deep engagement, use internet research when available to refresh the current program policy, observed product/framework documentation, changelogs, vendor advisories, relevant standards, original researcher publications, and detailed disclosed reports. Record retrieval dates and retain only lessons that change a target-specific hypothesis.

Do not copy payload lists or infer vulnerability from a past report. Extract the required precondition, broken invariant, component boundary, controlled proof pattern, counter-evidence, and sibling surfaces. If live research is unavailable, label the plan provisional and avoid “current,” “latest,” or known-vulnerable claims. Read [`references/research-refresh.md`](references/research-refresh.md) for the source hierarchy, dated technique cards, and normalization method.

## Choose the Operating Mode

Use the narrowest mode that fits the evidence:

| Mode | Use when | Read |
| --- | --- | --- |
| Architecture mapping | The target or feature is unfamiliar | [`references/architecture-modeling.md`](references/architecture-modeling.md) |
| Research refresh | Standards, framework behavior, advisories, or public techniques may have changed | [`references/research-refresh.md`](references/research-refresh.md) |
| Code-assisted analysis | Source, SDKs, bundles, mobile code, IaC, or decompiled clients are available | [`references/code-to-runtime.md`](references/code-to-runtime.md) |
| Identity and authority | Testing auth bypass, IDOR/BOLA, privilege escalation, MFA, sessions, SSO, invitations, or tenant isolation | [`references/identity-authorization.md`](references/identity-authorization.md) |
| Server-side primitives | Testing RCE, SQLi, SSRF, SSTI, file access, deserialization, conversion, or privileged workers | [`references/server-side-primitives.md`](references/server-side-primitives.md) |
| State and business logic | Testing races, payments, approvals, quotas, one-time actions, reconciliation, or workflow order | [`references/state-and-business-logic.md`](references/state-and-business-logic.md) |
| Parser, cache, and edge | Testing request smuggling, cache poisoning/deception, URL drift, WAF differentials, middleware, or protocol translation | [`references/parser-cache-edge.md`](references/parser-cache-edge.md) |
| Client and cross-origin | Testing XSS, POST-reflected XSS, DOM flows, postMessage, CSRF, browser delivery, or client-side chains | [`references/client-side-and-cross-origin.md`](references/client-side-and-cross-origin.md) |
| Chain analysis | At least one primitive is already verified | [`references/chain-validation.md`](references/chain-validation.md) |
| Candidate validation | A possible finding needs reproducibility, false-positive controls, or an evidence packet | [`references/poc-and-evidence.md`](references/poc-and-evidence.md) |

Do not load every reference by default. Start with the architecture and suspected boundary, then read only the matching playbook.

## Core Workflow

### 1. Build the target model

Map connected graphs rather than a flat URL list:

- identity: login, recovery, sessions, MFA, federation, invitations, linking, service identities;
- authority: roles, tenants, namespaces, ownership, delegation, shares, billing authority;
- state: pending, verified, approved, active, archived, deleted, restored, refunded, settled, revoked;
- data flow: input, decoder, edge, router, binder, guard, service, model callback, queue, worker, sink, delivery;
- deployment: browser/mobile, CDN/cache, gateway, application, internal service, database/storage, cloud identity, third party.

Mark each edge where components may disagree about identity, ownership, state, parsing, URL authority, cache keys, time, or trust provenance.

### 2. Name the security invariant

Write the product promise before choosing a test. Examples:

- a project member cannot export another tenant's private child objects;
- a callback is bound to the client, user session, and exact registered destination;
- one gift card produces one durable credit;
- only the final canonical URL is authorized before a server fetch;
- a pre-authentication protocol state cannot reach privileged command handlers.

If the expected secure behavior is unknown, research the feature or observe a normal controlled flow first.

### 3. Generate target-specific hypotheses

Derive hypotheses from architecture, code, product documentation, observed clients, current advisories, original research, and disclosed reports. Phrase each one as:

> Because component A trusts property X from component B, actor Y may cross boundary Z. Compare baseline M with one change N and confirm using controlled observable O.

Favor unconventional but evidenced surfaces:

- old, mobile, GraphQL, bulk, import/export, and administrative routes for the same action;
- hidden model fields and framework-generated helpers;
- background workers, operators, converters, previewers, and delayed delivery;
- internal or sentinel headers whose provenance may be forgeable;
- parent/child visibility mismatches and cross-namespace references;
- parser, normalization, protocol downgrade, cache-key, and middleware disagreements;
- saved reports, filter DSLs, dynamic identifiers, arrays, and second-order execution;
- pre-authentication state handlers and interpreters reached before the intended gate;
- reconciliation, retries, idempotency, and alternate business channels.

### 4. Rank for information and impact

Prioritize a hypothesis when it has:

- a high-value asset, identity, authority, or business invariant;
- strong evidence that the feature and architecture exist;
- a short attacker-to-impact path;
- a safe, authoritative proof oracle;
- likely reuse across sibling features;
- low operational risk and few speculative dependencies.

Deprioritize scanner-only signals, banner/version matches, intended public behavior, long chains with unverified edges, and tests whose proof would be unsafe.

Use [`scripts/research_triage.py`](scripts/research_triage.py) to normalize already-collected research and rank it by computed architecture match and anchored target evidence. It does not browse or scan.

### 5. Design the experiment

Every active experiment needs:

- a normal baseline;
- one semantic change;
- an expected secure result;
- a negative control;
- a controlled proof observable;
- a stop point.

Change one axis at a time: actor, object, tenant, role, state, order, timing, transport, parser, content type, client, cache key, destination, or downstream consumer. Keep exact requests and authoritative before/after state.

### 6. Test manually, then automate narrowly

Run the highest-information test first. Automate only a stable comparison whose volume and safety are already understood. Use scanners for coverage and clues, not verdicts.

When source is available, trace entry, transformations, guard, sink, runtime reachability, service identity, and safe oracle. A dangerous function in source is not a finding until the deployed path and boundary consequence are shown or the program explicitly accepts source-only reports.

### 7. Confirm the primitive

A candidate becomes a verified primitive only when evidence shows:

- the named invariant;
- a reproducible baseline;
- one explainable condition that breaks it;
- a negative control;
- an actual boundary crossing;
- a controlled primary or secondary observable;
- authoritative or victim-side state where applicable;
- repeatability without unrelated-user impact.

Use [`scripts/evidence_lab.py`](scripts/evidence_lab.py) `diff-http` for offline comparison of saved transcripts. It never renders HTML, replays traffic, or treats a status/body difference as exploit proof.

### 8. Validate chains edge by edge

Represent a chain as:

```text
verified primitive -> gained capability -> next reachable boundary -> verified consequence
```

For every edge, record preconditions, identity/tenant context, controlled evidence, and whether it is proven, safely inferred, or untested. The previous edge's output must actually satisfy the next edge's input. Report the last verified consequence separately from possible follow-ons.

### 9. Search siblings by root cause

After confirmation, search callers and consumers that reuse the same guard, serializer, model, worker, parser, cache rule, identity mapper, ledger, or third-party integration. Do not multiply one shared sink into duplicate findings without program-specific justification.

### 10. Produce the evidence packet

Use [`scripts/evidence_lab.py`](scripts/evidence_lab.py) `packet` to create a sanitized packet containing the scope snapshot, architecture evidence, hypothesis, baseline, one change, negative control, reproduction notes, evidence hashes, proven impact, unverified follow-ons, stop condition, and remediation invariant.

## Anti-Noise Gates

Do not report a candidate based only on:

- an HTTP status, response length, generic error, or one timing outlier;
- reflection without execution in a normal browser and intended origin;
- POST-reflected XSS that requires proxy modification and cannot be delivered to a realistic victim;
- GraphQL introspection, schema presence, or accepted-but-ignored fields;
- removal of a client-side restriction without server-side effect;
- a version banner or CVE match without affected-code reachability;
- DNS/HTTP callbacks that may come from browsers, previews, or security scanners;
- multiple success responses without authoritative durable state;
- temporary value that reconciliation reverses;
- public or inherited data described as private;
- an open redirect that preserves no capability and has no trusted consumer;
- blind SSRF without proving the target-owned fetcher and relevant security boundary;
- source-level sinks disabled or unreachable in the deployed configuration;
- a chain whose severity depends on an unverified edge.

## Safety and Stop Rules

Stop when scope becomes uncertain, unrelated data appears, minimum proof is complete, or the next step risks availability, irreversible state, spam, financial loss, third-party resource claims, credential use, persistence, or broader authority than the policy grants.

Use controlled accounts, tenants, objects, files, inboxes, payment value, callbacks, and client sessions. Keep concurrency and resource tests small. Do not retrieve real secrets merely to strengthen impact.

## Required Outputs

Maintain only the artifacts useful to the engagement:

- scope ledger and policy timestamp;
- architecture/trust-boundary model;
- high-value assets and security invariants;
- prioritized hypothesis board;
- experiment ledger with disproved assumptions;
- verified primitive and chain graph;
- sanitized evidence packet.

For schemas and examples used by the scripts, read [`references/engagement-artifacts.md`](references/engagement-artifacts.md).
