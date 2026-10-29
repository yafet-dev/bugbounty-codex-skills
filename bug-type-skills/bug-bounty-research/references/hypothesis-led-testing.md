# Hypothesis-Led Testing

Use this reference to convert research and observed traffic into high-information, low-impact experiments.

## Contents

- Security model
- Hypothesis grammar
- Differential matrix
- Advanced hypothesis families
- Confirmation ladder
- False-positive controls
- Chain analysis

## 1. Security model

Represent an operation as:

```text
decision = f(actor, credential, object, action, tenant, role, state, purpose, channel, time)
```

Then map the processing path:

```text
client -> edge/cache/WAF -> proxy -> framework/parser -> policy check
       -> data store/worker/integration -> browser/mobile/email/webhook
```

A useful hypothesis identifies which argument is missing, stale, attacker-controlled, checked at the wrong time, or interpreted differently by two components.

## 2. Hypothesis grammar

Use one sentence:

> Because **component** trusts **property** from **source**, **actor** may perform **action** on **asset** across **boundary**; compare **baseline** with **mutation** and confirm through **observable**.

Weak: “Test the endpoint for IDOR.”

Strong: “Because the export worker appears to trust the stored `reportId` without tenant context, a member of tenant A may schedule an export of a tenant B report; compare an A-owned report with a B-owned disposable report and confirm through the generated file and both tenants' audit logs.”

## 3. Differential matrix

Keep the request shape stable and vary one semantic axis.

| Axis | Baseline | Mutations |
| --- | --- | --- |
| Actor | Correct owner | Peer, lower role, other tenant, removed member, unauthenticated |
| Object | Actor-owned | Victim-owned control, parent/child mismatch, deleted, archived, shared |
| Action | Expected read/write | Alternate verb, bulk, export, link, approve, restore, background action |
| State | Normal current state | Pending, expired, canceled, partially created, restored, stale token |
| Context | Correct tenant/purpose | Mismatched tenant, client, redirect, issuer, audience, workflow purpose |
| Channel | Main web route | Mobile, API version, GraphQL resolver, import/export, webhook, worker |
| Parser | Canonical encoding | Equivalent content type, duplicate key, normalization boundary, alternate serialization |
| Time | Sequential | Replayed, concurrent, delayed, precondition changed between check and use |
| Cache | Fresh unique key | Same key with unkeyed input, alternate path interpretation, personalized response |

Use controlled identifiers that make ownership and state obvious. Refresh sessions and cache busters when those layers could contaminate a comparison.

## 4. Advanced hypothesis families

### Cross-surface policy drift

The same action exists in web, mobile, REST, GraphQL, legacy, regional, admin, import/export, or worker code, but only the main route received the newest policy check.

Compare equivalent actions, not merely endpoint names. Carry the same actor, object, role, and state through each surface.

### Hidden and transient states

A single request can traverse partially constructed, pre-verified, post-payment, or pre-commit sub-states. Background email, indexing, thumbnailing, billing, or notification work may observe a different state from the response path.

Benchmark sequential behavior first. Then synchronize only the minimum safe requests and inspect secondary effects, not just responses.

### Stale authority

Capabilities, shares, signed URLs, sessions, refresh tokens, invitations, exports, and cached policy may outlive role removal, password change, tenant exit, object privacy change, deletion, or ownership transfer.

Test before and after a single lifecycle transition with a clean control session.

### Partial policy checks

The route may check that the actor belongs to a tenant but not that the object belongs to that tenant; check object access but not sensitive fields; authorize creation but not the downstream job; validate an OAuth code but not issuer/client/purpose; validate a parent but trust a nested child ID.

Build parent/child and field-level mismatch cases rather than swapping only the most obvious ID.

### Parser and normalization disagreement

The validator, WAF, framework binder, URL parser, cache, database, template engine, filesystem, or browser may see different values.

Establish canonical valid and invalid controls, mutate one grammar boundary at a time, and identify the exact transform. Record the filter differential and downstream security behavior as separate capabilities, then apply the program's own reporting and severity rules.

### Asynchronous authorization gaps

Scheduled exports, imports, webhooks, callbacks, media processors, moderation jobs, and notification workers often run with service privilege. Determine whether they re-authorize the stored object and action at execution time.

Use a controlled object and observe job state, output, audit entry, or callback. Do not infer success from job acceptance alone.

### Capability transport

Reset links, magic links, signed URLs, share tokens, invite links, authorization codes, device codes, and unsubscribe links are bearer capabilities. Test their binding to actor, client, object, purpose, redirect, lifetime, single use, and lifecycle state.

Avoid collecting real-user capabilities. Use only tokens issued to controlled accounts.

### Unsafe trust in integrations

Third-party APIs, identity providers, webhooks, imported documents, remote images, cloud storage events, and billing callbacks may be treated as trusted. Map who signs or authenticates the data, what fields are authoritative, and whether replay, substitution, or tenant confusion is possible.

### Economic and quota invariants

Resource-consumption and business-flow bugs are often broken equations: quantity must be positive, redemption count at most one, balance conserved, paid amount equals fulfilled value, quota checked atomically, and provider cost bounded per actor.

Use the smallest non-harmful values and controlled accounts. Do not generate material cost or load.

## 5. Confirmation ladder

Escalate only as far as needed:

1. Input is accepted and reaches the suspected component.
2. A deterministic differential survives retries and clean controls.
3. A protected read or reversible state change crosses the intended boundary.
4. A secondary system confirms the effect: victim UI, audit log, email, export, callback, cache hit, or worker output.
5. A realistic consequence follows without adding an unverified assumption.

Stop at the lowest rung that proves the issue under the program rules.

## 6. False-positive controls

For every promising result, check:

- public, shared, inherited, or previously granted access;
- stale cache, browser history, service worker, or CDN behavior;
- request accepted but sensitive parameter ignored;
- generic or queued success followed by downstream rejection;
- different objects accidentally sharing test data;
- eventual-consistency delay mistaken for a race;
- random latency mistaken for a time oracle;
- redirect or client-side display hiding a server-side denial;
- DNS, callback scanner, link preview, or security product causing out-of-band noise;
- framework coercion producing a benign default rather than attacker control.

Repeat with new objects and swap control labels when practical.

## 7. Chain analysis

Write each chain as evidence-bearing edges:

| Edge | Required capability | Evidence | Status |
| --- | --- | --- | --- |
| A -> B | What the first primitive grants | Request/response/state proof | Proven / plausible / blocked |
| B -> C | Feature needed for escalation | Target evidence | Proven / plausible / absent |

Do not use generic possibilities such as “could lead to account takeover” as edges. Name the required feature: change recovery email, mint session, read a reset token, bind an identity, execute in a privileged origin, or perform an admin mutation.

Impact is the last proven node, not the most severe node imaginable.
