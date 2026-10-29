# Architecture-Adaptive Attack-Surface Modeling

Use this reference when the target is unfamiliar, when several technologies meet, or when endpoint-by-endpoint testing is producing low-value noise.

The goal is not to draw a perfect system diagram. Build the smallest model that reveals where security decisions can disagree.

## Start with business assets

List what would create material impact if crossed or controlled:

- user and administrator identities;
- tenant membership, roles, invitations, and delegated authority;
- secrets, private objects, billing records, reports, and exports;
- money, credits, inventory, rewards, approvals, and irreversible actions;
- deployment, build, integration, webhook, and cloud-service authority;
- moderation, support, and internal operational interfaces.

For each asset, record its owner, intended audience, lifecycle, authoritative store, and actions that change it. This prevents the assessment from optimizing for technical novelty while missing the product's real security boundaries.

## Build five connected views

### Identity view

Map login, recovery, MFA, SSO, OAuth linking, invitations, sessions, remembered devices, API tokens, service accounts, mobile identities, support recovery, and reauthentication.

Ask where an identity claim changes form: email to account, provider subject to local user, session to API token, invite to membership, or device approval to durable session.

### Authority view

Map owner, member, guest, removed member, suspended user, tenant administrator, platform staff, integration, and anonymous access. Include inherited roles, group membership, sharing, delegated billing, and object-specific grants.

Do not model roles as a single ladder. A billing administrator, project owner, and support user may have incomparable powers.

### State view

Map security-relevant states and transitions: pending, verified, approved, active, archived, deleted, restored, refunded, settled, revoked, expired, locked, suspended, and reconciled.

Mark the actor and condition allowed to trigger every transition. Note background transitions and transitions that span several services.

### Data-flow view

Follow high-value input through:

```text
client -> edge/proxy -> router -> binder/decoder -> validator
       -> service -> model callback -> queue -> worker
       -> database/storage/renderer -> browser, API, email, or third party
```

At each edge, record identity context, tenant context, transformations, validation, credentials, and the observable result.

### Deployment view

Map browser and mobile clients, CDN/cache, API gateway, application services, GraphQL or RPC layers, workers, databases, object storage, internal admin services, identity providers, cloud metadata, CI/CD, and third-party integrations.

Mark where requests change protocol or trust domain. Many high-impact findings live at these seams rather than in the main application route.

## Discover the architecture from evidence

Prefer evidence with a clear origin:

- normal browser and mobile traffic;
- public product, API, SDK, and integration documentation;
- JavaScript bundles, mobile code, schemas, and route definitions;
- response headers, error shapes, cookies, redirects, and cache behavior;
- source code, configuration, IaC, queue definitions, and dependency manifests when authorized;
- controlled object lifecycle, audit logs, emails, exports, and webhook deliveries.

Label every component as observed, strongly inferred, or unknown. Do not turn a product name in a header into an assumed deployment architecture.

## Convert seams into hypotheses

Prioritize places where two components may disagree about:

- who the caller is;
- which tenant or owner applies;
- whether an object is public, private, deleted, or pending;
- whether a session has completed the current assurance policy;
- how a URL, path, body, or request boundary is parsed;
- which fields belong in a cache key;
- whether an earlier authorization decision remains valid for a worker;
- whether imported data is inert data or invokes model behavior;
- whether a child object inherits the parent's visibility;
- whether a retry is the same business operation or a new one.

Write the hypothesis in falsifiable form:

> Because **component A** trusts **property X** from **component B**, **controlled actor Y** may gain **capability Z** across **boundary Q**. Compare **baseline** with **one changed condition** and confirm using **observable O**.

## Adapt strategy to architecture

### Monolith with server-rendered pages

Look for shared controller filters, mass assignment, legacy routes, template context, session-state drift, and differences between visible forms and accepted model attributes.

### API-first or microservice system

Focus on identity propagation, tenant headers, service-to-service credentials, asynchronous authorization, retry semantics, schema drift, and gateway-versus-service validation.

### GraphQL system

Model resolver and loader paths. Compare direct node lookup, nested traversal, connection shortcuts, generated fields, persisted operations, and matching REST behavior.

### Event-driven or job-heavy system

Record the identity and authorization snapshot stored with each job. Test whether current state is re-read before processing and whether duplicate or reordered events violate an invariant.

### CDN or multi-proxy system

Model cache keys, routing normalization, forwarded identity, protocol conversion, and which layer applies each security decision.

### Mobile or desktop client

Treat the client as route and schema documentation. Confirm every locally enforced role, state, or integrity check on the server. Map deep links and web-to-app handoffs.

### Import, export, or conversion platform

Inspect serialized fields, hidden model properties, archive members, remote attachments, parser callbacks, renderer credentials, storage destinations, and delayed processing.

## Architecture readiness gate

Do not begin broad active testing until the current hypothesis names:

- an in-scope entry point;
- a protected asset or authority;
- the two components or states suspected to disagree;
- the controlled identities or objects required;
- expected secure behavior;
- one safe confirmation oracle;
- a stop point.

If one is missing, gather targeted evidence instead of spraying inputs.

## Anti-noise checks

Do not promote these to architecture facts:

- scanner technology guesses without a second signal;
- a version string without deployed-feature reachability;
- a single error or timing outlier;
- an endpoint name that implies an internal service but behaves like a normal public route;
- a client-side route that has no server operation;
- a public schema field with no sensitive data or action;
- a DNS or callback event that may come from a security scanner or preview service.

## Required output

Return a compact model containing:

1. high-value assets;
2. identities and authority boundaries;
3. important states and transitions;
4. data and deployment flows;
5. observed trust seams;
6. unknowns that block safe testing;
7. an evidence-supported ranked hypothesis set, usually three to ten items, each with a baseline, one change, oracle, and stop point.

Never invent hypotheses to reach a quota. Return one or two strong hypotheses when that is all the observed architecture supports, and list the missing evidence needed to expand the board.
