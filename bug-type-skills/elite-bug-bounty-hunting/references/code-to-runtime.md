# Code-to-Runtime Vulnerability Research

Use this reference when source code, client bundles, SDKs, schemas, mobile code, configuration, infrastructure definitions, or decompiled artifacts are available.

Static code is a hypothesis generator. A report-quality finding still requires deployed reachability, a broken security invariant, and controlled evidence unless the program explicitly accepts source-only reports.

## Build an entry-to-effect trace

For every candidate, record:

| Stage | Question |
| --- | --- |
| Entry | How can an authorized test actor supply or influence the value? |
| Transformation | Where is it decoded, normalized, cast, copied, stored, serialized, or queued? |
| Guard | What authentication, authorization, validation, state, or allowlist decision applies? |
| Sink | What query, command, template, fetcher, filesystem, serializer, cloud API, or business mutation consumes it? |
| Context | Which user, tenant, service identity, container, network, and environment execute it? |
| Observable | What safe result proves the effect occurred? |

The valuable unit is the complete path, not an isolated dangerous function.

## Start from security invariants

Read code while asking what must remain true:

- the current actor must own or be allowed to act on the object;
- tenant context must come from trusted identity, not a client selector;
- a sensitive transition must be atomic and valid in the current state;
- imported data must not silently invoke privileged callbacks;
- a worker must recheck current authority before producing sensitive output;
- a URL policy and the final network client must agree on the destination;
- a serializer must apply the same audience rules on every route;
- an interpreter must receive data, not attacker-authored instructions.

Search for where that invariant is established, passed, cached, weakened, or assumed.

## High-information review paths

### Authorization drift

Trace all callers of service methods that read, copy, export, mutate, or delete protected objects. Compare controllers, GraphQL resolvers, mobile routes, bulk operations, admin tools, and workers.

Look for authorization based only on a parent object while child data has narrower visibility, or authorization performed at scheduling time but not execution time.

### Model and serializer behavior

Inspect accepted fields beyond the visible UI. Check mass assignment, deserialization, cloning, import/export cleaners, model setters, callbacks, default scopes, and serializers.

A hidden field matters when it triggers a fetch, file operation, privilege change, external request, or other security effect.

### Identity mapping

Trace how emails, provider subjects, issuer, tenant, invitation, and local account identifiers are joined. Look for fallback matching and different normalization across login, linking, and provisioning.

### Query construction

Trace filters, arrays, sort or identifier choices, report builders, stored metadata, and admin analytics into query construction. Distinguish parameterized values from dynamically constructed identifiers or clauses.

### Interpreter and process boundaries

Trace input into template compilation, shell wrappers, deserializers, build hooks, conversion tools, plugin systems, and job runners. Record the actual process identity and sandbox, not an assumed worst case.

### Network fetch boundaries

Trace URL parsing, allowlisting, DNS resolution, redirects, re-resolution, proxy behavior, credentials, response storage, and downstream parsing. Check framework or model callbacks that cause a fetch indirectly.

### Concurrency and state

Identify read-check-write sequences, distributed locks, unique constraints, idempotency keys, external provider calls, retries, event consumers, and reconciliation jobs. Ask which operations share one atomic boundary.

## Reachability gates

Before runtime validation, confirm as much as possible:

1. The route, operation, job, or component is registered.
2. The feature is enabled in the tested environment.
3. The deployed version contains the path.
4. The controlled actor can satisfy all earlier branches.
5. The candidate value reaches the guard and sink after real transformations.
6. The sink is not dead code, test-only code, or a non-production adapter.
7. A safe observable exists.

If these are unknown, design one low-impact probe that resolves the highest-value unknown rather than attempting exploitation.

## Turn code evidence into a runtime experiment

Use this card:

```text
Security invariant:
Entry and required role/state:
Transformations:
Guard and suspected assumption:
Sink and execution context:
Normal baseline:
One changed condition:
Negative control:
Safe observable:
Stop point:
Sibling callers:
```

Keep the first runtime test semantically close to normal product use. Change one actor, object, destination, field, state, route, or timing condition.

## Framework-generated and implicit behavior

Do not review only handwritten routes. Include:

- generated GraphQL connection and node fields;
- ORM callbacks, setters, scopes, and serializer defaults;
- framework route aliases and format handlers;
- upload, preview, and attachment library behavior;
- automatic redirects and URL normalization;
- queue retries and scheduled jobs;
- cloud SDK credential discovery;
- default deserializers and content negotiation;
- mobile deep-link and WebView dispatch.

Framework upgrades can add reachable behavior that the product frontend never uses.

## False-positive filters

Reject or downgrade a candidate when:

- the sink is unreachable in the deployed configuration;
- trusted code constructs the value and no attacker-controlled edge reaches it;
- an earlier normalization makes the dangerous form impossible;
- authorization occurs in a shared service below the visible route;
- a database constraint or transaction enforces the invariant atomically;
- the value is accepted but ignored;
- a callback belongs to the researcher's browser, preview bot, or scanner rather than the target worker;
- the effect exists only in a local development or test environment;
- impact assumes privileges the executing process does not have.

## Safe validation ladder

1. Confirm route and branch reachability.
2. Confirm value propagation with a harmless marker.
3. Confirm the suspected guard difference with paired controlled identities or states.
4. Confirm a reversible controlled effect.
5. Stop when the security boundary is established.

Do not read real secrets, modify unrelated data, run broad commands, enumerate internal networks, or establish persistence to prove code execution or server-side reach.

## Required output

For each serious candidate, return the entry-to-effect trace, runtime reachability evidence, experiment card, result, false-positive controls, root-cause invariant, and sibling code paths worth reviewing.
