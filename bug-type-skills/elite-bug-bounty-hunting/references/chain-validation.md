# Exploit-Chain Validation

Use this reference only after at least one primitive or capability has been verified. Its purpose is to test whether verified outputs connect to real downstream boundaries, not to inflate severity with generic possibilities.

## Model capabilities, not bug labels

Represent each step as:

```text
preconditions -> action -> verified output capability -> affected boundary
```

Examples of capabilities:

- read a controlled cross-tenant object;
- set a callback to a controlled destination;
- cause the server to fetch a controlled URL;
- write a controlled file into a specific storage namespace;
- execute a harmless expression in a named worker;
- retain a session after a security transition;
- duplicate a controlled credit;
- influence the next controlled request on one connection.

Avoid labels such as “SSRF to RCE” unless the intermediate capabilities are established.

## Edge contract

Every proposed edge must answer:

| Field | Requirement |
| --- | --- |
| Input | Exact capability supplied by the previous step |
| Preconditions | Role, state, architecture, victim action, and timing required |
| Transformation | How the capability reaches the next component |
| Guard | Security decision or assumption crossed |
| Output | New capability actually obtained |
| Evidence | Controlled observable and negative control |
| Safety | Why validation remains within policy and stop conditions |

If the output of one edge does not satisfy the next edge's exact input, the chain is broken.

## Evidence status

Label each edge:

- **Proven:** reproduced with controlled evidence on the target.
- **Strongly evidenced:** target-specific architecture proves the transition, but policy or safety prevents active confirmation.
- **Plausible:** analogous technique exists, but a target-specific requirement is unverified.
- **Invalid:** control evidence contradicts the transition.

Only proven edges determine demonstrated impact. Strongly evidenced edges may be described separately with the reason testing stopped. Plausible edges must not drive severity.

## Chain-building workflow

1. Freeze the verified primitive and its exact capability.
2. List target features that consume that capability.
3. Select the shortest, safest downstream boundary.
4. Identify every added precondition.
5. Test one edge with controlled data and a negative control.
6. Update the graph and discard invalid branches.
7. Stop when a meaningful high-impact capability is proven or the next edge is unsafe or speculative.

Prefer a short, fully verified chain over a longer dramatic narrative.

## High-value transition questions

### Identity transitions

- Does a leaked or redirected value create a session for the wrong controlled account?
- Can an unverified claim map to an existing local identity?
- Does stale assurance permit a protected action?
- Can one identity attach a stronger login method to another account?

### Authority transitions

- Does a cross-object read expose a capability token, invite, or credential?
- Can a limited action create a stronger role, token, integration, or destination?
- Does copied or exported data land in an attacker-controlled container?

### Server-side transitions

- Does a fetcher carry credentials or return controlled response content to a parser?
- Does stored input reach a privileged template, converter, build, or job worker?
- Can a controlled file or model field invoke behavior rather than remain inert data?

### Parser and edge transitions

- Does a parser mismatch reach a real route, cache, redirect, authorization, or rendering consequence?
- Does an unkeyed input produce a response served to a second controlled session?
- Can cross-request influence be shown entirely with controlled clients?

### State transitions

- Does a duplicate or reordered action produce durable authority or settled value?
- Does an external provider call and internal ledger share one idempotency boundary?
- Can access change between job scheduling and execution?

## Victim-condition realism

Record every required victim condition:

- logged in or already approved;
- opens a normal link or performs a plausible action;
- belongs to a particular tenant or role;
- shares a cache, connection pool, object, or workflow;
- uses a specific client or state.

Do not assume impossible precision, developer tools, proxy modification, disabled browser security, or unreasonable multi-step interaction.

## Impact discipline

Separate:

1. **Primitive:** the first broken boundary.
2. **Demonstrated capability:** the strongest verified output.
3. **Affected asset:** controlled data, authority, value, or execution context.
4. **Breadth:** one object, tenant class, role, or shared infrastructure.
5. **Untested follow-on:** clearly marked and not used as proof.

Do not claim all users, all tenants, full account takeover, internal network compromise, or code execution unless the target-specific chain establishes that breadth.

## Chain anti-patterns

Reject chains that rely on:

- a public report proving behavior on another product;
- a version string proving a deployed vulnerable path;
- an open redirect automatically implying token theft;
- blind SSRF automatically implying metadata access;
- file upload automatically implying execution;
- SQL injection automatically implying operating-system execution;
- XSS automatically implying cookie theft when cookies are inaccessible;
- request smuggling automatically implying victim impact;
- a temporary race result automatically implying settled loss;
- two low-value findings whose outputs and inputs do not connect.

## Safe confirmation ladder

For each new edge:

1. Use a controlled marker, account, object, file, callback, or low-value transaction.
2. Confirm the previous capability reaches the next component.
3. Confirm the new boundary with the least privileged effect.
4. Use a clean-session or authoritative-state check.
5. Stop before secrets, unrelated users, persistence, destructive commands, internal enumeration, or availability impact.

## Required chain output

Return:

- an edge list with evidence status;
- a diagram or compact capability sequence;
- target-specific preconditions;
- strongest demonstrated consequence;
- invalidated branches;
- untested follow-ons and why testing stopped;
- remediation invariants covering the primitive and any magnifying secondary behavior.
