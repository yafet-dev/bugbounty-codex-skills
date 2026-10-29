# State, Race, and Business-Logic Research

Use this reference when the product promises uniqueness, ordering, limits, approvals, balances, inventory, settlement, verification, or another business invariant.

Business-logic research begins with the rule the product must preserve, not with malformed input.

## Write the invariant first

Examples:

- a gift card or recovery token is consumed once;
- a refund cannot exceed the settled charge;
- a removed member cannot act after removal;
- an approval cannot be used before it exists or after revocation;
- inventory cannot be sold below zero;
- a tenant cannot apply another tenant's discount or entitlement;
- an action requiring MFA cannot occur under a lower-assurance session;
- an external provider and the internal ledger represent the same operation once.

State the invariant without naming a specific endpoint. This makes adjacent routes and clients visible.

## Build the state-transition table

For the selected object or workflow, record:

| From state | Action | Required actor/condition | Expected next state | Authoritative evidence |
| --- | --- | --- | --- | --- |

Include pending, approved, active, cancelled, failed, expired, refunded, settled, deleted, restored, reconciled, suspended, and retry states where relevant.

Mark transitions performed by background jobs, webhooks, administrators, or third-party providers.

## Establish sequential truth

Before testing races or unusual sequences:

1. Capture the initial authoritative state.
2. Perform the action once normally.
3. Re-read the authoritative state, ledger, inventory, relationship, or audit event.
4. Repeat the same action sequentially.
5. Record the documented or observed duplicate behavior.

Without this baseline, duplicate responses cannot establish a concurrency flaw.

## Sequence and omission testing

Use valid actions in unexpected but plausible orders:

- perform a final step before approval or verification;
- repeat a completed action;
- cancel after fulfillment or approve after cancellation;
- reuse an expired, revoked, or already-consumed capability;
- delete or remove while another action is pending;
- change account, tenant, address, price, role, or destination between steps;
- begin in one client and finish in another;
- replay an old step after a new state has been established;
- omit a step and call the observed final route directly.

Change one sequence fact at a time and verify the durable state.

## Boundary-value method

Test values that remain syntactically valid but challenge the invariant:

- zero, negative, maximum, minimum, partial, and repeated quantities;
- currency, unit, rounding, precision, and conversion boundaries;
- expired, near-expiry, already-used, pending, and reconciled objects;
- mixed owners, tenants, destinations, or funding sources;
- list or bulk operations containing one invalid member;
- optional, omitted, null, and server-defaulted values.

Confirm how the authoritative ledger or object interprets the value. An echoed request is not proof.

## Small, controlled race testing

Use concurrency only after sequential behavior is understood and only where program rules allow it.

1. Use controlled accounts and low-value objects.
2. Capture the exact legitimate request or paired transitions.
3. Synchronize a pair or very small bounded set.
4. Re-read the authoritative state rather than counting successful HTTP responses.
5. Compare with the sequential control.
6. Inspect downstream jobs, notifications, provider calls, and reconciliation.
7. Stop when one durable impossible state is proven.

Useful race pairs include:

- redeem/redeem;
- pay/refund;
- approve/cancel;
- invite/remove;
- verify/change;
- enable/disable;
- create/delete;
- consume/revoke;
- action/membership removal.

Do not use large bursts to turn uncertain behavior into availability impact.

## Atomic-boundary analysis

When a race or duplicate effect is observed, determine which boundary is missing:

- database uniqueness;
- transaction or row lock;
- compare-and-swap on state or version;
- idempotency key bound to the business operation;
- atomic check and mutation;
- distributed lock or single consumer;
- deduplication across web, mobile, API, and worker routes;
- one idempotency domain spanning internal state and an external provider;
- safe retry and webhook replay handling.

This root cause is more reusable than the timing technique.

## Economic and settlement truth

For money, rewards, credits, inventory, and provider-backed actions, separate:

- UI balance;
- pending ledger entry;
- spendable balance;
- provider authorization;
- capture or settlement;
- reconciliation and anti-fraud reversal;
- notification or receipt;
- actual controlled benefit.

State exactly which layer changed and whether it survived. Never claim lasting financial loss from a temporary value that is automatically reversed.

## Cross-channel and shared-service testing

Repeat the invariant through all observed routes:

- web and mobile;
- REST and GraphQL;
- single and bulk operations;
- customer and staff interfaces;
- synchronous and queued processing;
- direct action and webhook or callback;
- current and supported legacy APIs.

Look for different idempotency scopes, normalization, validation, and state checks feeding one ledger or object.

## Background and event-driven workflows

Record event identity, object version, tenant, delivery attempt, ordering key, deduplication key, and retry behavior. Ask whether:

- delayed events can overwrite newer state;
- the same event can apply twice;
- two event types can produce an impossible order;
- authorization is rechecked at consumption time;
- failure after the external side effect causes an unsafe retry;
- reconciliation repairs or hides the issue.

Use controlled objects and wait for normal processing rather than manipulating shared queues.

## Proof requirements

A strong result shows:

- the intended invariant;
- sequential normal behavior;
- the minimal changed sequence, value, or timing;
- an authoritative durable result impossible under the normal workflow;
- downstream settlement or reconciliation status;
- a negative control;
- the smallest affected business capability.

## Anti-noise rules

Do not report:

- two success responses with one backend effect;
- a stale or optimistic UI counter;
- duplicate notifications without duplicate authority or value, unless notifications themselves create material harm;
- a temporary pending entry that normal reconciliation removes;
- behavior documented as retry-safe or eventually consistent without a security consequence;
- a client-side limit enforced correctly by the server;
- a large-load availability effect when the suspected issue is a one-time invariant.

## Safety stop points

Use minimal controlled value and request volume. Do not affect shared inventory, other users, real payouts, external recipients, production availability, or irreversible transactions. Stop at the first durable controlled proof.
