# Business Logic Methodology

Use this reference to test product invariants across multi-step flows.

## Start here: how hunters found this in real reports

1. **State the rule.** Examples: a gift card is redeemed once; a refund cannot exceed the charge; an invite is accepted only while pending.
2. **Record the normal sequence and final state.** Capture balance, status, ownership, inventory, audit events, and downstream notifications.
3. **Change the sequence, not random bytes.** Repeat, omit, reorder, reverse, cancel, retry, or cross web/mobile/API routes.
4. **Try boundary values that still parse.** Zero, negative, maximum, partial, duplicate, mixed currency, expired, or already-consumed states often reveal a missing invariant.
5. **Test concurrency only after sequential behavior is known.** A small synchronized pair is more informative than a large burst.
6. **Judge the durable business result.** Multiple success messages are weak; duplicated credit, a forbidden state, or a settled downstream action is strong.

### Expand the pattern

Search adjacent workflows that share the same ledger, state machine, coupon engine, approval service, or job queue. Include reconciliation and anti-fraud behavior before claiming lasting financial impact.

## 1. Workflow inventory

Record actor, object, state, prerequisite, action, side effect, and downstream consumer for every step. Include UI, API, emails, background jobs, webhooks, exports, and mobile routes.

## 2. State matrix

Test before/after states: unpaid, paid, pending, approved, rejected, deleted, restored, archived, canceled, refunded, verified, unverified, invited, accepted, blocked, and removed.

## 3. Value-flow checks

Review quantity, price, tax, currency, discount, credits, wallet balance, coupon, gift card, refund, subscription period, booking duration, and shipping fields. Confirm server-side recomputation.

## 4. Sequence checks

Try skipping, repeating, reordering, pausing, resuming, and racing steps. Use old links and stale tokens after the flow advances.

## 5. Cross-feature checks

Combine features that were designed separately: template copy, import/export, sharing, invitations, recovery, abuse reporting, moderation, migration, and restore.

## 6. Confirmation rules

Confirm durable business impact: money, access, private data, victim effect, moderation effect, approval bypass, or system-of-record mutation.

## 7. Remediation checklist

- Enforce product invariants server-side.
- Recompute financial and approval state.
- Treat workflow state transitions as policy decisions.
- Make stale links and retired states fail closed.
- Add regression tests for ordering, replay, stale state, negative values, duplicate redemption, and downstream jobs.

## 8. What successful reports teach

Public reports repeatedly show that the vulnerable decision is often separated from the obvious request:

- **Copy and clone are authorization decisions.** GitLab's project-template report shows why every copied child object needs a fresh destination-context policy check; do not assume access to a template authorizes its repositories, issues, snippets, secrets, or history.
- **Valid numeric syntax can violate business equations.** The negative-quantity report suggests testing conservation rules across subtotal, discount, tax, credit, refund, provider charge, and fulfillment rather than mutating `quantity` alone.
- **Safety features create delegated authority.** The abuse-report deletion report motivates tracing report, flag, block, moderation, and takedown flows through thresholds, reviewer state, automation, and restoration.
- **Verification is a state transition, not a UI screen.** OTP or response-manipulation bypass reports suggest checking whether downstream consumers use an unverified object before the authoritative verification state commits.
- **Entitlements drift across clients.** Subscription or role-gate reports suggest comparing web, mobile, API, export, invite, and background-job enforcement for the same paid capability.

## 9. Invariant and consumer analysis

Write invariants as equations or predicates that can be checked at each state transition:

```text
fulfilled_value <= settled_value
refund_total <= captured_total - prior_refunds
redemption_count(actor, instrument) <= allowed_count
effective_role <= purchased_or_granted_role
copied_child_set subset_of source_children_visible_to(actor)
```

Map who computes each value and who later trusts it. High-value gaps occur when the UI validates a field but a worker trusts it, a payment callback updates only one ledger, a refund uses stale price data, or a copy/import operation preserves source authority in the destination.

Test one invariant across sequence, concurrency, cancellation, retries, partial failure, currency/rounding, and downstream delivery. Use the smallest controlled value and confirm both the system of record and the external side effect.

## 10. Controls

- Compare an impossible but syntactically valid mutation with a normal boundary value and a clearly invalid value.
- Check whether a temporary response is rolled back before fulfillment, billing, export, notification, or entitlement use.
- Repeat with a fresh cart, token, coupon, invite, or test object to rule out residual state.
- Separate an intentionally flexible product rule from an invariant by checking first-party documentation and equivalent UI flows.
