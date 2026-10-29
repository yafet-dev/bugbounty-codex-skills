# Race Condition Methodology

Use this reference to test concurrency-sensitive state transitions.

## Start here: how hunters found this in real reports

1. **Choose a one-time or limited action.** Redemption, payout, refund, invite, verification, inventory purchase, factor change, and approval transitions are good candidates.
2. **Establish sequential behavior.** Send the request once, then again normally, and record final balance, state, ledger, notifications, and downstream jobs.
3. **Send a small synchronized pair.** Duplicate the same valid request or pair opposing actions such as redeem/refund or add/remove.
4. **Inspect the durable result.** In a disclosed gift-card report, the key evidence was multiple wallet credits after identical concurrent redemption, not multiple HTTP successes.
5. **Check reconciliation.** Anti-fraud, settlement, deduplication, or later rollback may remove a temporary effect; state exactly what survives and for how long.
6. **Locate the atomic boundary.** Decide whether the missing guard is uniqueness, idempotency, row locking, compare-and-swap, or a split between internal state and a provider call.

### Expand the pattern

Repeat the minimal pair across web, API, mobile, and background retries. Keep value and request volume low and use only controlled assets.

## 1. Candidate inventory

List one-time tokens, balance updates, redemptions, payments, invites, follows, deletes, approvals, recoveries, MFA, and background jobs.

## 2. Race types

Test identical request races, opposing action races, cross-endpoint races, stale-token races, and job duplication races.

## 3. Timing strategy

Use small controlled bursts, synchronize final bytes where possible, and compare with sequential baseline.

## 4. Confirmation rules

Confirm durable duplicate value, inconsistent membership, duplicated payout, bypassed approval, or impossible state.

## 5. Remediation checklist

- Use atomic database constraints and transactions.
- Make operations idempotent.
- Lock per object/user/token.
- Recheck authorization and state at commit time.
- Add concurrency regression tests.

## 6. Research-derived state-machine method

Use PortSwigger's Smashing the state machine methodology: benchmark normal sequencing, identify a shared state or hidden multi-step sequence, synchronize the smallest request group, look for deviations including second-order effects, and reduce the proof to the minimum race.

The report corpus includes duplicate gift-card redemption, payments, rewards, follows, membership changes, verification, MFA, quotas, and OAuth code use. These are different business effects with the same root causes: check/use separation, non-atomic uniqueness, stale reads, partial construction, duplicated job delivery, or idempotency scoped to the wrong key.

## 7. Candidate model

For each operation record:

```text
precondition read -> authorization -> state/value read -> mutation
-> commit -> event/job/email/provider call -> response
```

Mark the shared record and the invariant. Useful pairs include:

- identical actions competing for a one-time token or quota;
- opposing actions such as accept/revoke, pay/edit, delete/restore, verify/change;
- two endpoints updating the same balance, membership, recovery session, or object;
- create/use during partial construction;
- request and background job both delivering the same side effect.

## 8. Synchronization and locking diagnostics

First send the request group sequentially and record latency, response, state, emails, jobs, and audit events. Then synchronize the final byte or use a single-packet technique only in an authorized, bounded setup.

If requests serialize, determine whether locking is per connection, session, actor, object, tenant, or global. Separate controlled sessions may reveal object-level races masked by session locking. Do not interpret mere parallel completion as a vulnerability.

## 9. Report-derived hypotheses

- Gift-card multiple redemption: uniqueness must be atomic at the value ledger, not enforced by a pre-check.
- Duplicate payment: external provider calls and internal payout records need one idempotency domain.
- MFA race bypass: session assurance and protected-route access must not observe a transient authenticated state.
- Email verification and recovery races: asynchronous delivery can bind a token to state that changes before the email is sent.
- Quota races: database constraints must enforce the limit, not a cached count followed by insert.

## 10. Confirmation controls

- Use unique disposable objects and the smallest concurrency likely to expose the window.
- Prove an impossible durable state or duplicate side effect, then show the sequential control does not produce it.
- Repeat with fresh objects to rule out retries, duplicate UI submission, and eventual consistency.
- Stop before material financial, notification, quota, or availability impact; a single duplicated controlled unit can prove the invariant failure.
