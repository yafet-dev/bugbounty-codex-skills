# MFA Bypass Methodology

Use this reference to test factor binding and enforcement.

## Start here: how hunters found this in real reports

1. **Draw the MFA lifecycle.** Include unenrolled, setup started, verified, remembered, recovery, disabled, factor changed, password changed, and account reset.
2. **Capture sessions at each moment.** Keep controlled sessions from before and after enrollment, then retest them after every security transition.
3. **Compare all clients.** Web, mobile, API tokens, desktop, SSO, remembered devices, and support flows may carry different assurance markers.
4. **Try order and state changes.** Start setup in one session, finish in another, reuse setup material, change the factor mid-flow, or access a protected route while verification is pending.
5. **Test session retirement.** One disclosed bug simply enabled MFA on device A while device B remained fully active; the missing step was revoking or downgrading old sessions.
6. **Prove a protected capability.** In a clean controlled session, reach data or an action that the system says requires MFA.

### Expand the pattern

Repeat the same checks after password reset, recovery-code use, factor replacement, and administrator-enforced MFA. Separate a UX gap from a real assurance bypass.

## 1. State matrix

Track not enrolled, pending setup, enrolled, enforced, remembered, recovery, disabled, old session, and admin-policy states.

## 2. Binding checks

Bind factor to user, session, challenge, device, phone/email, tenant, purpose, and expiry.

## 3. Bypass checks

Test blank code, replay, race, challenge swap, factor linking, disable without password, recovery reset, embedded forms, API-only access, and old sessions.

## 4. Client parity

Compare web, mobile, desktop, API, SSO, old app versions, and embedded submission forms.

## 5. Remediation checklist

- Bind MFA challenges to user/session/device.
- Invalidate old sessions after MFA changes.
- Require fresh proof to disable MFA.
- Enforce MFA on all clients and APIs.
- Rate-limit and expire challenges.

## 6. What successful reports teach

- A blank-code bypass illustrates that presence, parsing, and verification must be distinct checks; test malformed or missing values only with controlled accounts and confirm a session was actually promoted.
- Previously valid sessions surviving MFA activation shows that enrollment is a session-policy transition. Inventory existing browser, mobile, API, refresh-token, remembered-device, and app-password sessions before and after every MFA change.
- Embedded forms, alternate clients, team invitations, and account-destruction APIs can enforce a different assurance level from the main web flow.
- Factor enrollment and linking can be an account-takeover primitive when the challenge is not bound to the same user, session, device, and purpose.
- Public race reports show that challenge consumption, session promotion, and verification-state commit must be atomic.

## 7. Assurance-state machine

Model at least these transitions:

```text
password-only -> primary-authenticated -> challenge-issued
-> factor-verified -> high-assurance session
-> remembered device / recovery / factor replacement / disabled
```

For every transition record the session identifier, actor, factor owner, challenge ID, purpose, tenant/policy, expiry, retry count, and credentials minted. Test whether a token issued before the transition gains post-transition authority without re-evaluation.

Separate bypass classes:

- challenge not required on an alternate route;
- challenge accepted without valid proof;
- valid proof bound to the wrong actor, session, factor, or purpose;
- low-assurance session accepted for a high-risk action;
- recovery or device trust silently downgrades policy;
- session or refresh token remains over-privileged after policy changes.

## 8. Confirmation and controls

- Confirm access from a clean client to a resource that explicitly requires MFA, not just a success message.
- Compare the same route before and after policy enablement with fresh and old sessions.
- Test challenge replay and swapping only between researcher-controlled accounts.
- Treat rate-limit, lockout, and notification behavior as separate controls; do not generate material SMS/email cost.
- Verify that disabling, replacing, or recovering a factor requires assurance appropriate to the consequence.
