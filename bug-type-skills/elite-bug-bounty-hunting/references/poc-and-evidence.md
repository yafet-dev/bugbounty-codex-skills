# Reproducible PoC and Evidence Standard

Use this reference to turn a candidate into a minimal, safe, reviewable finding. The goal is causal proof, not an impressive payload or a large evidence dump.

## Experiment card

Complete this before testing:

```text
In-scope asset and policy limit:
Security promise or invariant:
Controlled actor, object, tenant, and state:
Normal baseline:
Expected secure result:
One changed condition:
Negative control:
Primary proof observable:
Secondary proof observable:
Safety stop point:
Cleanup or reversal:
```

If the expected secure result or proof observable is unknown, research the feature before mutating it.

## Proof ladder

Use the lowest step that establishes the boundary:

1. **Reachability:** the feature, route, branch, or worker exists.
2. **Propagation:** a harmless unique marker reaches the suspected component.
3. **Decision difference:** a paired control shows the security decision changes under one condition.
4. **Controlled boundary crossing:** protected controlled data or authority crosses the intended boundary.
5. **Durable consequence:** the authoritative state, session, ledger, file, or audit trail confirms the result.
6. **Safe chain edge:** the verified capability reaches one additional controlled boundary.

Stop as soon as the report's security claim is proven. Do not escalate merely because a more dramatic proof is imaginable.

## Baseline and negative controls

A useful baseline is the same legitimate workflow with the intended actor, object, state, route, and timing.

Choose a negative control that distinguishes the suspected cause:

- remove the changed field;
- use a second unique marker;
- use the authorized actor or owned object;
- use a destination known not to trigger the callback;
- send requests sequentially instead of concurrently;
- fetch with a clean session and unique cache key;
- request the safe resolver path instead of the suspected alternate path;
- use a literal value where a parser-specific value is suspected.

Do not change several semantic facts at once.

## Authoritative evidence by finding type

### Authorization and IDOR

Verify the victim-controlled object, audit log, notification, export, or clean attacker view. A success-shaped response without protected data or state change is insufficient.

### Authentication and session

Use a fresh browser or isolated cookie jar. Prove which controlled local account, tenant, and assurance level the session reaches and which protected capability it can perform.

### XSS and browser issues

Confirm execution in a normal browser under the intended target origin and viewer. Raw reflection, proxy rendering, disabled browser security, or manual developer-console execution is insufficient.

For POST-based reflected XSS, submit the legitimate POST through a browser-compatible delivery path, confirm the response renders as active content, and explain how the intended controlled victim can realistically issue that POST. A payload visible only after manual proxy modification is self-XSS or a non-deliverable lead.

### SSRF and callbacks

Use unique controlled destinations plus a no-callback control. Correlate method, source, headers, timing, redirects, and stored output to distinguish the target fetcher from browsers, scanners, and preview bots.

### SQLi and other query influence

Use repeated paired true/false, valid/invalid, or bounded timing controls. Demonstrate controlled query influence without dumping unrelated records or modifying production data.

### RCE, SSTI, and interpreter boundaries

Use harmless arithmetic, a controlled error, a benign file or callback marker, or another reversible effect. Record the actual worker, process, sandbox, and identity. Do not read secrets, establish persistence, or run broad commands.

### Race and business logic

Compare the sequential baseline with a small synchronized attempt. Verify the authoritative ledger or object and include reconciliation or settlement behavior. Multiple HTTP successes are not enough.

### Cache behavior

Use unique cache keys and two controlled sessions. Show which input is unkeyed, which response was stored, and that the second session received the same object. Never poison a popular shared route.

### Parser and request-boundary differences

Identify both interpretations with controlled clients or canaries. Preserve the control differential, status or connection behavior, and any downstream effect as separate evidence, then follow the program's rules when deciding how to report them.

## Reproducibility standard

A reviewer should be able to reproduce using:

- exact prerequisites and controlled roles;
- clean starting state;
- minimal numbered actions;
- complete relevant request data with secrets redacted;
- expected baseline and actual result;
- negative control;
- authoritative final-state check;
- timing or concurrency details where essential;
- cleanup instructions.

Avoid relying on unexplained tool state, old cookies, browser extensions, stale cache, or prior requests.

## Evidence capture

Preserve only what supports the causal claim:

- request and response or normalized transcript;
- timestamps and correlation identifiers;
- before and after authoritative state;
- controlled callback entry;
- browser origin and rendered DOM when relevant;
- role, tenant, object, and lifecycle state;
- audit, notification, ledger, job, or export evidence;
- negative-control result;
- program-policy note for any intentionally untested impact.

Redact cookies, authorization headers, reset tokens, personal data, credentials, internal addresses, and unrelated records. Replace secrets with stable labels so cross-step relationships remain understandable.

## False-positive rejection gate

Do not submit a finding based only on:

- scanner output or a vulnerable-version guess;
- an error, status, length, or single timing anomaly;
- accepted but ignored input;
- reflection without the claimed execution context;
- client-side validation removal without server effect;
- public or intentionally shared data;
- a transient UI state contradicted by the authoritative store;
- duplicate responses with one durable action;
- callbacks with uncertain origin;
- an unverified chain assumption;
- impact that requires out-of-scope behavior.

When evidence is ambiguous, return to the smallest paired experiment rather than adding more payloads.

## Evidence packet structure

```text
Title: affected feature + broken invariant + demonstrated consequence

Scope and prerequisites
Security expectation
Minimal reproduction
Baseline and negative control
Observed result
Authoritative proof
Root cause and affected boundary
Demonstrated impact
Untested follow-ons and stop reason
Remediation invariant
Redacted evidence index
```

## Impact language

Use capability language tied to evidence:

- “An unrelated controlled tenant read this private object” rather than “all data is exposed.”
- “A session created before MFA enrollment retained this protected action” rather than “MFA is completely bypassed.”
- “Two concurrent redemptions produced two durable controlled credits” rather than “unlimited money.”
- “The worker fetched and stored a controlled remote file” rather than “internal network compromise.”

State breadth only when tested safely or directly established by architecture.

## Safety and cleanup

- Use controlled accounts, tenants, objects, files, inboxes, callback infrastructure, and minimal financial value.
- Keep request volume bounded.
- Do not access unrelated user data or claim third-party resources.
- Do not persist access, send spam, degrade availability, or perform irreversible actions.
- Revoke test tokens, remove controlled objects, reverse reversible changes, and document any state intentionally left for triage.
