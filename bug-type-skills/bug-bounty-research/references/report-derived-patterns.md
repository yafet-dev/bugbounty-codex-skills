# Report-Derived Hunting Patterns

These are not report summaries. Each example keeps the thinking move that can be reused on a different authorized target.

## 1. Compare two paths that should return the same protected data

### What the hunter noticed

A GraphQL connection exposed records through both an older `edges -> node` path and a newer `nodes` shortcut. The frontend used the older path, so the shortcut received less real-world testing.

### What was actually broken

The older path returned an object whose sensitive fields were filtered. The shortcut returned a different object type and skipped that field-level protection. The root problem was not GraphQL introspection; it was authorization drift between equivalent resolvers.

### Reusable method

1. Choose a sensitive field that a low-privilege controlled user should not see.
2. List every graph path, API route, serializer, and client that can return the same record.
3. Request the smallest safe field set through each path.
4. Add one protected nested field and compare roles.
5. Test generated helpers and schema fields that the current frontend does not use.
6. If one path leaks, trace the object type, loader, and serializer it uses and test siblings.

## 2. Add a hidden model field to an import

### What the hunter noticed

A project import accepted serialized model data. The underlying upload library supported a remote-attachment field even though the normal product UI never exposed it.

### What was actually broken

The importer did not remove that field. Creating the model triggered a callback that downloaded the supplied URL on the server. A normal import feature had therefore become a hidden server-side fetcher.

### Reusable method

1. Export a harmless object you control and inspect its serialized fields.
2. Learn which fields the underlying model or library supports beyond the UI.
3. Add one harmless hidden field and re-import the object.
4. Watch model callbacks, background jobs, file creation, notifications, and controlled callbacks.
5. Use a no-change import as the negative control.
6. Test sibling models that use the same importer or library.

The transferable idea is “imported data may invoke model behavior,” not “try this particular field name everywhere.”

## 3. Follow an OAuth value through every redirect hop

### What the hunter noticed

An OAuth application locked callbacks to a trusted site. Ordinary external URLs were rejected, but an incomplete relative callback form was accepted.

### What was actually broken

The validator assumed it was checking a complete URL. Path traversal inside the accepted callback reached a trusted-site redirect feature, which then sent the token to a controlled destination. Existing user approval made the flow require less interaction.

### Reusable method

1. Draw authorization, login, consent, callback, secondary redirects, and final session creation.
2. Record what binds client, redirect, user, state, and code or token at each step.
3. Compare complete URLs with relative or otherwise incomplete forms only where the target supports them.
4. Follow the security value through every hop; the chain fails if the value is dropped.
5. Test new-consent and already-approved controlled users separately.
6. Prove the final controlled account or session, not merely an open redirect.

## 4. Prove a race with the final ledger, not response messages

### What the hunter noticed

A one-time gift-card redemption request could be duplicated concurrently. Several requests returned success.

### What was actually broken

The valuable evidence was that the controlled wallet received multiple credits. Later fraud or reconciliation behavior could still reverse them, so temporary and settled impact had to be separated.

### Reusable method

1. Record the balance and state before any test.
2. Send the action once and then a second time sequentially to learn the intended one-time behavior.
3. Use a small synchronized pair of identical requests.
4. Re-read the authoritative balance, ledger, inventory, or object state.
5. Wait for or inspect documented reconciliation using only controlled value.
6. Test adjacent one-time operations that share the same ledger or idempotency system.

## 5. Retest old sessions after a security upgrade

### What the hunter noticed

MFA was enabled in one controlled device while another already-authenticated device remained active.

### What was actually broken

The login screen correctly required MFA for future logins, but sessions created under the weaker policy were not retired or downgraded. The assurance rule was applied only at new login.

### Reusable method

1. Open controlled sessions before MFA enrollment or another security change.
2. Perform the change in a separate session.
3. Recheck old web, mobile, API, desktop, and remembered-device sessions.
4. Try an action that the product says requires the stronger assurance level.
5. Repeat after factor replacement, recovery, password reset, and administrator enforcement.
6. Distinguish “session still displays a page” from “session can perform a protected action.”

## 6. Recheck authorization inside background work

### What the hunter noticed

A project-template copy flow authorized the initial request differently depending on destination type. Public parent projects could be discovered even when child repositories or issues were restricted.

### What was actually broken

The asynchronous export or copy job trusted the earlier request and did not recheck the current actor against each child object. Restricted child data could be copied into an attacker-controlled destination.

### Reusable method

1. Choose copy, clone, export, import, template, scheduled, or bulk features.
2. Test different destination containers such as user, group, tenant, public, and private.
3. Compare parent visibility with every child object copied by the job.
4. Change access after scheduling but before the worker runs.
5. Inspect the controlled destination for unmistakable child data.
6. Trace where actor identity is stored and where the worker re-authorizes it.

## 7. After finding a parser mismatch, search for the second feature

### What the hunter noticed

A front end and back end disagreed on a request boundary because they interpreted a transfer header differently.

### What was actually broken

The mismatch became critical only when the hunter found a backend redirect behavior that could be placed in front of a later request. The chain crossed from parser disagreement to controlled victim effect.

### Reusable method

1. Prove the parser disagreement against your own follow-up request with a harmless canary.
2. Reduce it to the smallest stable representation difference.
3. Map what the affected connection can reach next: redirects, caches, routing, authentication, or content generation.
4. Use controlled clients to show cross-request influence without collecting other users' data.
5. Keep the parser primitive and the application consequence as separate evidence.
6. Recommend fixing both ambiguous parsing and the secondary behavior that magnifies it.

## A compact extraction worksheet

For the next report you read, fill this in:

```text
Feature:
Security promise:
Clue the hunter noticed:
One condition they changed:
Component that made the wrong decision:
Controlled proof:
Negative control:
Lasting result:
Sibling features to test:
Safe stop point:
```

If these fields cannot be completed, the report may be interesting but it has not yet produced a usable methodology.
