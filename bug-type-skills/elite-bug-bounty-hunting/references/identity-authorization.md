# Identity and Authorization Research

Use this reference for authentication bypass, session and MFA failures, IDOR/BOLA, cross-tenant access, privilege escalation, account linking, federation, invitations, and authorization drift.

The core question is not “does this endpoint require authentication?” It is “which identity, authority, tenant, object, state, and assurance level does every action require?”

## Build the controlled identity matrix

Create only the identities needed to distinguish policy decisions:

- anonymous;
- user A and user B in the same tenant;
- user C in another controlled tenant;
- owner or administrator;
- limited member or guest;
- invited but not accepted user;
- removed, suspended, or deprovisioned user;
- API, integration, service, or application identity when permitted.

Record sessions and tokens created before and after role, password, MFA, membership, and recovery changes.

## Write the authority contract

For each high-value action, record:

```text
Actor and assurance required:
Tenant and relationship required:
Object and lifecycle states allowed:
Action and fields allowed:
Reauthentication or approval required:
Expected audit or notification:
```

This contract supplies the expected secure result before any mutation is tested.

## Authentication state-machine method

Map anonymous, primary factor accepted, additional factor pending, fully authenticated, remembered device, recovered, reauthenticated, locked, and suspended states.

List every path into each state:

- password, passwordless, magic link, and device approval;
- password reset and account recovery;
- MFA setup, verification, replacement, disable, and recovery code;
- OAuth/OIDC/SAML login and account linking;
- invitation and just-in-time provisioning;
- mobile, desktop, API, support, and legacy flows.

Compare the assurance checks on each path. Try safe order changes, old material, cross-browser completion, and direct final-step requests only with controlled accounts.

### Session retirement checks

Retest sessions and tokens created before:

- MFA enrollment or enforcement;
- password reset or credential change;
- role downgrade;
- tenant removal;
- account suspension;
- recovery or factor replacement;
- SSO deprovisioning.

The proof is access to a capability that should require the new state, not merely a page remaining open.

## Object and action authorization method

Use objects with unmistakable controlled values. Keep the caller constant and change one reference or relationship at a time.

Test every meaningful action, not only read:

- create, view, list, search, and autocomplete;
- edit individual fields and bulk update;
- delete, restore, archive, clone, and copy;
- share, invite, export, download, and generate links;
- attach, comment, approve, refund, settle, or change role;
- access child records, files, revisions, audit events, and background results.

Compare numeric IDs, UUIDs, slugs, global IDs, filenames, nested IDs, cursors, and indirect tokens only when observed in legitimate traffic.

## Equivalent-route comparison

Repeat the same business action through routes that should enforce the same rule:

- web, mobile, desktop, and API;
- current and older supported API versions;
- REST and GraphQL;
- direct node lookup and nested traversal;
- connection edges and shortcut node lists;
- single and bulk operations;
- live action and scheduled/background action;
- normal UI and import, export, template, or clone features.

Generated helpers and unused schema paths deserve attention because the current frontend may never exercise them.

## Container and child-object checks

Change the destination or parent context:

- user-owned versus group-owned;
- private versus public;
- tenant A versus tenant B;
- active versus archived or deleted;
- parent visible but child restricted;
- shared parent with private attachment or revision.

Verify authorization on every child copied, exported, or rendered. Do not assume the parent's visibility safely applies to its contents.

## Background authorization and TOCTOU

For copy, export, import, scheduled, report, webhook, and bulk jobs, identify:

- which actor and tenant are stored with the job;
- whether object IDs or serialized data are stored;
- whether the worker re-reads current membership, role, visibility, and state;
- whether access can change between scheduling and execution;
- where the output is delivered and who can retrieve it.

With controlled data, schedule a normal job, change access before execution when practical, and inspect only the controlled destination.

## Federation and account-linking checks

Separate protocol validity from safe local-account mapping. Test controlled cases involving:

- same email from different issuers;
- verified versus unverified email;
- stable provider subject versus mutable email;
- tenant and allowed-domain enforcement;
- existing-account linking versus new-account provisioning;
- invitation acceptance and just-in-time creation;
- local-password fallback and deprovisioned identities;
- callback, state, nonce, client, redirect, and session binding.

Trace every redirect hop. A redirect chain matters only when the security value survives and produces the wrong controlled account or session.

## Privilege-escalation method

Model capabilities rather than assuming roles form a simple hierarchy. Compare who may:

- assign roles or invite users;
- create tokens or integrations;
- approve, publish, refund, or export;
- change billing or security settings;
- impersonate, support, or view audit data;
- modify policies that later grant authority.

Test direct role fields, indirect group membership, inherited ownership, approval workflows, delegated administration, stale tokens, and actions that create a more powerful credential.

## Confirmation ladder

1. Confirm normal access with the intended controlled actor.
2. Confirm denial with the unauthorized controlled actor.
3. Change one identity, object, tenant, state, route, or timing fact.
4. Confirm the protected data or action using the authoritative object, audit log, notification, or clean session.
5. Repeat with a fresh identifier or session.
6. Stop after the boundary is proven.

## Anti-noise rules

Do not report:

- a UI-hidden button when the server rejects the action;
- an identifier that is visible but carries no unauthorized capability;
- public data as private;
- a success-shaped response when the transaction rolls back or the object is unchanged;
- a stale page without a protected action;
- GraphQL introspection without unauthorized fields or actions;
- a token accepted only for its documented scope;
- an open redirect without a preserved identity capability;
- a role name change without gained authority;
- several routes calling one root cause as separate vulnerabilities without program justification.

## Safety stop points

Use only controlled accounts, tenants, objects, and inboxes. Stop before viewing unrelated user data, changing a real user's membership, sending external invitations, persisting access, or using staff-only authority beyond the minimal controlled proof.
