# GraphQL Methodology

Use this reference to test GraphQL resolver, mutation, and query-cost boundaries.

## Start here: how hunters found this in real reports

1. **Choose sensitive data or an action.** Start with a private field, billing record, membership, export, delete, role change, or token-generating mutation.
2. **List equivalent graph paths.** Compare direct node lookup, parent traversal, `edges { node }`, a `nodes` shortcut, fragments, aliases, persisted queries, and the matching REST route.
3. **Request the smallest field set first.** Then add one nested field at a time across anonymous, user, member, removed-member, and admin contexts.
4. **Watch the returned object type.** A real disclosure appeared because a new shortcut returned an object that skipped the attribute-scrubbing path used by the older connection shape.
5. **Inspect unused and generated schema features.** Framework upgrades can add helper fields that the frontend never calls, so they receive less product testing.
6. **Confirm field and action results independently.** For reads, use unmistakable controlled values. For mutations, inspect the victim object or audit record; a GraphQL `200` is not proof.

### Expand the pattern

After finding one resolver mismatch, trace its loader, serializer, and service calls and test sibling fields. Also compare query cost by actual resolver executions, not query text length.

## 1. Operation inventory

Collect operation names, variables, persisted query IDs, fragments, node IDs, connection cursors, schema hints, and mobile/web/client documents.

## 2. Authorization matrix

Test anonymous, user A/B, roles, tenants, removed users, API tokens, app tokens, and admin/staff paths for each resolver and nested field.

## 3. Mutation review

Focus on create/update/delete/copy/verify/generate-session/add-rule operations. Swap object, owner, tenant, role, and lifecycle state.

## 4. Cost review

Test bounded aliases, nested fragments, large lists, connection traversal, batching, and repeated mutations. Look for missing query cost limits.

## 5. Drift checks

Compare REST, mobile, old GraphQL operation names, persisted queries, and admin UI routes for the same object/action.

## 6. Remediation checklist

- Authorize every resolver and nested field.
- Scope node lookups by caller and tenant.
- Enforce query depth, complexity, aliases, and rate limits.
- Validate mutation input server-side.
- Regression-test REST/GraphQL parity.

## 7. What successful reports teach

- **Nested-field authorization is independent of root authorization.** Public reports exposed confidential program, report, user-email, and private-list fields through otherwise reachable objects; see confidential GraphQL data and invitation email disclosure.
- **Mutations need object/action authorization, not only input validation.** The certification deletion IDOR shows that create-or-update style mutations may perform destructive replacement on another user's collection.
- **Resolvers are injection and fetch boundaries.** Filter languages, URL arguments, and custom scalars may reach query engines, template evaluators, or network fetchers.
- **Aliases multiply side effects.** The mutation-aliasing DoS report shows why HTTP request limits must account for field executions and downstream provider cost.
- **Scoped tokens may gain broader GraphQL authority than REST/UI.** Compare token type, installation/user context, scopes, and field-level policy across equivalent APIs.

## 8. Resolver graph method

Build a graph rather than a flat endpoint list:

```text
operation -> root resolver -> node/global-ID lookup -> nested resolver
          -> loader/cache -> service/API -> field serializer
```

For each edge record actor, tenant, object, field, scope, and expected policy. Test direct node lookup and traversal through a parent separately; many systems authorize one path but reuse a loader that bypasses the other.

Compare omitted, `null`, empty, aliased, batched, and fragment-delivered fields only when they map to a plausible binder or resolver difference. A schema leak is reconnaissance; the finding is unauthorized data, action, or resource consumption.

For persisted queries, determine whether authorization is evaluated when registering, resolving the hash, and executing. Old operation documents embedded in mobile or JavaScript clients can reveal retired fields whose resolvers still run.

## 9. Confirmation controls

- Use two controlled users/tenants and objects with unmistakably different values.
- Verify unauthorized fields are not intentionally public or inherited through a parent relationship.
- For mutations, confirm the victim-side object or audit record; GraphQL `200` with an error is not success, and a success-shaped response may still be rolled back.
- For cost issues, count resolver/downstream executions rather than query text length and keep experiments bounded.
