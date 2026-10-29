# OpenID and SSO Methodology

Use this reference to test federated identity trust.

## Start here: how hunters found this in real reports

1. **Separate protocol validity from local identity.** A correctly signed assertion still needs a safe mapping to account, tenant, email, role, and invitation.
2. **Create identity collisions with controlled accounts.** Compare the same email from different issuers, verified versus unverified email, changed subject, aliases, and case or normalization differences.
3. **Test every provisioning path.** Existing account login, just-in-time creation, invite acceptance, domain auto-join, account linking, and tenant migration may use different rules.
4. **Check tenant policy after authentication.** A valid SAML or OIDC response must not bypass allowed-domain, membership, role, or organization restrictions.
5. **Test lifecycle edges.** Removed users, deprovisioned identities, disabled SSO, local-password fallback, stale sessions, and changed group claims reveal drift.
6. **Verify local account and role.** The proof is which controlled account and tenant the session reaches, not merely that an assertion was accepted.

### Expand the pattern

After one mapping failure, test all configured providers and account-linking routes. Describe which stable identifier should have been used and which local policy was skipped.

## 1. Trust model

Map IdP, SP/RP, tenant, domain, user matching, role mapping, callback, ACS, metadata, and provisioning authority.

## 2. Assertion checks

Validate signature, issuer, audience, recipient, ACS, expiry, nonce, subject, NameID, email verification, and RelayState binding.

## 3. Provisioning checks

Review JIT, SCIM, invite acceptance, domain verification, deprovisioning, duplicate users, and existing-account matching.

## 4. Bypass checks

Test local fallback, XMLRPC, client-generated JWTs, unsigned tokens, trailing chars, Unicode, old metadata, and IdP/SP initiated differences.

## 5. Remediation checklist

- Validate assertions and ID tokens strictly.
- Bind RelayState and nonce to sessions.
- Treat email domain as sensitive authorization.
- Scope SCIM/JIT to verified tenants.
- Disable unintended local fallback auth.

## 6. Separate protocol models

Do not merge OIDC, SAML, proprietary signed-login URLs, and SCIM into one checklist.

For OIDC, map discovery, issuer, authorization/token endpoints, client, redirect URI, `state`, `nonce`, code/PKCE, ID-token signature key, `iss`, `aud`/`azp`, `sub`, time claims, and UserInfo. Apply OAuth security guidance from RFC 9700 plus OpenID Connect Core.

For SAML, map IdP/SP identifiers, metadata and signing keys, ACS, binding, request ID, `InResponseTo`, issuer, audience, recipient, destination, subject/NameID, conditions, signature coverage, RelayState, and provisioning.

## 7. What successful reports teach

- Shopify SSO reports on email-confirmation bypass show that verified federation does not prove ownership of an unverified local email or shop identity.
- The SAML domain-enforcement bypass shows that tenant/domain policy must apply after successful protocol validation and on every provisioning path.
- Signature-verification bypass reports motivate checking which exact assertion or response element is signed and which element the application consumes; avoid indiscriminate XML mutation.
- Client-generated JWT and proprietary SSO reports show that key location, issuer, audience, algorithm, and server-side signing authority must be established rather than inferred from a token shape.
- Deprovisioning, SSO enforcement, and local fallback must be tested as lifecycle states, not only initial login.

## 8. Identity and provisioning matrix

Compare two controlled identities across:

- same email, different issuer/subject;
- same subject-looking value, different issuer or tenant;
- verified and unverified email claims;
- invited, JIT-created, existing local, deprovisioned, suspended, and reactivated users;
- IdP-initiated and SP-initiated flows;
- local login, recovery, API token, app password, mobile, and legacy endpoints.

Record which claim selects the local account and which claim grants tenant membership or role. Email, domain, display name, and group strings are not stable identity keys unless the deployment explicitly and safely defines them that way.

## 9. Confirmation controls

- Validate the final local account, tenant, and role from a clean session.
- Use researcher-controlled IdPs/tenants only where the program permits federation testing.
- Distinguish token parsing from token acceptance and acceptance from privileged provisioning.
- Confirm replay, logout, deprovisioning, and key-rotation behavior without using real-user assertions.
- Treat metadata exposure or enabled discovery as information unless it enables a demonstrated trust failure.
