# OAuth Methodology

Use this reference to test OAuth/OIDC-style authorization flows.

## Start here: how hunters found this in real reports

1. **Draw every browser hop.** Record authorization request, login, consent, callback validation, code or token delivery, account linking, and final session creation.
2. **Identify what is bound to what.** Check client, exact redirect, state, code verifier, user session, provider identity, local account, and tenant.
3. **Challenge parser assumptions.** A disclosed takeover worked because the callback validator rejected ordinary external URLs but accepted an incomplete relative path.
4. **Follow the value through secondary redirects.** The relative path used traversal to reach a trusted redirect feature, which then carried the token to the controlled destination.
5. **Test existing approval state.** Previously approved applications may skip consent and turn a visible chain into a one-click or background flow.
6. **Prove only with controlled accounts.** Show the code or token produces the intended victim-controlled session in a fresh browser.

### Expand the pattern

Apply the same binding checks to account linking, mobile callbacks, multiple providers, subdomains, and tenant-specific clients. Each redirect hop must preserve the security material for the chain to be real.

## 1. Flow inventory

Record authorize URL, callback, token exchange, linking endpoint, session issuance, client ID, redirect URI, scope, state, nonce, and provider.

## 2. Redirect review

Test exact matching, open redirect chains, path traversal, encoding, fragments, wildcard hosts, IDN, userinfo, and mobile schemes.

## 3. Binding review

Bind state, nonce, code, token, client, redirect, user, tenant, and purpose. Swap between sessions and accounts.

## 4. Account linking

Test forced linking, unverified email, pre-binding, provider mismatch, and OAuth CSRF.

## 5. Remediation checklist

- Enforce exact redirect allowlists.
- Bind state/nonce to session.
- Verify token issuer/audience/expiry.
- Trust only verified email claims.
- Require explicit account-link confirmation.

## 6. Current security baseline

Use RFC 9700 as the current OAuth 2.0 security baseline. In particular, model exact redirect matching, PKCE, CSRF protection, authorization-server mix-up defenses, code and token leakage, sender-constrained or rotated refresh tokens, and avoidance of implicit/password grants.

Do not label every deviation from a best practice as exploitable. Identify the attacker capability and demonstrate the missing binding that changes authorization or authentication.

## 7. What successful reports teach

- Public reports on callback validation, IDN redirect bypass, and code theft show that redirect validation must be reasoned about across the authorization server, client callback, browser URL parser, open redirects, and any page that can leak query or fragment data.
- Reports involving unverified email claims show that a relying party must distinguish identity-provider account ownership from verified ownership of the local account identifier.
- OAuth CSRF and forced-linking reports suggest testing login, account linking, provider replacement, and consent as different purposes even if they share one callback.
- Scope-display and scope-upgrade reports suggest comparing requested, approved, code-bound, token-bound, and resource-server-enforced scopes.
- Race reports motivate testing single use and atomic consumption of codes, device codes, and refresh-token rotation with controlled clients.

## 8. Artifact-binding matrix

Record every artifact and what it must bind:

| Artifact | Required bindings |
| --- | --- |
| `state` | Browser session, client, redirect flow, purpose, one-time use |
| authorization code | Client, redirect URI, PKCE verifier, user, scopes, issuer, single use, short lifetime |
| ID token | Issuer, audience/authorized party, nonce, subject, time, signature key |
| access token | Issuer, audience/resource, client/sender where applicable, scopes, time |
| refresh token | Client, user/session, rotation family or sender, scopes, revocation state |
| linking transaction | Existing local session, provider subject, explicit intent, fresh reauthentication |

Test swaps between two controlled browsers, users, clients, tenants, providers, redirect URIs, and purposes. Change one binding at a time and inspect the final local session or resource-server action, not only the callback response.

## 9. Flow-specific checks

- Verify authorization-server identity in multi-provider clients using `iss`, distinct redirect URIs, or an equivalent mix-up defense.
- Confirm PKCE is required and that the challenge belongs to the same authorization transaction; a present parameter is not enough.
- Inspect `postMessage`, popup, and mobile custom-scheme return paths for exact origin/app binding.
- Test whether codes, tokens, or error parameters leak through Referer, logs, analytics, browser history, third-party content, or open redirects.
- Compare account creation and account linking when the provider returns the same email but a different issuer or subject.

## 10. Confirmation controls

- Use a client and accounts controlled by the researcher; never capture real-user codes or tokens.
- Confirm which principal and scopes the final session/token represents through a benign identity endpoint or controlled resource.
- Rule out a harmless login-CSRF result where the victim is merely logged into the attacker's disposable account unless a concrete victim consequence exists.
- Separate provider defects, client defects, and resource-server defects so remediation targets the component that failed the binding.
