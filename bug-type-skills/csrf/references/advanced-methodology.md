# CSRF Methodology

Use this reference to test browser-mediated authenticated state changes.

## Start here: how hunters found this in real reports

1. **Prioritize identity and money actions.** Account linking, payment destinations, email or phone changes, recovery settings, API keys, OAuth grants, and integrations are high value.
2. **Capture the legitimate request.** Identify method, content type, cookies, tokens, origin checks, custom headers, and any values tied to the user or session.
3. **Ask what a browser can actually send cross-site.** Build the simplest compatible form, navigation, image, or app-link request instead of merely deleting a token in a proxy.
4. **Test token meaning.** Check absence, reuse, another user’s token, another action’s token, and whether the token is bound to the session.
5. **Look across applications.** Deep links and OAuth callbacks can carry a cross-site action from browser to mobile app or from one trusted origin to another.
6. **Prove the victim account changed.** Use two controlled accounts and verify the new link, destination, setting, or credential from the victim side.

### Expand the pattern

After one endpoint fails, test sibling mutations that use the same middleware or framework exemption. A missing CSRF token is only a clue; browser-deliverable, victim-side impact is the finding.

## 1. Action inventory

List all create, update, delete, link, unlink, invite, approve, payment, admin, security-setting, and OAuth consent actions.

## 2. Defense review

Check synchronizer tokens, double-submit tokens, token binding to session/action, Origin/Referer checks, SameSite, CORS, and content-type assumptions.

## 3. Delivery modes

Try forms, auto-submit forms, images, script tags, top-level navigation, redirects, iframes, mobile deeplinks, and same-site subdomains.

## 4. JSON/API checks

Test simple content types, method override, multipart, duplicate parameters, preflight behavior, and token validation order.

## 5. Confirmation rules

Confirm durable side effects from a cross-site trigger under victim credentials.

## 6. Remediation checklist

- Require CSRF tokens on all cookie-auth state changes.
- Bind tokens to session and action.
- Enforce Origin/Referer for sensitive actions.
- Use SameSite defensively, not as the only control.
- Avoid state-changing GET endpoints.

## 7. What successful reports teach

- **Account and provider linking are identity mutations.** Reports on PayPal provider connection and linked-account takeover show that CSRF can bind an attacker's external identity or payment destination to a victim session.
- **Deep links can be cross-application request delivery.** The Android deep-link follow report motivates tracing browser-to-app and app-to-web transitions, not only same-browser forms.
- **A token is only as strong as its binding.** Token disclosure, reuse across sessions, validation on the wrong parameter, or validation after the mutation can turn a nominal token into no protection.
- **Integration setup is a high-value state change.** Webhooks, Slack-style integrations, API apps, SSO, email forwarding, and payment providers may grant long-lived capabilities after one forged request.

## 8. Browser acceptance matrix

For each action record:

| Property | Questions |
| --- | --- |
| Credential delivery | Cookie, client certificate, ambient WebView session, or URL capability? |
| Cross-site request shape | Navigation, simple form, multipart, image, redirect, deep link, popup? |
| Server checks | Token, Origin, Referer, Fetch Metadata, reauthentication, idempotency? |
| Token binding | Session, actor, action, object, origin, lifetime, one-time use? |
| Side effect | Immediate mutation, queued job, link/integration, email, payment, OAuth consent? |

Test SameSite as browser behavior, not a server invariant. Distinguish cross-site from cross-origin and include sibling subdomains, scheme changes, embedded browsers, and top-level navigation rules where the target architecture makes them relevant.

For JSON endpoints, first determine whether any supported content type or method reaches the same handler without a preflight. A CORS misconfiguration is relevant only when the browser can both send the credentialed request and satisfy or bypass the response restrictions needed by the chain.

## 9. Confirmation and controls

- Use a unique controlled object and verify the mutation from a clean victim session or audit log.
- Prove the request originated without reading a token or relying on attacker-controlled same-origin code.
- Repeat with missing, wrong-session, wrong-action, expired, and replayed tokens to map the validation boundary.
- Confirm redirects, queued responses, or UI success messages are followed by a durable server-side change.
