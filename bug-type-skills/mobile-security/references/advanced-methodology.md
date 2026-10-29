# Mobile Security Methodology

Use this reference to test mobile client and backend trust.

## Start here: how hunters found this in real reports

1. **Choose one app feature and trace it end to end.** Start at a deep link, intent, URL scheme, push notification, exported component, WebView, or local file and follow the backend request.
2. **Ask what the app enforces locally.** Role checks, feature flags, certificate state, object ownership, and navigation guards must also be enforced by the server.
3. **Test external entry.** Use a controlled link or app to invoke the component with changed account, object, tenant, redirect, or destination values.
4. **Inspect app-to-web handoffs.** Cookies, OAuth codes, tokens, and trusted origins can cross between browser, WebView, and native handlers.
5. **Review stored data by consequence.** A local token matters when another app, backup, log, clipboard, screenshot, or exported file can retrieve and reuse it.
6. **Prove the server-side result.** Confirm unauthorized data or a durable account action with controlled accounts; bypassing a screen alone is weak evidence.

### Expand the pattern

Test the same backend action through web and API clients. Mobile often reveals hidden routes, but the report should identify the trust decision that failed.

## 1. Surface inventory

List activities, intents, deeplinks, app links, WebViews, file providers, push notifications, background services, and API hosts.

## 2. Storage review

Check tokens, refresh tokens, logs, databases, backups, cache, screenshots, notifications, plist/resources, and debug configs.

## 3. API parity

Compare mobile vs web authorization, validation, rate limits, old endpoints, and client headers.

## 4. Handoff checks

Review OAuth, passwordless, magic links, app-to-app callbacks, browser-to-app transitions, and WebView cookie sharing.

## 5. Remediation checklist

- Validate auth server-side independent of client.
- Bind deeplinks and app links strongly.
- Avoid secrets in app bundles.
- Harden WebViews and exported components.
- Protect local storage and logs.

## 6. What successful reports teach

- Mobile takeover chains often combine a browser or deep-link navigation primitive with a backend identity action; the Android one-click takeover report motivates tracing the full browser-to-app-to-API chain.
- The bank-account deletion report shows that mobile APIs need the same object authorization as web APIs; a signed app or special header is not user authorization.
- Host-validation bypass reports suggest comparing Android/iOS URL parsing, WebView navigation, intent filters, redirect handlers, and backend allowlists as separate parsers.
- Deep links can deliver CSRF-like actions under an ambient app session, as in the follow-action report.
- Notifications, screenshots, app switchers, backups, test buckets, and build artifacts can disclose data outside the app's primary storage model.

## 7. Component-to-backend method

For each exported activity, service, receiver, provider, URL scheme, universal/app link, WebView bridge, share target, and notification action, record:

| Layer | Required evidence |
| --- | --- |
| OS routing | Which apps/origins may invoke it and how verified links are enforced |
| App parsing | Host, path, parameters, nested URL, decoding, and fallback behavior |
| Session | Which cookies/tokens/device state are ambient |
| Backend call | Endpoint, actor, object, tenant, action, and server-side policy |
| Return path | Callback, WebView origin, external browser, local file, or other app |

Test the server independently of client checks. Then test whether an untrusted app or web origin can make the official client perform a request the server otherwise accepts.

For WebViews, map navigation allowlists, JavaScript bridges, file/content access, mixed content, cookie sharing, popup handling, and external-scheme dispatch. A bridge is high risk when untrusted content can reach a native method that reads data, opens URLs, accesses files, or invokes authenticated APIs.

## 8. Confirmation controls

- Use a test device/emulator and controlled accounts; avoid extracting data from unrelated apps.
- Verify an embedded key or endpoint grants a capability before calling it a secret, and use only a read-only check allowed by scope.
- Distinguish local compromise requiring a malicious installed app from remote delivery through a verified link or browser.
- Re-test on supported OS/app versions because platform link, WebView, storage, and permission behavior changes over time.
