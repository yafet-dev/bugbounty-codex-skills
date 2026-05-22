# Mobile Security Methodology

Use this reference to test mobile client and backend trust.

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
