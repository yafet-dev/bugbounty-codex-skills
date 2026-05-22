---
name: mobile-security
description: Advanced mobile application security testing methodology for bug bounty and application security work. Use when testing or reviewing Android or iOS apps, deeplinks, intents, universal links, WebViews, local storage, hardcoded secrets, mobile API authorization, certificate pinning, host validation, exported components, notification leaks, app-to-app auth handoff, file/path traversal, mobile RCE chains, and mobile-only account takeover or data exposure paths.
---

# Mobile Security Testing

## Core Posture

Treat mobile apps as client, transport, local storage, and backend API surfaces at once. Test what the app trusts locally and what the backend trusts from the app.

## Priority Patterns

- Deeplink and intent abuse: CSRF, auth token capture, account takeover, host validation bypass, and app-link confusion.
- Mobile API gaps: broken access control, mobile-only endpoints, private data, bank/payment actions, and stale app versions.
- Local storage leaks: tokens, configs, certificates, logs, notifications, backups, and path traversal.
- Hardcoded secrets: API keys, Cloudinary secrets, client IDs, service endpoints, and debug flags.
- WebView/RCE: JavaScript bridges, file access, renderer bugs, unsafe downloads, and untrusted content.

## Assessment Loop

1. Inventory app entry points: activities, intents, deeplinks, universal links, WebViews, push notifications, file handlers, and APIs.
2. Map local secrets and backend tokens by storage location and lifecycle.
3. Compare mobile API behavior with web API for authorization, validation, and rate limits.
4. Test app-to-app and browser-to-app auth handoff for state, nonce, and token leakage.
5. Confirm backend impact, local data exposure, or cross-app control.

## High-Value Cues

| Cue | Ask |
| --- | --- |
| Deeplink | Can another app inject or capture auth state? |
| Mobile endpoint | Does it skip checks present on web? |
| Local storage | Are tokens or secrets readable from backups/logs/files? |
| WebView | Can untrusted content reach bridges or cookies? |
| Hardcoded key | Is it valid, unrestricted, or write-capable? |

## Variant Playbook

- Try malformed schemes, hosts, paths, encoded URLs, open redirects, and custom-scheme collisions.
- Compare old app versions, Android/iOS parity, debug builds, and regional endpoints.
- Inspect bundles, manifests, plist, resources, strings, logs, and local databases.
- Test exported components, file providers, WebView settings, and notification previews.
- Replay mobile tokens through API clients and web tokens through mobile endpoints.

## Confirmation Discipline

Strong evidence shows backend access, account control, token theft, local secret exposure, cross-app abuse, or mobile-only authorization bypass. Rule out harmless hardcoded public IDs and local-only issues without sensitive data or backend impact.

## References

Read `references/advanced-methodology.md` only when the task needs deeper deeplink, WebView, storage, mobile API, hardcoded secret, confirmation, or remediation checks.
