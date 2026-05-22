---
name: clickjacking
description: Advanced clickjacking and UI redress testing methodology for bug bounty and application security work. Use when testing or reviewing frame embedding, OAuth authorization clicks, donation/payment flows, admin actions, browser permission prompts, double-clickjacking, drag-and-drop abuse, UI overlay attacks, mobile WebViews, postMessage UI flows, and any sensitive action that can be triggered by deceiving a user's clicks.
---

# Clickjacking Testing

## Core Posture

Treat clickjacking as user-intent confusion. Test whether a sensitive action can be triggered while the user believes they are interacting with something else.

## Priority Patterns

- OAuth grants, app authorization, login consent, and linked-account flows.
- Payment, donation, subscription, transfer, and payout actions.
- Admin actions, destructive actions, security-setting changes, and browser/tool integrations.
- Double-clickjacking and cursorjacking where the first click primes the second action.
- Frameable dashboards, old routes, popups, mobile WebViews, and embedded widgets.

## Assessment Loop

1. Identify sensitive click targets and whether they require one click, double click, drag, keyboard, or confirmation.
2. Check frameability and embed behavior across paths, subdomains, legacy hosts, and popup flows.
3. Review `X-Frame-Options`, `Content-Security-Policy: frame-ancestors`, SameSite cookies, and sandbox behavior.
4. Test overlays, opacity, pointer-events, scrolling, viewport offsets, and delayed UI changes.
5. Confirm that the framed action completes with victim credentials and produces a meaningful side effect.

## High-Value Cues

| Target | Ask |
| --- | --- |
| OAuth consent | Can a grant be approved by a hidden or misrepresented click? |
| Payment/donation | Can money or paid state change with one deceptive click? |
| Admin/security | Can roles, email, 2FA, API keys, or settings change? |
| Tool/browser | Can a scanner, crawler, extension, or desktop app be driven to dangerous URLs? |
| Double-click | Can a harmless first click place the pointer over a sensitive second click? |

## Variant Playbook

- Test top-level and nested frames, popups, iframes in redirects, and mobile WebViews.
- Try old domains, localized pages, subdomains, HTTP vs HTTPS, and alternate hosts.
- Use transparent overlays, delayed swaps, scrolling containers, CSS transforms, and small viewport changes.
- Test same-site embedding, cross-site embedding, and trusted partner embedding.
- Compare frame defenses before and after login, OAuth start, redirect, error, and confirmation pages.

## Confirmation Discipline

Strong evidence shows a sensitive action completed from a framed or overlaid UI. Rule out pages that frame but require unreproducible interaction, harmless clicks, or defenses that block authenticated completion.

## References

Read `references/advanced-methodology.md` only when the task needs deeper frame-defense review, OAuth/payment/admin click testing, double-clickjacking checks, or remediation guidance.
