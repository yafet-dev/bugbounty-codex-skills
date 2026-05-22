# Clickjacking Methodology

Use this reference to test whether UI framing or overlays can confuse user intent on sensitive actions.

## 1. Surface inventory

List pages with buttons for OAuth consent, payment, delete, admin, security settings, account linking, invite acceptance, file upload, scanner/crawler launch, and browser permissions.

## 2. Frame defense review

Check `X-Frame-Options`, `frame-ancestors`, CSP inheritance, redirect pages, error pages, legacy pages, cached pages, and partner-embed exceptions.

## 3. Interaction models

Test single-click, double-click, click-and-hold, drag-and-drop, keyboard focus, popup opener, and mobile touch flows.

## 4. Bypass angles

Review old hosts, alternate paths, HTTP downgrade, open redirects, nested frames, sandbox attributes, PDF/viewer wrappers, and WebView embedding.

## 5. Confirmation rules

Confirm a meaningful side effect under victim auth. Capture the minimum misleading interaction and resulting state change.

## 6. Remediation checklist

- Set strict `frame-ancestors`.
- Remove broad partner frame allowlists.
- Require explicit confirmations for high-risk actions.
- Bind OAuth/payment/security actions to visible user intent.
- Add regression tests for redirects and legacy pages.
