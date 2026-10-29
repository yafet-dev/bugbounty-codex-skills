# Clickjacking Methodology

Use this reference to test whether UI framing or overlays can confuse user intent on sensitive actions.

## Start here: how hunters found this in real reports

1. **Start from a meaningful action.** Prefer security changes, OAuth approval, payment, publishing, deletion, or permission changes over harmless navigation.
2. **Count the real clicks.** Open the page normally and write the exact click sequence, confirmations, scrolling, and reauthentication required.
3. **Check every window state.** Test direct framing, nested frames, popups, mobile web views, and intermediate pages; protection may disappear on one step.
4. **Design a believable overlay with controlled accounts.** The victim should not need impossible precision or dozens of unexplained clicks.
5. **Watch for UI changes.** Responsive layouts, consent prompts, and existing account state can move or remove the target.
6. **Verify the victim-side effect.** Confirm the setting, permission, payment, or published object changed.

### Expand the pattern

If framing works but no meaningful action is reachable, document it as a hardening gap rather than inflating impact. The report becomes valuable when framing and a realistic security consequence meet.

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

## 7. What successful reports teach

The public report corpus shows that impact depends on the capability behind the click, not framing alone:

- A framed scanner or crawler can turn one user gesture into server-side navigation or execution; see the Burp Scanner/Crawler report. Include developer tools, integrations, URL fetchers, and desktop-app bridges in the surface model.
- Social cards, messages, and embedded players can amplify a click into a self-propagating action; inspect whether attacker-controlled content supplies the next target or message.
- Payment and donation pages require amount, recipient, and final confirmation to remain visible and bound to the intended action.
- OAuth consent is vulnerable to popup and double-click choreography even when the authorization page itself is briefly visible; see the double-click OAuth report.

## 8. Interaction-state methodology

Model the exploit as timed UI states:

| Moment | Attacker controls | Trusted UI must guarantee |
| --- | --- | --- |
| Before gesture | Decoy position, popup, focus, scroll | Sensitive action not armed invisibly |
| First gesture | Window creation, navigation, focus | Target identity and action remain visible |
| Between gestures | Target movement or replacement | No stale pointer lands on a new control |
| Final gesture | Click, drag, keypress, touch | Fresh confirmation binds amount/object/action |

Test frameability and interaction separately. A page may resist iframes yet remain vulnerable through opener windows, delayed navigation, browser UI overlap, drag-and-drop, or a WebView.

Use a controlled account and a reversible action. Capture the exact number of gestures, timing, viewport assumptions, and whether the victim sees the origin, object, amount, and consequence at the final decision point.

## 9. False-positive controls

- Verify the browser actually sends an authenticated state-changing request; a visible overlay alone is not proof.
- Test `frame-ancestors` on the final action and every redirect/error variant, not only the landing page.
- Distinguish a same-origin product embed from an attacker-origin embed.
- Confirm that browser popup, focus, and user-activation behavior still works in a current stable browser.
