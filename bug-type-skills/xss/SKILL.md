---
name: xss
description: Advanced cross-site scripting testing methodology for bug bounty and application security work. Use when testing or reviewing reflected XSS, hidden-parameter and encoding-filtered XSS, stored XSS, DOM XSS, cache-poisoned XSS, OAuth/login-flow XSS, admin-context XSS, markdown/CMS/wiki XSS, chat/client XSS, SVG/file upload XSS, postMessage XSS, CSP bypass, mobile/WebView XSS, and workflows where attacker-controlled input executes JavaScript in another user's browser or a privileged admin context.
---

# XSS Testing

## Core Posture

Treat XSS as execution context control. Identify source, sink, parser, encoding layer, trust boundary, and victim context before judging impact.

## Priority Patterns

- Stored XSS in profiles, wiki pages, comments, chats, admin dashboards, uploads, and cached pages.
- Reflected XSS in login/OAuth/search/error paths with account-token exposure.
- Reflected XSS in legacy, non-standard, resource-looking, or source-discovered endpoints and parameters that are absent from the visible UI.
- DOM XSS through URL, hash, postMessage, local storage, and client-side templates.
- File/content XSS through SVG, images, PDFs, Markdown, HTML sanitizers, and filename rendering.
- Cache poisoning to stored XSS and privileged/admin-context XSS.

## Assessment Loop

1. Inventory sources and sinks: visible and hidden parameters, body fields, headers, cookies, stored content, files, postMessage, cache, page source, scripts, and observed requests.
2. Send a unique harmless canary through one candidate input at a time; locate it in both the raw response and the rendered DOM, and record decoding or normalization.
3. Determine context: HTML, attribute, JavaScript, URL, CSS, SVG/XML, Markdown, template, or DOM sink.
4. Test minimal context breakers before executable payloads; compare literal, percent-encoded, and application-normalized forms only where authorized.
5. Check sanitization, encoding, WAF/backend disagreement, CSP, Trusted Types, and browser-specific behavior.
6. Confirm execution in the intended victim context and assess reachable secrets/actions.

## High-Value Cues

| Cue | Ask |
| --- | --- |
| Hidden parameter | Do source files, archived links, forms, or sibling endpoints reveal inputs the visible UI no longer sends? |
| Canary reflection | Where is the marker reflected after server and browser parsing, and which characters or encodings transform? |
| Stored content | Does low-role input execute for users/admins? |
| Login/OAuth | Can script access tokens, codes, or linked-account flows? |
| DOM sink | Does client route/hash/message reach dangerous APIs? |
| File upload | Does uploaded content execute on trusted origin? |
| Cache | Can XSS be stored for many users through cache? |

## Variant Playbook

- Test context-specific escaping, nested parsers, double decoding, template interpolation, and sanitizer mutation.
- Build a target-specific parameter corpus from authorized pages, scripts, forms, routes, and captured traffic. Replay likely parameters individually against related endpoints with unique canaries and bounded request rates.
- Compare baseline, literal delimiter probes, URL encoding, and application-supported wrappers such as Base64 only when evidence identifies the corresponding decode stage. An accepted request or WAF bypass is not XSS until the browser reaches an executable sink.
- Compare web/mobile, old browsers, CSP variants, and admin rendering.
- Test SVG/Markdown/HTML/filename/metadata and uploaded previews.
- Probe postMessage origin checks and JSON parsing.
- Chain to meaningful actions: token theft, CSRF, account takeover, admin data, or privileged operations.

## Confirmation Discipline

Strong evidence shows JavaScript execution in a security-relevant origin and victim context. Rule out self-XSS, inert markup, sandboxed origins with no impact, and payloads requiring unrealistic victim developer action.

## References

Read `references/advanced-methodology.md` only when the task needs passive endpoint discovery, hidden-parameter and canary reflection fuzzing, encoding/WAF differential analysis, deeper context analysis, DOM/postMessage review, sanitizer/CSP bypass, file-upload XSS, confirmation, or remediation checks.
