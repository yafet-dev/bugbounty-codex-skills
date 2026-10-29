# Client-Side and Cross-Origin Methodology

Use this reference for XSS, POST-reflected XSS, DOM injection, stored/admin rendering, postMessage, CSRF, CORS, clickjacking, client-side request forgery, and browser-based chains. The browser’s origin, delivery path, victim reachability, and resulting capability determine impact.

## Source-to-sink graph

Trace:

```text
input source -> server/client decoding -> storage/API serialization
             -> template/DOM operation -> browser parser/context
             -> origin and user role -> reachable action or data
```

Sources include query, path, fragment, POST body, headers, cookies, uploaded names/metadata, stored records, postMessage, WebSocket events, local storage, service-worker messages, and API responses.

Sinks include HTML, attributes, URLs, JavaScript strings/objects, CSS, SVG, templates, markdown, DOM APIs, navigation, resource loading, and privileged client APIs.

## Context-first XSS method

1. Place a unique non-executable marker in one source.
2. Locate it in the raw response and final DOM.
3. Record every decode, sanitizer, serializer, and client transformation.
4. Identify the final browser parser context and delimiter.
5. Use the smallest context-specific probe and a literal-text negative control.
6. Confirm harmless execution in a normal browser under the intended target origin.
7. Determine which controlled user roles and tenants can cause and receive it.

Do not begin with a polyglot or payload list. Reflection is only discovery.

## POST-reflected XSS

A payload reflected in a POST response and displaying `alert(1)` can be a real reflected XSS, but only if the vulnerable response is rendered by a normal browser in the target origin and a realistic victim can be made to submit or reach the POST flow.

### Required checks

1. **Legitimate baseline:** Capture the normal browser-generated POST, response content type, redirect chain, cookies, CSRF state, and rendering behavior.
2. **Single body mutation:** Replace one body value with a unique marker, then identify the exact HTML/attribute/JavaScript/URL context.
3. **Normal-browser execution:** Submit through the application or a browser-compatible request. Execution only in a proxy response renderer does not count.
4. **Delivery feasibility:** Determine whether an external page, same-site page, upload, redirect, auto-submitting form, link, or existing application workflow can cause the victim’s browser to send the required method, body, headers, and credentials.
5. **Defense interaction:** Account for CSRF tokens, SameSite cookies, Origin/Referer checks, custom headers, content type, reauthentication, and user confirmation.
6. **Victim realism:** Count user actions and verify that the flow does not require developer tools, proxy modification, console pasting, or attacker access to the victim’s secrets.
7. **Impact:** Confirm the script runs as the controlled victim in the vulnerable origin and can reach a meaningful same-origin capability.

### Classify honestly

- **Deliverable reflected XSS:** A realistic attacker-controlled flow causes execution in another controlled user’s browser.
- **Stored/second-order XSS:** The POST stores data that later executes in a normal viewer.
- **Same-user workflow XSS:** Another feature reliably feeds the POST response for the logged-in user; impact depends on that feature.
- **Self-XSS/proxy-only behavior:** Execution requires manual request editing, developer tools, or a local renderer. Do not report as ordinary reflected XSS without a separate verified delivery primitive.

An alert proves browser execution, not meaningful impact by itself. Record origin, victim role, reach, and accessible capabilities.

## Stored and second-order viewers

Map every renderer of stored content:

- ordinary user and shared views;
- administrator, moderator, support, fraud, and operations panels;
- email, notification, PDF, export, report, and preview systems;
- mobile WebViews and desktop clients;
- search, autocomplete, activity feeds, audit logs, and error dashboards;
- caches and generated static pages.

Compare preview with delivery and low-privilege with high-privilege viewers. Use silent, harmless controlled markers so unrelated users are not affected. Stop once the controlled receiving role and origin are proven.

## DOM and client framework analysis

Trace data through framework routing, hydration, state stores, template compilation, URL parsing, and DOM APIs. Inspect which layer decodes fragments, queries, serialized state, postMessage data, and server-provided JSON.

Ask:

- Does a framework treat data as a template, URL, or HTML after a sanitizer saw plain text?
- Does client-side routing reparse a value the server encoded safely?
- Do legacy or alternate components use a different renderer?
- Does hydration merge attacker data with trusted configuration?
- Can a safe source reach a dangerous sink only after a user action or asynchronous event?

Confirm in the deployed browser with CSP, Trusted Types, sandboxing, and actual framework behavior enabled.

## postMessage and window trust

For each message handler record:

- expected sender window and origin;
- origin check and canonicalization;
- message schema and type dispatch;
- navigation, DOM, storage, token, or API sinks;
- opener/parent/frame relationships;
- whether a compromised trusted subdomain satisfies the check.

Test only with controlled origins and windows. `event.origin` validation without binding the expected window can still be unsafe, and binding a window without validating origin is insufficient.

## CSRF and cross-site request delivery

Prioritize identity linking, email/phone/recovery changes, OAuth grants, API keys, payment destinations, integrations, publishing, and destructive actions.

Prove:

1. a browser can create the required request cross-site;
2. credentials are included under actual SameSite and browser rules;
3. tokens and Origin/Referer checks are absent, weak, reusable, or unbound;
4. the victim-side controlled account changes durably;
5. the flow creates a demonstrated victim-side security consequence rather than only changing the attacker’s own controlled state.

Do not discard login CSRF categorically. It is security-relevant when a controlled victim is forced into an attacker-controlled account and then adds private data, payment details, recovery information, or another valuable capability that the attacker can later access. Prove that consequence with controlled accounts and harmless markers. If the forced login produces no victim-side exposure or authority change, classify it as a low-value lead rather than inventing impact. See the [OWASP CSRF prevention guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) for this distinction.

Deleting a token in a proxy is not a CSRF proof.

## CORS and cross-origin reads

Separate “request can be sent” from “response can be read.” Map origin reflection, credential mode, preflight, methods, headers, redirects, null/opaque origins, and cache interaction. Use controlled sensitive markers and a clean second origin.

An `Access-Control-Allow-Origin` anomaly matters only when a realistic hostile origin can read protected data or invoke a meaningful credentialed API.

## Clickjacking and UI redress

Work backward from a meaningful action. Verify framing across every step, count real clicks, account for responsive layouts and confirmations, and demonstrate the controlled victim-side effect. A frameable page with no realistic security action is a hardening observation.

## Chain upgrades

Client-side primitives become high impact when another verified edge expands reach:

- cache poisoning serves a controlled payload to clean requests;
- request desynchronization routes a victim to a harmful response;
- open redirect or OAuth flow preserves a token or trusted origin;
- stored input reaches staff/admin viewers;
- subdomain trust satisfies CSP, CORS, postMessage, or callback allowlists;
- CSRF delivers a state change that creates a later executable view.

Verify each edge. Do not assume a self-XSS can be “chained somehow.”

## False-positive controls

Reject or downgrade:

- proxy/editor rendering instead of target-origin execution;
- alert in the researcher’s manually modified request with no victim delivery;
- inert markup or reflection that never enters an executable context;
- execution in a sandboxed or opaque origin with no meaningful capability;
- browser extensions, disabled security, or stale local cache as requirements;
- postMessage handlers that cannot be reached from an untrusted controlled origin;
- CORS headers without a readable credentialed response;
- CSRF tests that do not reproduce browser cookie/token behavior;
- several URLs that share one sink presented as separate root causes.

## Evidence packet

Capture:

- exact source, method, body, and delivery path;
- final DOM/context and transformation chain;
- normal-browser reproduction;
- origin, role, tenant, and controlled victim state;
- CSP/Trusted Types/sandbox and relevant headers;
- baseline and negative control;
- proven same-origin capability;
- any chain edge separately.
