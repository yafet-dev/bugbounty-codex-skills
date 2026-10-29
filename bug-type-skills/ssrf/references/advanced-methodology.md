# SSRF Methodology

Use this reference to test backend URL-fetch boundaries.

## Start here: how hunters found this in real reports

1. **Look for remote-content features.** Imports, attachments, previews, avatars, document conversion, charts, analytics, webhooks, OAuth setup, and validation often hide server fetchers.
2. **Inspect serialized objects and model fields.** In one report, a normal project export was modified to add a remote-attachment field supplied by the upload library but never shown in the UI.
3. **Follow import into callbacks.** The importer accepted the hidden field; model creation triggered a server-side download; the resulting file was stored and visible to the researcher.
4. **Prove fetch ownership.** Use a unique controlled HTTP or DNS callback plus a no-callback control, and distinguish the server worker from browser previews or security scanners.
5. **Map each redirect and resolution.** Record validation, DNS, connection, redirect, re-resolution, credentials, response handling, and any later parser.
6. **Stop at the boundary.** Prove outbound reachability or controlled response handling without scanning internal networks or retrieving real credentials.

### Expand the pattern

Test sibling importable models and features using the same upload or URL-fetch library. The reusable question is: “Which hidden field or delayed callback can cause this service to fetch?”

## 1. Fetcher inventory

List previews, imports, exports, webhooks, callbacks, avatars, renderers, converters, OAuth controllers, analytics, and document processors.

## 2. Parser and network checks

Test schemes, redirects, DNS, IPv4/IPv6, localhost aliases, private IPs, userinfo, encoded hosts, and parser mismatches.

## 3. Blind channels

Use DNS, HTTP callback, timing, status, content length, titles, errors, and webhook logs.

## 4. Impact checks

Assess metadata credentials, internal admin panels, localhost APIs, file reads, cloud APIs, and RCE chains.

## 5. Remediation checklist

- Use strict URL allowlists after canonicalization.
- Block private/link-local/metadata ranges at egress.
- Revalidate after redirects and DNS resolution.
- Isolate fetchers from credentials.
- Log and rate-limit outbound fetches.

## 6. What successful reports teach

- Expense reports, analytics reports, webhooks, imports, previews, and OAuth controllers repeatedly appear as fetchers because they transform or validate remote content rather than simply “open a URL.”
- The project-import attachment report shows that nested or copied remote-attachment fields may bypass the main URL policy.
- Full-response reports reaching cloud metadata or private keys show that impact depends on the fetcher's network position, identity, response handling, and credential exposure—not merely loopback reachability.
- Blind internal-service reports show that a callback proves outbound reachability but not access to a protected internal asset.
- GraphQL, upload processors, chart embedding, document conversion, and OAuth integration can hide the URL several layers below the entry request.

## 7. Fetch lifecycle

Map each decision:

```text
input -> URL decode/parse -> scheme/host policy -> DNS resolution
-> connect/proxy -> redirect -> re-resolution -> response read
-> content parser/storage/renderer -> returned or side-channel observable
```

Record which component applies the allowlist and whether it validates every redirect and resolved address. Compare the validator's parsed scheme, authority, host, port, and path with the HTTP client or downstream SDK's interpretation. Use the URL validation bypass research to select context-specific parser tests rather than a universal payload list.

Classify the primitive:

- blind outbound request;
- partial metadata such as status, title, size, or timing;
- full response read;
- credentialed request using service identity;
- protocol or file access;
- stored/second-order fetch by a worker;
- cross-tenant fetch or callback confusion.

## 8. Safe confirmation and controls

- Start with a unique controlled HTTP/DNS endpoint and correlate method, headers, source, timing, and redirect behavior.
- Use two callback hostnames and a no-callback control to distinguish application traffic from scanners or link previewers.
- Confirm redirects and DNS changes are followed by the same fetcher, not by your browser.
- Prefer a documented harmless internal health/version endpoint or controlled test service when policy allows; do not enumerate internal networks.
- Stop after proving the network or identity boundary. Cloud credentials, admin actions, or internal RCE require separate authorization and evidence.
