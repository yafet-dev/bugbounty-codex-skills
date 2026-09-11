# XSS Methodology

Use this reference to test browser execution boundaries. Perform discovery and fuzzing only on assets and request volumes authorized by the program.

## 1. Passive endpoint and parameter discovery

Start with low-impact sources before active parameter testing:

- Use scope-constrained search-engine queries to find indexed legacy pages, unusual extensions, script-like resources, query-bearing URLs, error pages, and endpoints absent from current navigation. Treat indexed results as leads, not proof that an asset remains in scope.
- Preserve unusual paths exactly. Resource-looking or non-standard routes can still be dynamically rendered, and suffixes such as legacy framework extensions may identify separate parsing or filtering stacks.
- Inspect HTML source, forms, comments, inline scripts, JavaScript bundles, route definitions, source maps when authorized, and captured network traffic for parameter names the visible UI does not expose.
- Compare sibling pages and endpoints implemented by the same framework. A parameter used on one route may still be accepted by an older or shared handler on another.
- Build a target-specific parameter corpus with provenance: parameter name, source URL/file, observed method, content type, endpoint family, and whether the parameter appeared visible, hidden, legacy, or inferred. Prefer this evidence-backed corpus before generic wordlists.

Inventory URL path/query/fragment inputs, body fields, headers, cookies, stored content, uploads, cache, postMessage, local storage, and API responses. Hidden or apparently unused parameters deserve attention because they may bypass the validation applied to the current UI path, but do not assume they are weaker without testing.

## 2. Canary reflection triage

Use harmless markers to find reflection before attempting execution:

1. Capture a clean baseline for the target endpoint, including status, length, redirect chain, content type, relevant security headers, and stable response regions.
2. Add one candidate parameter at a time. Use a collision-resistant canary that identifies the request and parameter rather than reusing one marker for the whole run.
3. Keep the method, cookies, and other parameters stable. Use bounded concurrency and rate limits consistent with program rules.
4. Search for the canary in the raw response, decoded response, attributes, script data, JSON, URLs, comments, and the browser-rendered DOM. Record whether it is copied, encoded, truncated, case-folded, normalized, or moved by client-side code.
5. Re-request without the candidate parameter and with a second canary to rule out static page text, cached content, reflection from another request, or a coincidental match.
6. Cluster confirmed reflections by template, handler, and transformation behavior. When several endpoints share the same sink, validate representative cases while collecting endpoint-specific evidence rather than assuming every reflection is independently exploitable.

Response length and status are useful triage signals, but direct canary location and context determine priority. Reflection alone is not XSS.

## 3. Context and transformation analysis

For each confirmed reflection, record the complete parser path:

`request bytes -> proxy/WAF normalization -> application decoding -> template serialization -> browser HTML parsing -> DOM or JavaScript sink`

Classify the final context as HTML text, quoted or unquoted attribute, JavaScript string/template/object, URL, CSS, SVG/XML, Markdown, JSON embedded in HTML, template syntax, or DOM API input. Inspect enough surrounding source and live DOM to determine which delimiter closes the current context and which parser consumes the next bytes.

Start with minimal non-executable delimiter probes and observe transformations. Do not jump from a reflected canary directly to a large polyglot: extra syntax can hide which layer is vulnerable, trigger unrelated defenses, or create a result that cannot be explained reliably.

## 4. Encoding and filter differential analysis

Treat a WAF decision and an application encoding decision as separate observations:

- Compare a baseline marker with a small set of context-relevant delimiters in literal and percent-encoded form. Record the exact bytes sent, what each intermediary accepts, and what the browser ultimately parses.
- Test one transformation at a time: URL decoding, form decoding, HTML entity handling, Unicode normalization, case normalization, or application-specific escaping. Try an additional encoding layer only when the response shows evidence of an additional decode stage.
- Treat Base64, Base64url, hex, compression, or serialized wrappers as application protocols, not browser encodings. Use them only when frontend code, documentation, or observed traffic indicates a decoder; encode an exact benign delimiter/canary control and trace the decoded value into the final browser context.
- If the WAF blocks a literal form but accepts an encoded form, verify whether the backend decodes it into dangerous syntax and whether output encoding remains correct. A non-`403` response is not a vulnerability.
- If a tool generates an obfuscated candidate, decode and understand it before use. Reduce a working result to the smallest context-specific proof so the report identifies the root cause rather than merely presenting a filter-evasion string.
- Recheck in a real browser with the target's CSP, Trusted Types policy, sanitizer, and client-side transformations active. Raw response text that resembles markup may remain inert.

Stop broad mutation once the relevant normalization path is understood. Prefer a few explainable variants over unbounded payload spraying.

## 5. Broader source and sink inventory

Beyond reflected query parameters, examine body fields, headers, cookies, stored content, uploaded filenames and metadata, cache inputs, postMessage data, local storage, fragments, and API responses consumed by client templates. Trace each source to its final sink rather than assuming server reflection is required.

## 6. Defense review

Check output encoding, sanitizers, CSP, Trusted Types, sandboxed origins, cookie flags, and framework escaping.

## 7. Confirmation and impact checks

Confirm JavaScript execution in the intended origin and user context with a minimal benign proof. Capture the vulnerable parameter, exact context, transformation chain, rendered DOM, relevant headers, and a reproducible request. Then assess token access, account actions, admin context, OAuth/login flows, stored reach, cache reach, and sensitive APIs.

Rule out:

- A marker or markup fragment that never becomes executable.
- Execution only in a local tool's response renderer or disabled-security browser.
- Self-XSS requiring the victim to paste code or use developer tools.
- A sandboxed or opaque origin with no meaningful trust or reachable action.
- A result dependent on an extension, stale cached page, or unrelated prior request.
- Several URLs that all reach one shared sink being reported as distinct root causes without program-specific justification.

## 8. Remediation checklist

- Apply output encoding for the final parser context, including hidden and legacy parameters.
- Canonicalize once at a defined boundary, validate the canonical form, and avoid WAF/application decoding disagreements.
- Sanitize rich content with proven libraries.
- Avoid dangerous DOM sinks.
- Enforce CSP/Trusted Types defensively.
- Isolate uploaded active content.
- Remove unused parameters and legacy handlers, or route them through the same validation and templating controls as visible inputs.
