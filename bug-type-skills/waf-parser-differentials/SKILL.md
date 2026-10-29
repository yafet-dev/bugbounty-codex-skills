---
name: waf-parser-differentials
description: Test parser and normalization differentials between WAFs, proxies, servers, frameworks, and final sinks during authorized application security work. Use when equivalent requests are blocked or interpreted differently because of charset, URL/JSON/XML encoding, content type, parameter duplication, path normalization, application wrappers, or framework-specific parsing, including standalone defensive-control research and chains into downstream behavior.
---

# WAF Parser Differential Testing

## Core Posture

Treat the request as a pipeline of parsers, not a single string. A useful finding exists when an upstream control approves one interpretation while a downstream component reconstructs different security-sensitive meaning.

Record the control bypass and downstream behavior as separate capabilities. Depending on the program, a WAF or validation differential may be assessed independently or chained with SQLi, XSS, SSTI, file read, SSRF, cache poisoning, or an authorization failure.

Test only authorized assets and request volumes. Begin with harmless semantic controls, use bounded delays and controlled callbacks, and avoid shared-cache or cross-user effects.

## Report-Derived Starting Point

Identify the two components that disagree, then change one encoding or structure at a time. Reduce the discrepancy to a small transformation, preserve exact evidence from both components, and separately record any backend behavior so program-specific rules—not the skill—determine reportability.

## Differential Families

| Family | Compare | Evidence required |
| --- | --- | --- |
| Application wrappers | Raw value versus Base64, Base64url, hex, serialized, or compressed value the application is known to decode | The decoded value reaches the same sink with the same meaning |
| URL and path | Literal versus encoded delimiters, reserved characters, dot segments, and alternate URL representations | Two components map the same request to different hosts, routes, paths, or policies |
| Request charset | UTF-8 versus another charset explicitly accepted by the server stack | The backend decodes meaningful input that the upstream control did not inspect equivalently |
| Structured body | JSON Unicode escapes, XML representations, form data, and supported multipart forms | The application parser reconstructs a value or structure the control missed |
| Duplicate parameters | First, last, joined, comma-concatenated, or array interpretations | The control and application select or combine different values |
| Framework or language | Alternate operators, literal escapes, template filters, fallback grammars, and client-framework parsing | The final engine evaluates equivalent syntax after the upstream check |
| Cache or proxy | Cache key, origin route, decoded path, delimiter, and forwarded representation | Cache/proxy and origin disagree, confirmed without affecting unrelated users |

## Assessment Loop

1. Capture a stable benign baseline and identify the final security-sensitive sink.
2. Draw the parser chain: client serialization, edge/WAF, proxy/CDN, server, framework binder, application decoder, interpreter or filesystem, and browser where relevant.
3. Establish a minimal sink-specific signal: harmless boolean pair, arithmetic marker, controlled filename, unique canary, cache-key observation, or controlled callback.
4. Reduce a blocked request to the smallest triggering atom. Change one token, delimiter, encoding, header, or structural feature at a time.
5. Form a parser hypothesis from evidence such as client code, documentation, stack traces, content types, duplicate-parameter behavior, or response transformations.
6. Test byte-equivalent or semantically equivalent pairs plus a negative control. Record exact bytes and each observed interpretation.
7. Confirm the downstream sink, not merely a status change, timeout, response length, or missing block page.
8. Stop after the minimum proof allowed by the program and report the root flaw and differential separately.

## Variant Playbook

- Build a small hypothesis-led matrix across representation, content type, charset, parameter multiplicity, and endpoint. Do not combine axes until each single-axis behavior is understood.
- For Base64-like wrappers, verify an actual application decoder and preserve exact bytes, including leading separators, case, padding, and enclosing form/query encoding.
- For JSON, XML, or multipart bodies, preserve a valid document and test whether the edge and framework agree on decoded strings, field boundaries, duplicates, and selected parts.
- For duplicate parameters, fingerprint first/last/join/array behavior with harmless distinct canaries before testing a sink-specific proof.
- For paths and URLs, compare literal and encoded forms with cache busters and known resources; distinguish browser, edge, cache, proxy, and origin normalization.
- For SSTI or other language sinks, build upward from harmless expressions and use syntax valid for the identified engine instead of blindly obfuscating a complex payload.
- Automate only after a manual variant proves the transformation. Preserve request order, unique correlation IDs, bounded concurrency, and per-variant evidence.

## Evidence and Interpretation

Preserve both sides of the differential: the baseline, blocked form, accepted equivalent form, negative control, and exact parser interpretations. When a downstream effect exists, preserve that evidence separately. Let the program's policy determine whether the control differential is assessed alone or as part of a chain.

Classify these outcomes explicitly rather than collapsing them into one claim:

- `403` becomes `200`, but the parameter is ignored or the response is a generic fallback.
- Base64 or another wrapper changes the decoded bytes or semantics of the control value.
- A WAF permits the request while the application safely parameterizes, escapes, rejects, or sandboxes the value; record this as control-layer behavior without attributing an application-sink effect.
- Timing changes are inconsistent or lack matched true/false and no-delay controls.
- A cache observation lacks cache-key evidence or risks poisoning content for other users.
- Multiple endpoints share one parser/sink and are counted as unrelated root causes without program-specific justification.

## References

Read `references/advanced-methodology.md` when the task needs a parser ledger, baseline quartet, detailed differential families, safe automation rules, bug-class confirmation matrix, reporting structure, remediation guidance, or the ten-source research synthesis behind this skill.
