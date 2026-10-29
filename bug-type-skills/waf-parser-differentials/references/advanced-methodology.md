# WAF Parser Differential Methodology

Use this reference to investigate authorized cases where a control and downstream application assign different meaning to the same request.

## Start here: how hunters found this in real reports

1. **Name the two interpreters.** Examples: CDN versus origin, WAF versus JSON parser, framework router versus proxy, or validator versus URL client.
2. **Build four controls.** Use a normal accepted request, a normal rejected request, a suspicious request that should be blocked, and a harmless value shaped like the suspicious one.
3. **Change one representation.** Test a single difference in encoding, duplicate fields, case, whitespace, content type, charset, path delimiter, or nesting.
4. **Observe both decisions.** The useful signal is “the guard saw A while the backend acted on B,” not merely a different status code.
5. **Reduce the mutation.** Remove every unnecessary character until the smallest stable disagreement remains, then rebuild only enough to reach a controlled sink.
6. **Prove the underlying bug.** A bypass matters only when it reaches a real injection, routing, cache, authorization, or validation flaw.

### Expand the pattern

Automate only after a manual differential is stable. Report the parser disagreement and backend consequence so defenders can fix canonicalization or reject ambiguous input.

## 1. Parser ledger

Create a ledger before mutating requests:

| Stage | Record |
| --- | --- |
| Client/tool | HTTP version, exact target, headers, body bytes, transfer framing |
| Edge/WAF | block signature, status, headers, body fingerprint, rate behavior |
| Proxy/CDN/cache | rewrites, decoding, forwarded headers, cache key, cache hit/miss |
| Web server | route mapping, path normalization, charset and content-type handling |
| Framework | parameter binding, duplicates, arrays, JSON/XML/multipart parsing |
| Application | Base64 or custom decoding, validation order, business transformation |
| Final sink | SQL, template engine, filesystem, URL fetcher, cache, or browser parser |

Do not assume visibility into every stage. Mark an interpretation as observed, inferred, or unknown and design the next harmless control to distinguish competing explanations.

## 2. Baseline quartet

Use four related requests wherever the input contract permits:

1. B0: a benign raw value with known behavior.
2. B1: a supported alternate representation of the exact same benign value.
3. P0: a minimal harmless sink probe in its ordinary representation.
4. P1: the semantically equivalent probe using one hypothesized transformation.

Add an invalid-encoding or false-condition request as a negative control. Hold method, path, cookies, headers, body shape, and unrelated fields constant. This separates decoder evidence from block-page, fallback, caching, and ignored-parameter behavior.

## 3. Derive hypotheses from clues

Prioritize transformations supported by evidence:

- Base64-looking padding, URL-safe alphabets, opaque tokens that decode cleanly, client-side encode/decode calls, or API documentation suggest an application wrapper.
- A JSON body suggests JSON escape processing; XML or multipart suggests parser-specific field and boundary behavior.
- A `charset` parameter or non-UTF client serialization suggests request-body character decoding.
- Repeated names in traffic, array syntax, framework stack traces, or documented binders suggest duplicate-parameter behavior.
- Cache headers, route-dependent response equivalence, rewrites, or framework-specific suffixes suggest path delimiter and normalization tests.
- A reflected framework expression, error type, or recognizable template object suggests engine-native alternate syntax rather than generic encoding.

Prefer source-informed and observed variants over generic mutation lists.

## 4. Reduce before rebuilding

When a request is blocked, remove or neutralize one region at a time to identify the smallest triggering atom. Work backward from comments, separators, operators, function names, delimiters, and data literals. Retest removed elements after other regions change because signature rules may depend on combinations.

Once the trigger is isolated, rebuild a minimal proof from components that are valid for the downstream grammar. This is more reliable than stacking unrelated encodings and makes the report explainable.

## 5. Differential test families

### Application-decoded wrappers

Base64, Base64url, hex, compression, encryption, or serialized blobs are application protocols. Use them only when a decoder is evidenced. Preserve exact bytes and separately account for transport parsing of `+`, `/`, `=`, percent signs, padding, Unicode, and nulls. Determine whether validation occurs before decoding, after decoding, both, or neither.

### Request charset

Some server stacks decode request bodies according to the `Content-Type` charset while an upstream control assumes UTF-8. Test only charsets plausibly accepted by the observed stack. Preserve field delimiters according to the server's actual rules, start with benign canaries, and reject conclusions based only on a missing block response.

### Structured serialization

For JSON, compare literal characters with JSON Unicode escapes while keeping the decoded string identical. For XML or multipart, first fingerprint which element, attribute, field, filename, duplicate, or part the application selects. Do not convert the body to a different media type unless the endpoint demonstrably accepts both formats.

### Duplicate parameters and recombination

Send harmless distinct values and observe whether each stage chooses the first, last, all, an array, or a delimiter-joined value. A useful differential can occur when the WAF inspects values individually but the framework concatenates them before a JavaScript, SQL, template, or path sink. Confirm the actual join delimiter and final grammar.

### URL, path, and cache normalization

Test a known route, a random suffix, then one candidate delimiter before the suffix. Compare literal and encoded forms. Use non-cacheable requests or unique cache busters to fingerprint the origin; use explicit hit/miss evidence when fingerprinting a cache. Track percent decoding, reserved characters, dot-segment removal, slashes, matrix variables, extensions, rewrites, and absolute URL parsing separately.

### Framework and language semantics

Filters often recognize common spellings rather than every equivalent expression supported by the final engine. After identifying the engine, test harmless alternate comparison operators, whitespace, literals, escapes, property access, filters, or fallback grammars one feature at a time. An engine-native reconstruction may be more important than transport encoding.

## 6. Safe automation

Automate a transformation only after a manual request proves it preserves semantics. A useful runner should:

- mutate one dimension at a time;
- assign unique request and parameter canaries;
- store exact raw requests and response fingerprints;
- compare matched positive, negative, and no-op controls;
- cap concurrency, timing probes, retries, and total requests;
- stop on instability, rate limiting, cross-user effects, or unclear authorization;
- never enumerate sensitive data merely because a bypass works.

Automation should reproduce a hypothesis, not replace parser analysis.

## 7. Bug-class confirmation matrix

| Sink | Minimal confirmation |
| --- | --- |
| File read/LFI | Controlled file or stable known-file signature outside the intended mapping |
| SQLi | Repeatable boolean/result/error pair or bounded timing signal with matched controls |
| SSTI | Harmless server-side arithmetic or engine-object marker |
| XSS | Minimal benign execution in the intended browser origin and victim context |
| SSRF | Controlled callback or deterministic internal-resource distinction permitted by scope |
| URL validation | Intended and actual destination differ after all parsers |
| Cache | Explicit cache-key/hit evidence using a unique non-shared test object or cache buster |

A generic `200`, response-length change, timeout, or absent WAF banner is one observation. Pair it with exact request bytes, stable controls, and parser evidence so the reported capability is reproducible.

## 8. Reporting

Report the observed capabilities clearly and follow the program's rules on whether they belong together or separately:

1. Control differential: the WAF, proxy, validator, or sanitizer interpreted the request differently.
2. Downstream behavior, when present: the final sink consumed attacker-controlled meaning in a security-relevant way.

Include a parser diagram or ledger, exact equivalent controls, the smallest successful transformation, negative controls, any final-sink evidence, affected stack assumptions, and a bounded impact statement. Avoid claiming a universal vendor bypass from one configuration.

## 9. Remediation

- Fix the underlying injection, file, URL, cache, or authorization flaw; do not rely on the WAF as the primary fix.
- Define one canonical request representation and normalize once before validation and use.
- Make edge and application layers agree on URL decoding, path mapping, duplicate parameters, structured bodies, and forwarded values.
- Allowlist required media types and charsets; reject malformed, ambiguous, unsupported, or multiply encoded input.
- Parse structured data with the same grammar used by the application or enforce it after parsing.
- Reject unexpected duplicate parameters or define a single deterministic selection rule.
- Keep decoded SQL values parameterized, decoded template values as data, paths mapped from identifiers, URLs parsed once with an allowlist, and browser output encoded for its final context.
- Regression-test both the root sink and the representation that crossed the defensive layer.

## 10. Lessons extracted from prior research

The workflow above synthesizes recurring lessons from these original researcher write-ups without copying their payload lists:

1. RCE via Spring error-page SSTI with WAF bypass - build complex proofs upward from small expressions known to work in the identified engine.
2. Real-case SQLi character-encoding bypass - use response differentials to isolate accepted syntax, then automate the proven transformation.
3. JSON Unicode escape WAF bypass - inspect the actual structured parser and adapt automation only after manually confirming decoded equivalence.
4. Industry-leading WAF and blind SQLi - reduce the blocked expression atom by atom and confirm with controlled timing or result behavior.
5. Jinja2 SSTI methodology - use language-native literals, filters, and reconstruction only after fingerprinting the template engine.
6. JavaScript injection through parameter pollution - fingerprint duplicate-parameter recombination and the final JavaScript grammar.
7. URL validation bypass research - select mutations for the exact URL context and parser rather than using one universal URL list.
8. Cache and origin path parser discrepancies - use baselines, random suffixes, delimiters, cache busters, and hit evidence to distinguish each parser.
9. JavaScript framework parser abuse - understand framework-specific URL and expression semantics that generic mitigations do not model.
10. Request charset encoding against WAFs - test request-body charsets only where the server stack decodes them and enforce a narrow charset policy defensively.
