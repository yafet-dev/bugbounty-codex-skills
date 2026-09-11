# WAF Parser Differential Methodology

Use this reference to investigate authorized cases where a control and downstream application assign different meaning to the same request.

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

A generic `200`, different response length, timeout, or absent WAF banner is not sufficient.

## 8. Reporting

Report two linked facts:

1. Root cause and impact: the downstream sink consumes attacker-controlled meaning unsafely.
2. Control differential: the WAF, proxy, validator, or sanitizer interpreted the request differently and therefore did not mitigate the root flaw.

Include a parser diagram or ledger, exact equivalent controls, the smallest successful transformation, negative controls, final sink evidence, affected stack assumptions, and a bounded impact statement. Avoid claiming a universal vendor bypass from one configuration.

## 9. Remediation

- Fix the underlying injection, file, URL, cache, or authorization flaw; do not rely on the WAF as the primary fix.
- Define one canonical request representation and normalize once before validation and use.
- Make edge and application layers agree on URL decoding, path mapping, duplicate parameters, structured bodies, and forwarded values.
- Allowlist required media types and charsets; reject malformed, ambiguous, unsupported, or multiply encoded input.
- Parse structured data with the same grammar used by the application or enforce it after parsing.
- Reject unexpected duplicate parameters or define a single deterministic selection rule.
- Keep decoded SQL values parameterized, decoded template values as data, paths mapped from identifiers, URLs parsed once with an allowlist, and browser output encoded for its final context.
- Regression-test both the root sink and the representation that crossed the defensive layer.

## 10. Ten-source research synthesis

The workflow above synthesizes recurring lessons from these original researcher write-ups without copying their payload lists:

1. [RCE via Spring error-page SSTI with WAF bypass](https://www.pmnh.site/post/writeup_spring_el_waf_bypass/) - build complex proofs upward from small expressions known to work in the identified engine.
2. [Real-case SQLi character-encoding bypass](https://wetofu.github.io/blog/2024/07/06/real-case---bypass-sql-injection-using-character-encoding-and-sqlmap-tamper/) - use response differentials to isolate accepted syntax, then automate the proven transformation.
3. [JSON Unicode escape WAF bypass](https://trustfoundry.net/blog/bypassing-wafs-with-json-unicode-escape-sequences) - inspect the actual structured parser and adapt automation only after manually confirming decoded equivalence.
4. [Industry-leading WAF and blind SQLi](https://blog.stratumsecurity.com/2023/06/01/sqli-the-road-to-bypassing-an-industry-leading-waf/) - reduce the blocked expression atom by atom and confirm with controlled timing or result behavior.
5. [Jinja2 SSTI methodology](https://onsecurity.io/article/server-side-template-injection-with-jinja-2-for-you/) - use language-native literals, filters, and reconstruction only after fingerprinting the template engine.
6. [JavaScript injection through parameter pollution](https://blog.ethiack.com/blog/bypassing-wafs-for-fun-and-js-injection-with-parameter-pollution) - fingerprint duplicate-parameter recombination and the final JavaScript grammar.
7. [URL validation bypass research](https://portswigger.net/research/introducing-the-url-validation-bypass-cheat-sheet) - select mutations for the exact URL context and parser rather than using one universal URL list.
8. [Cache and origin path parser discrepancies](https://portswigger.net/research/gotta-cache-em-all) - use baselines, random suffixes, delimiters, cache busters, and hit evidence to distinguish each parser.
9. [JavaScript framework parser abuse](https://portswigger.net/research/abusing-javascript-frameworks-to-bypass-xss-mitigations) - understand framework-specific URL and expression semantics that generic mitigations do not model.
10. [Request charset encoding against WAFs](https://soroush.me/downloadable/request-encoding-to-bypass-web-application-firewalls.pdf) - test request-body charsets only where the server stack decodes them and enforce a narrow charset policy defensively.
