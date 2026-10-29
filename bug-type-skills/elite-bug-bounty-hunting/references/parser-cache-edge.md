# Parser, Cache, and Edge Methodology

Use this reference for request smuggling/desynchronization, cache poisoning or deception, WAF/parser differentials, URL confusion, middleware bypass, Unicode normalization, content-type confusion, and protocol translation. These areas can affect shared infrastructure; follow the program’s explicit rules and use controlled keys and clients.

## Draw the interpretation chain

Record every component that may parse, normalize, route, key, or authorize the request:

```text
client -> CDN/cache -> WAF -> gateway/load balancer -> protocol downgrade
       -> reverse proxy -> framework router/middleware -> binder/decoder
       -> authorization guard -> application sink -> response cache/browser
```

For each layer capture:

- protocol and connection reuse;
- raw bytes or structured representation received;
- path, authority, method, body length, content type, and charset selected;
- duplicate-field behavior;
- decoding and normalization order;
- internal/sentinel headers added or trusted;
- cache key and cacheability decision;
- identity/tenant context forwarded;
- whether ambiguous input is rejected or repaired.

The target hypothesis is always “guard sees A while consumer acts on B,” not “an encoding bypasses a filter.”

## Baseline quartet

Before active mutation, establish:

1. a normal accepted request;
2. a normal rejected request;
3. a suspicious semantic value that the guard should reject;
4. a harmless value shaped similarly to the suspicious one.

Change only one representation feature at a time. Compare exact bytes, normalized values, selected route/object, cache behavior, and final sink effect.

## High-value differential families

### Authority and URL parsing

Compare which component selects scheme, host, port, path, query, fragment, userinfo, and redirect authority. Focus on real URL consumers: server fetchers, OAuth callbacks, password-reset links, tenant routing, image optimizers, proxy rules, and caches.

The finding requires a protected destination, route, identity, or response consequence. A strange parse with no security decision is not enough.

### Path and routing normalization

Map dot segments, duplicate separators, encoded delimiters, suffixes, matrix/path parameters, trailing forms, case, Unicode normalization, and framework rewrites only as supported by the observed stack. Compare edge policy, middleware match, final handler, and cache key.

### Structured bodies and duplicate fields

Test JSON, form, multipart, XML, GraphQL, and custom wrappers for differences in:

- first/last/all duplicate selection;
- array versus scalar binding;
- nested object flattening;
- field-name normalization;
- MIME part parameter selection;
- charset and Unicode handling;
- validation of one representation followed by consumption of another.

Use semantic pairs and inspect the final object or action. Do not spray parser tricks without a sink hypothesis.

### Internal and sentinel headers

Frameworks and proxies may mark rewrites, subrequests, authenticated users, original URLs, or middleware state in headers. Determine:

1. who is supposed to create the header;
2. where external copies are stripped;
3. whether direct-origin or alternate ingress bypasses stripping;
4. whether the final handler rechecks authentication and authorization;
5. whether case, duplication, list parsing, or protocol conversion changes provenance.

An externally accepted internal header matters only when it changes a protected decision.

### Unicode and canonicalization

Record normalization form, encoding, case folding, confusable handling, filesystem/database collation, and the layer where canonicalization occurs. Compare the identifier used by validation with the identifier used for lookup or execution. Use controlled accounts/objects whose normalized forms are unmistakable.

## Cache methodology

### Model every cache separately

Inventory browser, CDN, reverse-proxy, framework, data, fragment, and application caches. For each, learn:

- key components and ignored inputs;
- normalization before keying;
- cacheable methods, statuses, content types, routes, and extensions;
- `Vary`, cookie, authorization, tenant, and locale behavior;
- TTL, revalidation, stale behavior, and purge boundaries;
- whether errors, redirects, personalized data, and generated assets are cached;
- which inner cache can influence an outer one.

### Safe cache experiment

1. Use a unique path or researcher-specific cache key.
2. Establish miss/hit/revalidation behavior with a harmless marker.
3. Change one possible unkeyed input.
4. Confirm the origin processes it meaningfully.
5. Request with a second clean controlled session.
6. Verify the same cached object and a security-relevant cross-session effect.
7. Stop and allow or trigger safe expiry only as policy permits.

An unkeyed input is not a finding. A manipulated response that never reaches another security context is not a finding.

### Cache deception

Prove separately:

- the origin treats the request as personalized or protected;
- the cache treats it as shared/cacheable;
- another controlled session can retrieve the cached sensitive marker;
- authentication, tenant, and query/path differences are not part of the key;
- the behavior is not a local proxy artifact.

Use controlled records only.

## Desynchronization and request-boundary research

These tests can affect other users and infrastructure. Perform them only when explicitly allowed.

### Method

1. Confirm multiple HTTP parsers or protocol translation exists.
2. Use a harmless canary against the researcher’s own immediate follow-up request.
3. Reduce the disagreement to one message-boundary or translation rule.
4. Determine which methods, paths, headers, protocols, and connection pools are affected.
5. Search for a second target-specific gadget: cache, redirect, routing, internal API, authentication, or response confusion.
6. Demonstrate cross-request influence only with controlled clients and non-cacheable markers.
7. Stop before unrelated traffic can be affected.

Classic probes can miss edge-internal or protocol-specific discrepancies. Conversely, a timeout or connection error is not confirmation. The primitive requires repeatable evidence that two components disagree on the boundary.

### Impact discipline

Keep these separate:

- parser disagreement;
- influence over the researcher’s own next request;
- influence across controlled clients;
- reachable application gadget;
- verified security consequence.

Do not jump from the first line to mass compromise.

## WAF and validation differentials

A defensive bypass can be studied independently or as one edge in a larger chain. Workflow:

1. identify the final security-sensitive sink;
2. obtain a harmless sink-specific signal;
3. isolate the minimal value the control blocks;
4. derive one parser hypothesis from observed transformations or documentation;
5. compare semantically equivalent pairs and a negative control;
6. confirm the downstream sink behavior;
7. preserve the differential and any downstream behavior separately, then apply the program's reporting rules.

## Side channels

Error shape, response size, ETag, timing, redirect behavior, connection scheduling, cache state, and ORM result shape can reveal hidden state. Require:

- a falsifiable state hypothesis;
- randomized, repeated paired measurements;
- clean-session and network controls;
- a meaningful secret or authorization boundary;
- an explanation that survives ordinary jitter and caching.

Do not report one statistical anomaly.

## False-positive controls

Reject or downgrade:

- status-code changes without route/sink differences;
- cache headers without cross-session body evidence;
- local Burp/browser cache artifacts;
- apparent desync that is normal connection closure;
- an accepted internal header that changes nothing protected;
- canonicalization differences with no identity/object collision;
- shared-cache tests performed without a unique safe key;
- timing/size differences that disappear under randomized controls.

## Remediation invariants

- Reject ambiguous requests at the first boundary and keep parser behavior consistent across hops.
- Strip and regenerate internal headers at every trust boundary; authorize again at the final handler.
- Canonicalize once before validation and use the same canonical value at the sink.
- Key every security-relevant response input or do not cache the response.
- Never cache personalized content in a shared cache without an explicit, tested policy.
- Revalidate authorization and routing after rewrites, redirects, and protocol translation.
