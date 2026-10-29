# Server-Side Primitives

Use this reference for RCE, SQL/NoSQL injection, SSRF, SSTI, file access, unsafe deserialization, import/export, document conversion, and privileged workers. Start from the component and trust boundary, not a payload catalog.

## Shared source-to-sink method

For every candidate, trace:

```text
entry -> decoding/normalization -> binder/model -> guard -> storage/queue
      -> worker/service identity -> interpreter/query/fetcher/filesystem -> observable
```

Record which layer owns each decision. A controller may validate input while a model callback or worker later interprets the stored value differently.

## RCE and dangerous interpreters

### Find interpreters by behavior

Prioritize:

- template, expression, macro, rules, and workflow engines;
- shell/process wrappers and command-building helpers;
- plugin, package, theme, and extension installation;
- archive, media, PDF, office, image, and document conversion;
- CI/CD, build, preview, rendering, and deployment hooks;
- deserialization, message decoding, RPC, WSDL/SOAP, and protocol handlers;
- support/admin diagnostics, test-connection, and import tools;
- jobs that run under a stronger service or operating-system identity.

Enumerate the state machine around the interpreter. The April 2025 [Erlang/OTP SSH unauthenticated RCE advisory](https://github.com/erlang/otp/security/advisories/GHSA-37cp-fgq5-7wc2) is a concrete reminder to review message handlers reachable before authentication or before the intended protocol state. Transfer the state-machine question, not the CVE conclusion: require evidence that the target uses the affected component, exposes the service, and reaches the relevant handler.

### Code-to-runtime questions

1. Can attacker-controlled data reach the interpreter in the deployed feature?
2. Which transformations occur before interpretation?
3. Is the value data, a template, an identifier, a path, or code?
4. Which user/container/service identity executes it?
5. Is execution synchronous, queued, preview-only, or triggered by another user?
6. What configuration, feature flag, file type, or protocol state is required?
7. What is the smallest benign observable?

### Proof ladder

Climb only as far as policy and minimum proof require:

1. syntax-specific response or controlled error;
2. harmless deterministic evaluation;
3. controlled callback or unique temporary marker;
4. execution-context evidence that does not expose secrets;
5. stop.

Do not establish persistence, read unrelated files or environment secrets, or execute broad system commands to strengthen severity.

## SQL, NoSQL, ORM, and filter injection

### High-value construction sites

- dynamic identifiers, sort keys, field selectors, and table/model names;
- arrays, list expansion, repeated parameters, and collection binders;
- report builders, analytics filters, saved searches, and query DSLs;
- ORM relation filters, joins, eager loading, projections, and computed fields;
- headers, filenames, import metadata, webhooks, and values stored for later staff views;
- second-order queries executed by exports, scheduled reports, admin tools, or another user’s database identity;
- tenant or role predicates built separately from the user-controlled filter.

Prepared statements do not protect dynamic identifiers, unsafe raw fragments, parser bugs in emulated prepares, or logic that lets a filter remove the authorization predicate.

### Confirmation

Use repeated paired controls:

- true versus false condition;
- short versus long bounded delay;
- valid versus invalid syntax with a clean baseline;
- controlled record present versus absent;
- role/tenant A versus B with unmistakable test data.

Identify query context and execution identity. Do not dump unrelated records. A database error, isolated delay, or scanner signature is a lead only.

### ORM leakage

Treat search and filter APIs as authority-bearing programs. Ask whether joins, relation filters, counts, ordering, error shape, or aggregate behavior reveal data outside the selected projection. Compare equivalent filters across roles and tenants and verify with controlled records.

## SSRF and server-side fetching

### Find hidden fetchers

Look beyond obvious URL inputs:

- remote attachments, imports, avatars, images, previews, unfurls, charts, and analytics;
- PDF, office, SVG, font, stylesheet, media, and document conversion;
- webhooks, OAuth/OIDC metadata, SAML metadata, WSDL, package registries, and repository imports;
- health checks, test-connection tools, monitoring, backup, and migration features;
- framework redirects, server actions, image optimizers, middleware, and model callbacks;
- hidden serialized fields accepted by importers but absent from the UI;
- second-order workers that fetch after storage, approval, or delivery.

### Map the fetch lifecycle

```text
input -> parse/canonicalize -> scheme/host policy -> DNS -> connect/proxy
      -> redirect -> re-resolution -> credentials/service identity
      -> response read -> parser/storage/renderer -> observable
```

Record which component validates and which component connects. Re-check redirects, DNS changes, alternate address families, and final canonical authority only when the architecture indicates those paths exist.

### Safe proof

Use unique controlled HTTP/DNS endpoints and a no-callback control. Correlate method, timing, headers, source, redirect behavior, and worker delay. Distinguish target-owned fetching from the researcher’s browser, link previewers, email scanners, or security products.

Classify only what is proven:

- outbound request;
- status/title/size or other partial response metadata;
- full controlled response read;
- credentialed request using a service identity;
- delayed/second-order fetch;
- cross-tenant fetch or confused callback.

Do not enumerate internal networks or retrieve cloud credentials. A blind callback alone does not prove access to a sensitive internal service.

## SSTI and expression evaluation

### Surface selection

Prioritize tenant-customizable email, notification, receipt, PDF, label, theme, error, workflow, and document templates. Compare preview with actual background delivery; they often use different engines or contexts.

### Method

1. Determine whether the user controls template source or only template data.
2. Identify engine and context using harmless syntax/evaluation pairs.
3. Compare literal-text controls with deterministic evaluation.
4. Trace sandbox, exposed objects, filters, imports, and worker identity.
5. Separate evaluation, object access, file access, and code execution as distinct capabilities.
6. Stop at the smallest controlled proof.

Error-based and side-channel techniques may confirm blind evaluation, but require repeated paired controls. Do not infer RCE from arithmetic evaluation.

## Files, imports, archives, and converters

Treat these as pipelines:

```text
admission -> metadata/format detection -> extraction/transformation
          -> storage -> preview/serve -> later reuse
```

Test the final consumer’s interpretation, not only the upload gate. Useful questions:

- Does archive extraction change namespaces or overwrite controlled files?
- Does a renderer resolve local paths, remote URLs, fonts, stylesheets, or nested documents?
- Can an import set a model field the current UI hides?
- Do callbacks execute before field allowlisting or authorization?
- Are generated thumbnails, PDFs, or CDN copies served under different policy?
- Does a worker carry broader storage, network, database, or cloud authority?

Use harmless marker files and controlled storage. Do not upload malware or read unrelated files.

## Deserialization and message boundaries

Identify the concrete parser, message type, object graph, signer, and allowed classes. Verify whether data is attacker-controlled before discussing gadget chains. Pay special attention to:

- signed but attacker-created objects;
- encrypted data without integrity;
- type metadata and polymorphic binding;
- cross-language message translation;
- queue consumers and retry/dead-letter processing;
- protocol messages accepted in the wrong authentication state.

A recognizable serialization format or dependency is not proof of unsafe deserialization.

## Privileged workers and service identities

For operators, workers, schedulers, and automation services, map:

```text
requesting actor -> user-controlled reference -> queued instruction
                 -> service identity -> target namespace/resource -> action
```

Test whether the service re-authorizes the current actor and object at use time. Compare user versus group/tenant destinations, parent versus child visibility, scheduling versus execution, and access revoked before the worker runs.

## False-positive controls

Reject or downgrade:

- source sinks unreachable in the deployed configuration;
- callbacks caused by a browser or scanner;
- accepted fields that are ignored;
- generic errors or delays without paired controls;
- static/template text that is never interpreted;
- local tool rendering mistaken for target-side execution;
- database or filesystem behavior using only the researcher’s own public data;
- theoretical privileged identity with no reachable user-controlled instruction.

## Remediation invariants

State fixes as system properties:

- interpret untrusted input only as data;
- authorize the current actor, object, tenant, and action at the final use point;
- allowlist imported fields before model callbacks;
- bind queries structurally and keep authority predicates outside user-controlled DSLs;
- validate the final canonical destination at every fetch and redirect;
- isolate workers from unnecessary credentials, filesystems, networks, and control planes;
- reject ambiguous or out-of-state protocol messages.
