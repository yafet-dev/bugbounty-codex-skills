# File Reading Methodology

Use this reference to test filesystem and file-fetch boundaries.

## Start here: how hunters found this in real reports

1. **Collect path-like inputs.** Include download names, image and font URLs, archive entries, export templates, document references, backup paths, and storage keys.
2. **Trace every transformation.** Record URL decoding, Unicode handling, path normalization, archive extraction, mount mapping, proxy rewrites, and worker handoffs.
3. **Identify the final namespace.** Determine whether the sink reads a local filesystem, container mount, object store, network share, or converter sandbox.
4. **Use a controlled marker first.** Read a file or object you created and whose contents are unmistakable; this proves the path reaches the intended sink.
5. **Compare front-end and downstream checks.** The web route may reject traversal while a PDF renderer, image processor, or storage proxy resolves it later.
6. **Check credential scope.** A narrow path bug becomes more serious when the reader carries a broad bucket, proxy, or service identity.

### Expand the pattern

Test sibling renderers and download routes that share the same helper. Stop at a harmless proof and describe the reachable namespace; do not collect real secrets.

## 1. Input inventory

List filename, path, URL, archive entry, template, export HTML, image metadata, attachment, import, callback, and storage key inputs.

## 2. Namespace mapping

Identify server filesystem, container filesystem, client filesystem, storage bucket, cloud metadata, renderer sandbox, or internal service.

## 3. Traversal checks

Test encoding, mixed separators, absolute paths, symlinks, archive paths, Windows paths, Unicode normalization, and prefix bypasses.

## 4. Application-decoded transport checks

When an application accepts Base64 or another wrapper, map the decoder and record whether the representation changes edge/WAF handling, application semantics, or filesystem behavior. Treat each observed capability separately under the program's rules.

1. Look for evidence of an encoded contract in frontend code, API documentation, captured requests, sibling parameters, recognizable padding, or a successful decode of a harmless value.
2. Choose a benign known file or controlled filename. Create raw and encoded forms from the exact same bytes, preserving leading slashes, separators, case, and terminators. For example, Base64 for `/path` is not a valid control for raw `path` because those paths have different semantics.
3. Send a baseline, the raw value, and one supported encoded form while holding all other request state constant. Percent-encode transport characters such as `+`, `/`, or `=` when the enclosing query or form parser requires it.
4. Record the full normalization chain: URL/form parsing, Base64 or Base64url decoding, character decoding, path normalization, validation, and filesystem access. Test alternate alphabets or missing padding only when client behavior suggests support.
5. Record status, length, and filtering differences, then separately test for returned controlled content, a stable known-file signature, or equivalent file-read evidence so each capability is supported by its own evidence.
6. Use a negative control containing invalid encoded data and a second harmless valid value to rule out default-file behavior, error-page differences, caching, or a parameter the server ignores.

Once a decode-before-validate mismatch is established, test only the minimum authorized path variants needed to demonstrate the boundary failure. Avoid treating arbitrary encoding mutations as separate vulnerabilities.

## 5. Renderer checks

Review PDF/HTML/SVG/image converters for local file fetch, SSRF, external resources, and metadata-triggered reads.

## 6. Confirmation rules

Use controlled files first; then assess secrets such as configs, env vars, source, tokens, metadata, and tenant files.

## 7. Remediation checklist

- Canonicalize paths before policy checks.
- Decode supported transport formats exactly once, reject malformed or ambiguous encodings, then canonicalize and validate the decoded path before filesystem use. Apply equivalent policy at the edge and application layers.
- Use allowlisted storage IDs, not raw paths.
- Disable local file fetch in renderers.
- Sanitize archives and reject symlinks/traversal.
- Isolate converters and workers.

## 8. What successful reports teach

- **Renderers create a second filesystem boundary.** An HTML-to-PDF LFI report shows why HTML, CSS, image, font, and stylesheet fetches must be traced inside the converter rather than judged by the web route alone.
- **Path traversal can combine with an over-broad credential.** The restricted-data traversal report motivates testing storage paths together with cookies, signed URLs, proxy authorization, or bucket identities.
- **Client applications have local file boundaries too.** Download and attachment handlers can traverse user-writable directories or overwrite sensitive files; test the destination path and post-download consumer separately.
- **Worker isolation defines impact.** Public container-escape and worker-read reports suggest recording mounts, service credentials, host paths, and whether tenant jobs share a worker or volume.

## 9. Source-to-namespace tracing

For each candidate, record:

```text
input -> transport decode -> application decode -> join/base path
      -> canonicalization -> policy check -> symlink/archive resolution
      -> filesystem/storage identity -> reader/renderer -> response or callback
```

Test parent and child identifiers together. A safe parent directory with an attacker-controlled archive entry, symlink, storage key, template include, or renderer URL can cross the boundary after the initial check.

Differentiate read primitives:

- application reads and returns bytes;
- renderer embeds local content in an output;
- worker uses a file as configuration, template, or code;
- client writes or opens a path on the user's device;
- SSRF-capable fetcher reaches `file` or a local service that returns files.

## 10. Confirmation controls

- Start with a unique controlled file or documented harmless system file allowed by policy.
- Use two distinct paths with different known contents to rule out static error pages and default files.
- Re-test with a fresh cache key and without browser/service-worker caches.
- Treat disclosed path strings, exception messages, or existence oracles separately from content read.
- Stop before secrets when a controlled file already proves the same boundary and impact can be established from the execution context.
