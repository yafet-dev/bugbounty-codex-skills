# File Reading Methodology

Use this reference to test filesystem and file-fetch boundaries.

## 1. Input inventory

List filename, path, URL, archive entry, template, export HTML, image metadata, attachment, import, callback, and storage key inputs.

## 2. Namespace mapping

Identify server filesystem, container filesystem, client filesystem, storage bucket, cloud metadata, renderer sandbox, or internal service.

## 3. Traversal checks

Test encoding, mixed separators, absolute paths, symlinks, archive paths, Windows paths, Unicode normalization, and prefix bypasses.

## 4. Application-decoded transport checks

Encoding is useful only when some application layer decodes it before the sensitive sink. Base64 is not an automatic WAF bypass and provides no security boundary by itself.

1. Look for evidence of an encoded contract in frontend code, API documentation, captured requests, sibling parameters, recognizable padding, or a successful decode of a harmless value.
2. Choose a benign known file or controlled filename. Create raw and encoded forms from the exact same bytes, preserving leading slashes, separators, case, and terminators. For example, Base64 for `/path` is not a valid control for raw `path` because those paths have different semantics.
3. Send a baseline, the raw value, and one supported encoded form while holding all other request state constant. Percent-encode transport characters such as `+`, `/`, or `=` when the enclosing query or form parser requires it.
4. Record the full normalization chain: URL/form parsing, Base64 or Base64url decoding, character decoding, path normalization, validation, and filesystem access. Test alternate alphabets or missing padding only when client behavior suggests support.
5. Confirm with returned controlled content, a stable known-file signature, or equivalent file-read evidence. A status transition, response-length change, or missing WAF block without file content is only a filter differential.
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
