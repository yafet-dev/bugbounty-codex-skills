# File Upload Methodology

Use this reference to test upload pipelines.

## Start here: how hunters found this in real reports

1. **Map the whole pipeline.** Admission, validation, transformation, metadata extraction, storage, preview, download, and later reuse can each interpret the file differently.
2. **Create paired control files.** Keep content constant while changing one of extension, MIME type, filename, archive path, metadata, or internal format.
3. **Follow generated versions.** Thumbnails, PDFs, extracted archives, transcoded media, and CDN copies may bypass the original validation decision.
4. **Ask who consumes it next.** Admin review, email, browser rendering, document conversion, import, and antivirus workers create new trust boundaries.
5. **Use harmless proof content.** Confirm server-side processing, cross-user delivery, or active rendering without executing destructive commands or uploading malware.
6. **Verify storage and serving policy separately.** Check authentication, tenancy, content disposition, sniffing, caching, and whether deleted or private files remain reachable.

### Expand the pattern

Once one processor disagrees with the upload gate, test every file type and feature routed through that processor. Report the exact stage where trust changed.

## 1. Pipeline inventory

Record accepted types, validators, storage, URLs, processors, previews, conversions, metadata, and deletion lifecycle.

## 2. Validation checks

Test extension, MIME, magic bytes, filename, size, dimensions, archive structure, and content scanning.

## 3. Processing checks

Review thumbnailers, SVG/PDF renderers, OCR, virus scanners, importers, converters, and background jobs for SSRF/RCE/XSS.

## 4. Serving checks

Check content type, content disposition, CSP, cookies, cache, public/private storage, and access control.

## 5. Remediation checklist

- Store uploads outside executable paths.
- Use allowlisted types and content rewriting.
- Serve from isolated domains.
- Sanitize filenames and metadata.
- Sandbox processors and validate archives.

## 6. What successful reports teach

Public upload reports cluster around different post-upload consumers:

- Direct execution when an uploaded object lands in an executable or interpretable path, including report-logo and web-root cases such as report-logo RCE.
- Active content served in a trusted origin, producing stored XSS even when server-side execution is impossible.
- Metadata or filename content processed in a privileged admin, scanner, or review context, producing blind XSS or command/argument injection.
- Media and document processors fetching external or local resources; the FFmpeg upload report demonstrates why the converter's network and file privileges matter.
- Archive extraction, overwrite, and path traversal that change a different file than the uploaded object.

## 7. Five-decision pipeline

Test each decision independently:

1. **Admission:** who may upload, which field, size, count, and declared type.
2. **Identification:** extension, MIME, signature, parser result, and filename normalization.
3. **Transformation:** image rewrite, metadata strip, OCR, archive extraction, transcoding, document rendering, malware scan.
4. **Storage:** generated key, tenant/owner, overwrite semantics, ACL, lifecycle, and public URL.
5. **Serving/consumption:** content type, disposition, origin, CSP, cache, renderer, browser, admin UI, or downstream import.

An allowlisted extension at admission does not protect a later consumer that selects a parser from content, metadata, or an inner archive member. Record which bytes survive each transformation and which identity the worker uses.

## 8. Differential and confirmation controls

- Compare declared type, detected type, stored type, and served type for the same benign sample.
- Use unique harmless markers in filename, metadata, body, and archive entry to identify which field reaches a consumer.
- Confirm owner/tenant checks on upload, processing status, preview, direct download, replacement, and deletion.
- Distinguish a file being stored from it being interpreted; prove the minimum relevant consumer behavior.
- Use a non-executable controlled artifact or callback when it proves processor reachability; do not deploy persistent shells.
