# XXE Methodology

Use this reference to test XML entity resolution boundaries.

## Start here: how hunters found this in real reports

1. **Find XML hiding inside features.** Office files, SVG, SAML, SOAP, feeds, mobile backups, document conversion, imports, and metadata parsers may invoke XML without an XML endpoint.
2. **Trace parser stages.** Identify archive extraction, format detection, schema validation, transformation, worker queue, and the library that performs entity resolution.
3. **Use a controlled external reference.** A unique callback plus a no-reference control can prove resolution without reading local files.
4. **Check delayed processing.** Preview, antivirus, indexing, thumbnail, and conversion workers may parse after the upload request returns.
5. **Distinguish parser behaviors.** External entity resolution, XInclude, DTD fetch, stylesheet fetch, and expansion limits are separate questions.
6. **Stop at a harmless boundary.** Do not retrieve real files or probe internal networks; show the parser made the controlled request or resolved a controlled marker.

### Expand the pattern

After identifying the parser library and worker, test every supported format that reaches it. State the exact unsafe parser option and processing stage.

## 1. Parser inventory

List XML bodies, SOAP, SAML, SXMP, SVG, Office, PDF, XMP metadata, uploads, imports, converters, and background processors.

## 2. Entity checks

Test harmless DTD/entity behavior, external general entities, parameter entities, external DTDs, and parser error output.

## 3. Blind channels

Use controlled DNS/HTTP callbacks, timing, error differences, and async processing artifacts.

## 4. Impact checks

Assess local file read, SSRF, metadata access, internal services, config disclosure, source disclosure, and credential exposure.

## 5. Remediation checklist

- Disable DTDs and external entity resolution.
- Use hardened XML parser settings.
- Block network/file access in parsers.
- Sanitize SVG/Office/PDF metadata processors.
- Isolate converters and background parsers.

## 6. What successful reports teach

- Public reports cover ordinary XML bodies, SXMP processors, SVG uploads, Office/PDF/image metadata, site-audit imports, and even voice/IVR pipelines. The lesson is to inventory formats that *contain* XML, not only endpoints labeled XML.
- The JPEG XMP metadata report shows that a binary-looking upload can reach an XML metadata parser after admission checks.
- The SVG upload report demonstrates that an image pipeline can create SSRF even when the stored file is never returned as XML.
- Partial-fix and blind-XXE reports show that disabling one entity form or suppressing output may leave external DTD, parameter-entity, stylesheet, schema, or secondary-parser behavior reachable.

## 7. Format-to-parser tracing

For each input record:

```text
container/transport -> decompression or metadata extraction -> XML parser
-> DTD/entity/schema/stylesheet features -> file/network resolver
-> transformed output, error, stored artifact, or background job
```

Identify the actual parser, version, configuration, and process identity where possible. The web framework's parser settings do not protect an image library, office converter, SAML component, SOAP client, PDF tool, or background scanner using a different parser.

Test capability classes separately:

- internal entity expansion only;
- external resource resolution;
- local file read reflected in output;
- blind outbound resolution;
- error-based inclusion;
- XInclude, schema, or stylesheet fetch where applicable;
- asynchronous processing after upload/import.

## 8. Confirmation and controls

- Start with a harmless internal entity or a unique controlled external resource as permitted.
- Use distinct callback hostnames for the application and for possible security scanners; correlate timing and request metadata.
- Pair a valid external reference with a disabled/malformed control to rule out generic XML errors.
- Confirm whether the response contains fetched bytes, only parser errors, or merely an outbound request; these are different primitives.
- Prefer controlled files and callbacks. Stop before reading secrets when the parser's file/network boundary is already proven.
