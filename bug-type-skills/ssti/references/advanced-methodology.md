# SSTI Methodology

Use this reference to test server-side template execution.

## 1. Surface inventory

List email templates, CMS fields, previews, themes, imports, names, custom blocks, Markdown/HTML renderers, and PDF generators.

## 2. Fingerprinting

Use harmless arithmetic/marker payloads and syntax errors to identify engine and context.

## 3. Application-decoded input checks

If frontend code, documentation, or captured traffic shows that template content or a variable is transported as Base64, Base64url, hex, or another wrapper, compare exact equivalent harmless marker and arithmetic controls in raw and supported encoded forms. Trace decoding relative to validation and rendering. A `403` to `200` transition is not proof; require repeatable server-side expression evaluation after decoding.

Use malformed encoded data and a second benign value as negative controls. Distinguish an application decoder from a template expression that explicitly invokes a decoder, because they imply different sources, sinks, and remediation.

## 4. Context review

Differentiate literal echo, client-side templates, server templates, sandboxed templates, and privileged admin renderers.

## 5. Impact checks

Assess object access, file read, environment variables, command execution, SSRF, and stored admin-context execution.

## 6. Remediation checklist

- Avoid rendering user-controlled templates.
- Decode supported transport formats once before validation and keep the decoded value as data, never as template source.
- Use safe variable interpolation.
- Sandbox engines and remove dangerous objects.
- Separate template authorship by role.
- Regression-test template contexts.
