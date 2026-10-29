# SSTI Methodology

Use this reference to test server-side template execution.

## Start here: how hunters found this in real reports

1. **Find customizable content.** Email bodies, receipts, labels, notifications, PDF templates, themes, error pages, and document generators are common template surfaces.
2. **Separate template source from template data.** Determine whether user text is inserted as a value or compiled again as part of the template.
3. **Compare preview and delivery.** A preview may escape input while a background email or document worker compiles the stored version later.
4. **Fingerprint gently.** Use harmless arithmetic, string operations, or controlled errors and a literal-text negative control.
5. **Identify context and engine.** HTML, text, attribute, expression, and sandbox contexts change what the result means; do not jump from evaluation to code execution.
6. **Prove the smallest consequence.** Show controlled evaluation or a benign callback and record the worker identity without reading secrets or running commands.

### Expand the pattern

Once one tenant-customizable template is confirmed, test all messages and documents using the same renderer. The root cause is untrusted template authorship, not a particular expression.

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

## 7. What successful reports teach

- The Return Magic email-template report shows that tenant-customizable messaging features may compile templates later under a background worker or privileged delivery context.
- Path-traversal/SSTI/RCE chains show that template selection and template content can be separate attacker-controlled inputs.
- CMS-wide and signup-name reports show that an input may be rendered by several engines or contexts—preview, email, PDF, admin UI, and live page—with different privileges.
- Framework/library reports motivate checking exact engine version and configuration before assuming syntax or sandbox behavior.

## 8. Engine and context method

Trace:

```text
input -> storage/transport decode -> template source or data binding
-> engine selection/configuration -> compile/render -> helper/object exposure
-> output sink, filesystem, network, or process capability
```

First distinguish server-side evaluation from literal reflection, client-side templating, Markdown, format-string substitution, and expression languages. Use harmless arithmetic or deterministic string construction with a non-evaluating control. Syntax errors can fingerprint an engine but are not proof of attacker-controlled evaluation.

Classify the controllable context:

- full template source;
- expression position;
- variable value only;
- template name/path;
- helper/filter/macro name;
- stored data rendered only by a privileged user or worker.

Test preview and delivery separately. A safe preview sandbox may differ from email, PDF, notification, or production rendering.

## 9. Proof ladder and controls

1. Deterministic server-side expression evaluation.
2. Read of a harmless engine property or researcher-controlled value.
3. Minimal filesystem/network/process capability if needed and permitted.

Do not jump to command execution when evaluation already proves the root flaw and the engine/context documents the capability. Re-test with fresh values to rule out cached output, client evaluation, and string substitution. Treat sandbox escape as a separate edge supported by the exact engine version and exposed object graph.
