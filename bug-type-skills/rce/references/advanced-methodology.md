# RCE Methodology

Use this reference to test execution boundaries safely.

## Start here: how hunters found this in real reports

1. **Identify an interpreter, not just input reflection.** Candidate sinks include template engines, shell wrappers, deserializers, build hooks, converters, plugin systems, and job runners.
2. **Trace the full path.** Record validation, decoding, storage, serialization, queueing, worker execution, and the user or container identity of the final process.
3. **Fingerprint with harmless behavior.** Use syntax differences, arithmetic, a controlled error, or a benign file or callback marker that cannot damage the target.
4. **Separate preview from execution.** A value may be escaped in the UI but interpreted later by an email, export, build, or conversion worker.
5. **Confirm a controlled side effect.** Reflected text that resembles command output is not enough; use a unique, reversible marker and a negative control.
6. **Stop before destructive impact.** Do not read real secrets, establish persistence, or run broad commands. Report the demonstrated execution context and reachable boundary.

### Expand the pattern

Search sibling features that feed the same worker or library. The reusable root cause is unsafe interpretation at a named stage, not a copied payload string.

## 1. Sink inventory

List shell commands, renderers, template engines, package managers, CI jobs, imports, exports, plugins, uploads, deserializers, and appliance endpoints.

## 2. Context mapping

Record auth needed, user, container, filesystem, network, secrets, persistence, and outbound capability.

## 3. Payload discipline

Prefer benign timing, DNS/callback, marker, or harmless output. Avoid destructive commands.

## 4. Chain checks

Review upload-to-render, admin-to-plugin, SSRF-to-local API, dependency confusion, flag injection, and worker escape paths.

## 5. Remediation checklist

- Avoid shell execution with user input.
- Use allowlists and structured APIs.
- Sandbox renderers/workers.
- Disable dangerous plugins/deserialization.
- Isolate secrets from execution contexts.

## 6. What successful reports teach

- The public-registry/internal-package report shows that build and dependency resolution are execution boundaries; inventory package names, registries, scopes, lockfiles, CI credentials, and egress before assuming “dependency confusion.”
- Git flag injection demonstrates that structured process APIs can still interpret user-controlled values as options. Record argument boundaries, option terminators, working directory, and which executable receives the value.
- ExifTool metadata RCE and upload reports show that a safe web tier may hand content to a powerful, outdated converter in a worker.
- Markdown, template, report, wiki, and document renderers may expose engine options or plugin loading rather than direct shell metacharacters.
- Admin panels, appliances, CI/CD, import/export, and plugin ecosystems often turn a lower-severity authorization or upload primitive into execution.

## 7. Source-to-execution tracing

For each candidate record:

```text
input -> decode/parse -> validation -> argument/template/config construction
-> executable/interpreter/plugin -> OS identity/container -> filesystem/network/secrets
```

Distinguish these root causes:

- shell command construction;
- argument or option injection without a shell;
- unsafe deserialization or expression evaluation;
- user-controlled template or build configuration;
- malicious file interpreted by a processor;
- plugin/package/dependency resolution;
- exposed administrative execution feature;
- memory-safety defect requiring product-specific research.

Use the bug-type skill for the initial primitive—upload, SSTI, SQLi, SSRF, path traversal, or authorization—and use this methodology to establish whether the next edge reaches an execution context.

## 8. Proof ladder and controls

1. Prove the suspected interpreter or process receives a controlled value.
2. Use a harmless deterministic marker, bounded timing effect, or controlled callback allowed by policy.
3. Record execution identity and isolation from observable context; do not enumerate unrelated secrets.
4. Demonstrate only the minimum filesystem or network capability needed to explain impact.

Rule out application-generated callbacks, scanner traffic, templating in the browser, and mere reflection. Avoid persistent agents, reverse shells, destructive commands, privilege escalation, lateral movement, or changes to shared build/package infrastructure.
