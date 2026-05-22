# RCE Methodology

Use this reference to test execution boundaries safely.

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
