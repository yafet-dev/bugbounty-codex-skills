---
name: rce
description: Advanced remote code execution testing methodology for bug bounty and application security work. Use when testing or reviewing command execution, server-side code execution, upload-to-RCE, parser or renderer RCE, dependency confusion, package-install hooks, Git flag injection, VPN/appliance pre-auth RCE, desktop app RCE, admin-to-RCE, template or deserialization execution, CI/build worker execution, and workflows where attacker-controlled input reaches code, commands, interpreters, plugins, or privileged jobs.
---

# RCE Testing

## Core Posture

Treat RCE as attacker influence over code, command, interpreter, job, package, or plugin execution. Identify the execution context, privilege, trigger, and sandbox boundary before escalating.

## Priority Patterns

- Upload/render RCE: logo upload, image/PDF/SVG converters, file upload, archive processing, and media metadata.
- Command/flag injection: Git search flags, shell arguments, template build commands, and backend job parameters.
- Dependency and package chains: npm/internal package confusion, post-install hooks, build workers, CI, and container jobs.
- Admin-to-RCE: plugin upload, WordPress hardening bypass, admin panels, debug consoles, and file permission bypass.
- Appliance/desktop RCE: VPNs, desktop clients, protocol handlers, buffer overflows, and update mechanisms.
- Template/deserialization: SSTI, unsafe eval, serialized objects, YAML/XML parsers, and expression engines.

## Assessment Loop

1. Identify attacker-controlled input that reaches an interpreter, command, compiler, renderer, package manager, or job runner.
2. Map execution context: user, container, host, network access, filesystem, secrets, and persistence.
3. Start with harmless proof of execution, such as timing, controlled callback, marker file in safe location, or benign command output.
4. Test sandbox boundaries and privilege only enough to establish impact.
5. Confirm whether execution is pre-auth, low-role, admin-only, local, containerized, or remote.

## High-Value Cues

| Cue | Ask |
| --- | --- |
| Upload/render | Can file content become code or command input? |
| Shell/Git | Are arguments escaped or passed as flags? |
| Package build | Can install hooks or dependency names run code? |
| Admin feature | Does admin upload/config lead to code despite hardening? |
| Worker/container | Can code reach secrets, host files, or network? |

## Variant Playbook

- Test filename, metadata, content, archive entry, template, URL, search, report, and import fields.
- Compare sync response, async job, preview, export, admin view, and background worker behavior.
- Test shell metacharacters, flag injection, path injection, template expressions, package hooks, and renderer payloads safely.
- Look for local-only privileged APIs reachable through SSRF or internal routing.
- Confirm execution context and least destructive impact.

## Confirmation Discipline

Strong evidence shows controlled code or command execution in a meaningful context. Rule out client-side execution, harmless templating, upload-only storage, or admin-only behavior with no privilege increase unless admin-to-RCE itself is the bug class.

## References

Read `references/advanced-methodology.md` only when the task needs deeper execution-sink inventory, upload/render review, command injection review, worker/container review, confirmation, or remediation guidance.
